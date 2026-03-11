package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T) (*x509.Certificate, *LocalSigner, string) {
	t.Helper()
	dir := t.TempDir()
	subject := pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
	}
	caCert, signer, err := GenerateLocalCA(dir, subject, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateLocalCA() error = %v", err)
	}
	return caCert, signer, dir
}

func TestGenerateLocalCA(t *testing.T) {
	caCert, _, dir := testCA(t)

	if !caCert.IsCA {
		t.Error("CA cert IsCA = false, want true")
	}
	if caCert.Subject.CommonName != "Test CA" {
		t.Errorf("CA CN = %q, want %q", caCert.Subject.CommonName, "Test CA")
	}

	// Verify files exist
	for _, name := range []string{"ca.crt", "ca.key"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %s to exist: %v", name, err)
		}
	}
}

func TestLocalSigner_LoadFromFile(t *testing.T) {
	_, _, dir := testCA(t)

	signer, err := NewLocalSigner(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewLocalSigner() error = %v", err)
	}
	defer signer.Close()

	if signer.Public() == nil {
		t.Error("Public() returned nil")
	}
}

func TestIssueClientCert(t *testing.T) {
	caCert, signer, _ := testCA(t)

	issued, err := IssueClientCert(caCert, signer, IssueOptions{
		Identity:     "test@example.com",
		Organization: "Test Org",
		Validity:     90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueClientCert() error = %v", err)
	}

	if issued.Certificate.Subject.CommonName != "test@example.com" {
		t.Errorf("CN = %q, want %q", issued.Certificate.Subject.CommonName, "test@example.com")
	}
	if !strings.HasPrefix(issued.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint = %q, want SHA256: prefix", issued.Fingerprint)
	}
	if issued.SerialNumber == "" {
		t.Error("SerialNumber is empty")
	}
	if len(issued.CertificatePEM) == 0 {
		t.Error("CertificatePEM is empty")
	}
	if len(issued.PrivateKeyPEM) == 0 {
		t.Error("PrivateKeyPEM is empty")
	}

	// Verify the cert is valid for client auth
	found := false
	for _, usage := range issued.Certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Error("client cert missing ExtKeyUsageClientAuth")
	}

	// Verify signature chain
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = issued.Certificate.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Errorf("certificate verification failed: %v", err)
	}
}

func TestFingerprintConsistency(t *testing.T) {
	caCert, signer, _ := testCA(t)

	issued, err := IssueClientCert(caCert, signer, IssueOptions{
		Identity:     "test@example.com",
		Organization: "Test Org",
		Validity:     90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueClientCert() error = %v", err)
	}

	// Fingerprint computed during issuance should match recomputing it
	recomputed := Fingerprint(issued.Certificate)
	if issued.Fingerprint != recomputed {
		t.Errorf("fingerprint mismatch: issued=%q, recomputed=%q", issued.Fingerprint, recomputed)
	}

	// Parse from PEM and verify fingerprint matches
	parsed, err := ParseCertificatePEM(issued.CertificatePEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM() error = %v", err)
	}
	fromPEM := Fingerprint(parsed)
	if issued.Fingerprint != fromPEM {
		t.Errorf("fingerprint from PEM mismatch: issued=%q, fromPEM=%q", issued.Fingerprint, fromPEM)
	}
}

func TestGenerateServerCert(t *testing.T) {
	caCert, signer, dir := testCA(t)

	err := GenerateServerCert(caCert, signer, []string{"localhost", "talos.local"}, dir)
	if err != nil {
		t.Fatalf("GenerateServerCert() error = %v", err)
	}

	for _, name := range []string{"server.crt", "server.key"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %s to exist: %v", name, err)
		}
	}

	// Parse and verify server cert
	data, _ := os.ReadFile(filepath.Join(dir, "server.crt"))
	serverCert, err := ParseCertificatePEM(data)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = serverCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("server cert verification failed: %v", err)
	}
}

func TestWriteOutputFiles(t *testing.T) {
	caCert, signer, _ := testCA(t)

	issued, err := IssueClientCert(caCert, signer, IssueOptions{
		Identity:     "test@example.com",
		Organization: "Test Org",
		Validity:     90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueClientCert() error = %v", err)
	}

	outDir := t.TempDir()

	t.Run("without passphrase", func(t *testing.T) {
		files, err := WriteOutputFiles(issued, outDir, "", "test@example.com", 1)
		if err != nil {
			t.Fatalf("WriteOutputFiles() error = %v", err)
		}
		if files.CertPath == "" {
			t.Error("CertPath is empty")
		}
		if files.KeyPath == "" {
			t.Error("KeyPath is empty")
		}
		if files.P12Path != "" {
			t.Errorf("P12Path = %q, want empty", files.P12Path)
		}
	})

	t.Run("with passphrase", func(t *testing.T) {
		outDir2 := t.TempDir()
		files, err := WriteOutputFiles(issued, outDir2, "test-passphrase", "test@example.com", 1)
		if err != nil {
			t.Fatalf("WriteOutputFiles() error = %v", err)
		}
		if files.P12Path == "" {
			t.Error("P12Path is empty when passphrase was provided")
		}
		if _, err := os.Stat(files.P12Path); err != nil {
			t.Errorf("P12 file does not exist: %v", err)
		}
	})
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"90d", 90 * 24 * time.Hour},
		{"365d", 365 * 24 * time.Hour},
		{"10y", 10 * 365 * 24 * time.Hour},
		{"1y", 365 * 24 * time.Hour},
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if err != nil {
				t.Fatalf("ParseDuration(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
