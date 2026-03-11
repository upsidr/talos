package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// IssuedCert holds the result of a certificate issuance.
type IssuedCert struct {
	Certificate    *x509.Certificate
	CertificatePEM []byte
	PrivateKey     *ecdsa.PrivateKey
	PrivateKeyPEM  []byte
	SerialNumber   string
	Fingerprint    string
	SubjectDN      string
}

// IssueOptions configures client certificate issuance.
type IssueOptions struct {
	Identity     string
	Organization string
	Validity     time.Duration
}

// IssueClientCert generates an ECDSA P-256 key pair and issues a client certificate
// signed by the given CA.
func IssueClientCert(caCert *x509.Certificate, signer Signer, opts IssueOptions) (*IssuedCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{
		CommonName:   opts.Identity,
		Organization: []string{opts.Organization},
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now,
		NotAfter:     now.Add(opts.Validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("create client certificate: %w", err)
	}

	clientCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal client key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &IssuedCert{
		Certificate:    clientCert,
		CertificatePEM: certPEM,
		PrivateKey:     key,
		PrivateKeyPEM:  keyPEM,
		SerialNumber:   serial.Text(16),
		Fingerprint:    Fingerprint(clientCert),
		SubjectDN:      clientCert.Subject.String(),
	}, nil
}

// GenerateServerCert creates a server certificate for the proxy itself (dev convenience).
// It writes server.crt and server.key to outDir.
func GenerateServerCert(caCert *x509.Certificate, signer Signer, hosts []string, outDir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		DNSNames:  hosts,
		NotBefore: now,
		NotAfter:  now.Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, signer)
	if err != nil {
		return fmt.Errorf("create server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(outDir, "server.crt"), certPEM, 0644); err != nil {
		return fmt.Errorf("write server certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(outDir, "server.key"), keyPEM, 0600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}

	return nil
}

// ParseCertificatePEM parses a PEM-encoded certificate.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseDuration parses duration strings like "90d", "365d", "10y" in addition to Go durations.
func ParseDuration(s string) (time.Duration, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty duration string")
	}

	last := s[len(s)-1]
	switch last {
	case 'd':
		return parseDurationMultiple(s[:len(s)-1], 24*time.Hour)
	case 'y':
		return parseDurationMultiple(s[:len(s)-1], 365*24*time.Hour)
	default:
		return time.ParseDuration(s)
	}
}

func parseDurationMultiple(numStr string, unit time.Duration) (time.Duration, error) {
	var n int
	for _, c := range numStr {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid duration: %s", numStr)
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return time.Duration(n) * unit, nil
}

