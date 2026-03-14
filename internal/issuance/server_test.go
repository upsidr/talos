package issuance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/cert"
	"github.com/upsidr/talos/internal/config"
	"github.com/upsidr/talos/internal/store"
)

func testServer(t *testing.T) (*Server, *store.MockStore) {
	t.Helper()
	tmpDir := t.TempDir()
	caCert, signer, err := cert.GenerateLocalCA(tmpDir, pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
	}, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateLocalCA: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	ms := store.NewMockStore()

	issCfg := &config.IssuanceConfig{
		ListenAddress: ":0",
		Kerberos: config.KerberosConfig{
			AllowedRealms:     []string{"DIRECTORY.UPSIDR.LOCAL"},
			AllowedPrincipals: []string{},
		},
		IdentityMapping: config.IdentityMappingConfig{
			Strategy: "principal",
		},
		Certificate: config.IssuanceCertificateConfig{
			ExpiresIn: "90d",
		},
	}

	globalCfg := config.DefaultConfig()
	globalCfg.Certificate.Organization = "Test Org"

	srv := NewServer(issCfg, globalCfg, ms, signer, caCertPEM, caCert, "test-ca-id", zap.NewNop())
	return srv, ms
}

func requestWithPrincipal(method, target string, principal, realm string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(r.Context(), contextKeyPrincipal, principal)
	ctx = context.WithValue(ctx, contextKeyRealm, realm)
	return r.WithContext(ctx)
}

func TestHandleIssue_Success(t *testing.T) {
	srv, ms := testServer(t)

	req := requestWithPrincipal("POST", "/v1/issue",
		"johndoe@DIRECTORY.UPSIDR.LOCAL", "DIRECTORY.UPSIDR.LOCAL")
	w := httptest.NewRecorder()

	srv.handleIssue(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/gzip")
	}

	// Verify the bundle can be decompressed
	gr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	fileNames := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		fileNames[hdr.Name] = true
	}

	expectedFiles := []string{
		"johndoe@directory.upsidr.local--v1.crt",
		"johndoe@directory.upsidr.local--v1.key",
		"ca.crt",
	}
	for _, f := range expectedFiles {
		if !fileNames[f] {
			t.Errorf("missing file %q in bundle", f)
		}
	}

	// Verify cert was stored
	certs, err := ms.ListCerts(context.Background(), store.ListCertsOptions{})
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert in store, got %d", len(certs))
	}
	if certs[0].Identity != "johndoe@directory.upsidr.local" {
		t.Errorf("identity = %q, want %q", certs[0].Identity, "johndoe@directory.upsidr.local")
	}
	if certs[0].IssuedBy != "kerberos:johndoe@DIRECTORY.UPSIDR.LOCAL" {
		t.Errorf("IssuedBy = %q, want %q", certs[0].IssuedBy, "kerberos:johndoe@DIRECTORY.UPSIDR.LOCAL")
	}
	if certs[0].Version != 1 {
		t.Errorf("version = %d, want 1", certs[0].Version)
	}
}

func TestHandleIssue_UnauthorizedRealm(t *testing.T) {
	srv, _ := testServer(t)

	req := requestWithPrincipal("POST", "/v1/issue",
		"evil@EVIL.REALM", "EVIL.REALM")
	w := httptest.NewRecorder()

	srv.handleIssue(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandleIssue_UnauthorizedPrincipal(t *testing.T) {
	srv, _ := testServer(t)
	// Set specific allowed principals
	srv.cfg.Kerberos.AllowedPrincipals = []string{"admin@DIRECTORY.UPSIDR.LOCAL"}

	req := requestWithPrincipal("POST", "/v1/issue",
		"johndoe@DIRECTORY.UPSIDR.LOCAL", "DIRECTORY.UPSIDR.LOCAL")
	w := httptest.NewRecorder()

	srv.handleIssue(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandleIssue_ReissueRevokesPrevious(t *testing.T) {
	srv, ms := testServer(t)

	// First issuance
	req1 := requestWithPrincipal("POST", "/v1/issue",
		"johndoe@DIRECTORY.UPSIDR.LOCAL", "DIRECTORY.UPSIDR.LOCAL")
	w1 := httptest.NewRecorder()
	srv.handleIssue(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first issuance: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// Second issuance (should revoke first)
	req2 := requestWithPrincipal("POST", "/v1/issue",
		"johndoe@DIRECTORY.UPSIDR.LOCAL", "DIRECTORY.UPSIDR.LOCAL")
	w2 := httptest.NewRecorder()
	srv.handleIssue(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second issuance: status = %d, want %d", w2.Code, http.StatusOK)
	}

	// Check store state
	identity := "johndoe@directory.upsidr.local"
	certs, err := ms.ListCerts(context.Background(), store.ListCertsOptions{
		Identity: &identity,
	})
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}

	var activeCount, revokedCount int
	for _, c := range certs {
		switch c.Status {
		case store.StatusActive:
			activeCount++
			if c.Version != 2 {
				t.Errorf("active cert version = %d, want 2", c.Version)
			}
		case store.StatusRevoked:
			revokedCount++
			if c.Version != 1 {
				t.Errorf("revoked cert version = %d, want 1", c.Version)
			}
		}
	}
	if activeCount != 1 {
		t.Errorf("active certs = %d, want 1", activeCount)
	}
	if revokedCount != 1 {
		t.Errorf("revoked certs = %d, want 1", revokedCount)
	}
}

func TestHandleIssue_UsernameStrategy(t *testing.T) {
	srv, ms := testServer(t)
	srv.cfg.IdentityMapping.Strategy = "username"

	req := requestWithPrincipal("POST", "/v1/issue",
		"johndoe@DIRECTORY.UPSIDR.LOCAL", "DIRECTORY.UPSIDR.LOCAL")
	w := httptest.NewRecorder()

	srv.handleIssue(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	certs, err := ms.ListCerts(context.Background(), store.ListCertsOptions{})
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Identity != "johndoe" {
		t.Errorf("identity = %q, want %q", certs[0].Identity, "johndoe")
	}
}

func TestMapIdentity(t *testing.T) {
	tests := []struct {
		strategy  string
		principal string
		want      string
	}{
		{"principal", "johndoe@DIRECTORY.UPSIDR.LOCAL", "johndoe@directory.upsidr.local"},
		{"username", "johndoe@DIRECTORY.UPSIDR.LOCAL", "johndoe"},
		{"", "johndoe@DIRECTORY.UPSIDR.LOCAL", "johndoe@directory.upsidr.local"},
		{"username", "johndoe", "johndoe"},
	}

	for _, tt := range tests {
		srv := &Server{cfg: &config.IssuanceConfig{
			IdentityMapping: config.IdentityMappingConfig{Strategy: tt.strategy},
		}}
		got := srv.mapIdentity(tt.principal)
		if got != tt.want {
			t.Errorf("mapIdentity(%q, strategy=%q) = %q, want %q", tt.principal, tt.strategy, got, tt.want)
		}
	}
}
