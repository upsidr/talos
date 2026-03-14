package issuance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/cert"
	"github.com/upsidr/talos/internal/config"
	"github.com/upsidr/talos/internal/store"
)

// Server is the Kerberos-authenticated certificate issuance HTTP server.
type Server struct {
	cfg       *config.IssuanceConfig
	globalCfg config.Config
	store     store.CertificateStore
	signer    cert.Signer
	caCertPEM []byte
	caParsed  *x509.Certificate
	caID      string
	logger    *zap.Logger
	auth      Authenticator
}

// NewServer creates a new issuance server.
func NewServer(cfg *config.IssuanceConfig, globalCfg config.Config, s store.CertificateStore, signer cert.Signer, caCertPEM []byte, caParsed *x509.Certificate, caID string, logger *zap.Logger) *Server {
	return &Server{
		cfg:       cfg,
		globalCfg: globalCfg,
		store:     s,
		signer:    signer,
		caCertPEM: caCertPEM,
		caParsed:  caParsed,
		caID:      caID,
		logger:    logger,
	}
}

// SetAuthenticator overrides the authenticator (for testing).
func (s *Server) SetAuthenticator(auth Authenticator) {
	s.auth = auth
}

// Run starts the HTTPS issuance server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	var middleware func(http.Handler) http.Handler
	if s.auth != nil {
		// Test mode: use the mock authenticator
		middleware = SPNEGOMiddleware(s.auth, s.logger)
	} else {
		// Production mode: use gokrb5's SPNEGO handler with keytab
		kt, err := LoadKeytab(s.cfg.Kerberos.KeytabPath)
		if err != nil {
			return fmt.Errorf("load keytab: %w", err)
		}
		middleware = NewKeytabMiddleware(kt, s.logger)
	}
	mux.Handle("POST /v1/issue", middleware(http.HandlerFunc(s.handleIssue)))

	tlsCert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertificatePath, s.cfg.TLS.KeyPath)
	if err != nil {
		return fmt.Errorf("load issuance TLS certificate: %w", err)
	}

	srv := &http.Server{
		Addr:    s.cfg.ListenAddress,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("issuance server starting",
			zap.String("address", s.cfg.ListenAddress),
			zap.String("service_principal", s.cfg.Kerberos.ServicePrincipal),
			zap.Strings("allowed_realms", s.cfg.Kerberos.AllowedRealms),
		)
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("issuance server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	principal := PrincipalFromContext(r.Context())
	realm := RealmFromContext(r.Context())
	if principal == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check realm
	if !s.isRealmAllowed(realm) {
		s.logger.Warn("unauthorized realm",
			zap.String("principal", principal),
			zap.String("realm", realm),
			zap.String("remote_addr", r.RemoteAddr),
		)
		http.Error(w, "Forbidden: realm not allowed", http.StatusForbidden)
		return
	}

	// Check principal allowlist
	if !s.isPrincipalAllowed(principal) {
		s.logger.Warn("unauthorized principal",
			zap.String("principal", principal),
			zap.String("remote_addr", r.RemoteAddr),
		)
		http.Error(w, "Forbidden: principal not authorized", http.StatusForbidden)
		return
	}

	// Map principal to identity
	identity := s.mapIdentity(principal)

	ctx := r.Context()

	// Revoke all active certs for this identity
	revokedCount, err := s.revokeActiveCerts(ctx, identity)
	if err != nil {
		s.logger.Error("revoke active certs failed",
			zap.String("identity", identity),
			zap.Error(err),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get next version
	version, err := s.store.GetNextVersion(ctx, identity)
	if err != nil {
		s.logger.Error("get next version failed",
			zap.String("identity", identity),
			zap.Error(err),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Determine validity
	validity := s.globalCfg.Certificate.DefaultValidity
	if s.cfg.Certificate.ExpiresIn != "" {
		v, err := cert.ParseDuration(s.cfg.Certificate.ExpiresIn)
		if err != nil {
			s.logger.Error("parse issuance validity failed", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		validity = v
	}

	// Issue certificate
	issued, err := cert.IssueClientCert(s.caParsed, s.signer, cert.IssueOptions{
		Identity:     identity,
		Organization: s.globalCfg.Certificate.Organization,
		Validity:     validity,
	})
	if err != nil {
		s.logger.Error("issue certificate failed",
			zap.String("identity", identity),
			zap.Error(err),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Zero the private key bytes after we're done
	defer func() {
		for i := range issued.PrivateKeyPEM {
			issued.PrivateKeyPEM[i] = 0
		}
	}()

	// Store in database
	certRecord := &store.Certificate{
		ID:                uuid.New().String(),
		SerialNumber:      issued.SerialNumber,
		Identity:          identity,
		Version:           version,
		CAID:              s.caID,
		FingerprintSHA256: issued.Fingerprint,
		SubjectDN:         issued.SubjectDN,
		Status:            store.StatusActive,
		IssuedAt:          time.Now(),
		ExpiresAt:         issued.Certificate.NotAfter,
		IssuedBy:          "kerberos:" + principal,
	}
	if err := s.store.InsertCert(ctx, certRecord); err != nil {
		s.logger.Error("store certificate failed",
			zap.String("identity", identity),
			zap.Error(err),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build bundle
	bundle, err := BuildBundle(BundleContents{
		Identity:       identity,
		Version:        version,
		CertificatePEM: issued.CertificatePEM,
		PrivateKeyPEM:  issued.PrivateKeyPEM,
		CACertPEM:      s.caCertPEM,
	})
	if err != nil {
		s.logger.Error("build bundle failed",
			zap.String("identity", identity),
			zap.Error(err),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Audit log
	s.logger.Info("certificate issued via kerberos",
		zap.String("identity", identity),
		zap.Int("version", version),
		zap.String("fingerprint", issued.Fingerprint),
		zap.String("kerberos_principal", principal),
		zap.String("kerberos_realm", realm),
		zap.String("remote_addr", r.RemoteAddr),
		zap.Int("previous_versions_revoked", revokedCount),
	)

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s--v%d.tar.gz", identity, version))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

func (s *Server) isRealmAllowed(realm string) bool {
	for _, r := range s.cfg.Kerberos.AllowedRealms {
		if r == realm {
			return true
		}
	}
	return false
}

func (s *Server) isPrincipalAllowed(principal string) bool {
	if len(s.cfg.Kerberos.AllowedPrincipals) == 0 {
		return true
	}
	for _, p := range s.cfg.Kerberos.AllowedPrincipals {
		if p == principal {
			return true
		}
	}
	return false
}

func (s *Server) mapIdentity(principal string) string {
	switch s.cfg.IdentityMapping.Strategy {
	case "username":
		if idx := strings.Index(principal, "@"); idx > 0 {
			return strings.ToLower(principal[:idx])
		}
		return strings.ToLower(principal)
	default: // "principal" or empty
		return strings.ToLower(principal)
	}
}

func (s *Server) revokeActiveCerts(ctx context.Context, identity string) (int, error) {
	activeStatus := store.StatusActive
	certs, err := s.store.ListCerts(ctx, store.ListCertsOptions{
		Identity: &identity,
		Status:   &activeStatus,
	})
	if err != nil {
		return 0, fmt.Errorf("list active certificates: %w", err)
	}

	reason := "reissued via kerberos"
	for _, c := range certs {
		if err := s.store.UpdateCertStatus(ctx, c.ID, store.StatusRevoked, &reason); err != nil {
			return 0, fmt.Errorf("revoke certificate %s v%d: %w", c.Identity, c.Version, err)
		}
		s.logger.Info("revoked for kerberos reissue",
			zap.String("identity", c.Identity),
			zap.Int("version", c.Version),
			zap.String("fingerprint", c.FingerprintSHA256),
		)
	}

	return len(certs), nil
}
