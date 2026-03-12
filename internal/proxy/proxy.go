package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/cert"
	"github.com/upsidr/talos/internal/config"
	"github.com/upsidr/talos/internal/store"
)

// Server is the mTLS-terminating TCP proxy server.
type Server struct {
	cfg      config.Config
	store    store.CertificateStore
	cache    *Cache
	logger   *zap.Logger
	listener net.Listener

	mu       sync.Mutex
	connCount int
}

// NewServer creates a new proxy server.
func NewServer(cfg config.Config, s store.CertificateStore, logger *zap.Logger) *Server {
	return &Server{
		cfg:   cfg,
		store: s,
		cache: NewCache(cfg.Cache.TTL, cfg.Cache.MaxEntries),
		logger: logger,
	}
}

// Run starts the proxy server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	caCert, err := os.ReadFile(s.cfg.TLS.CACertificatePath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	serverCert, err := tls.LoadX509KeyPair(
		s.cfg.TLS.ServerCertificatePath,
		s.cfg.TLS.ServerKeyPath,
	)
	if err != nil {
		return fmt.Errorf("load server certificate: %w", err)
	}

	minVersion, err := parseTLSVersion(s.cfg.TLS.MinVersion)
	if err != nil {
		return fmt.Errorf("parse TLS min version: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates:             []tls.Certificate{serverCert},
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                caPool,
		MinVersion:               minVersion,
		SessionTicketsDisabled:   true, // Force full handshake on every connection for revocation checks
		VerifyPeerCertificate:    nil,  // Set below after server is ready
	}

	s.listener, err = tls.Listen("tcp", s.cfg.Proxy.ListenAddress, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Proxy.ListenAddress, err)
	}
	defer func() { _ = s.listener.Close() }()

	s.logger.Info("proxy started",
		zap.String("listen", s.cfg.Proxy.ListenAddress),
		zap.String("backend", s.cfg.Proxy.BackendAddress),
		zap.Duration("cache_ttl", s.cfg.Cache.TTL),
		zap.String("tls_min_version", s.cfg.TLS.MinVersion),
		zap.Duration("revocation_check_interval", s.cfg.Proxy.RevocationCheckInterval),
	)

	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Error("accept connection", zap.Error(err))
				continue
			}
		}

		if s.cfg.Proxy.MaxConnections > 0 {
			s.mu.Lock()
			if s.connCount >= s.cfg.Proxy.MaxConnections {
				s.mu.Unlock()
				s.logger.Warn("max connections reached, rejecting",
					zap.String("client", conn.RemoteAddr().String()))
				_ = conn.Close()
				continue
			}
			s.connCount++
			s.mu.Unlock()
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	startTime := time.Now()
	clientAddr := conn.RemoteAddr().String()

	defer func() {
		_ = conn.Close()
		if s.cfg.Proxy.MaxConnections > 0 {
			s.mu.Lock()
			s.connCount--
			s.mu.Unlock()
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		s.logger.Error("connection is not TLS", zap.String("client", clientAddr))
		return
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.logger.Warn("TLS handshake failed",
			zap.String("client", clientAddr),
			zap.Error(err))
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		s.logger.Warn("no client certificate presented",
			zap.String("client", clientAddr))
		return
	}

	leaf := state.PeerCertificates[0]
	fingerprint := cert.Fingerprint(leaf)

	// Check certificate status (cache → DB)
	status, identity, version, cacheHit := s.cache.Get(fingerprint)
	if !cacheHit {
		cert, err := s.store.GetCertByFingerprint(ctx, fingerprint)
		if err != nil {
			s.logger.Error("database lookup failed (fail-closed)",
				zap.String("client", clientAddr),
				zap.String("fingerprint", fingerprint),
				zap.Error(err))
			s.logEvent("conn_rejected", clientAddr, fingerprint, "", 0, false, "database_error", startTime)
			return
		}
		if cert == nil {
			s.logger.Warn("unknown certificate (not in catalog)",
				zap.String("client", clientAddr),
				zap.String("fingerprint", fingerprint))
			s.logEvent("conn_rejected", clientAddr, fingerprint, "", 0, false, "unknown_certificate", startTime)
			return
		}
		status = cert.Status
		identity = cert.Identity
		version = cert.Version
		s.cache.Put(fingerprint, status, identity, version)
	}

	if status != store.StatusActive {
		s.logger.Warn("certificate revoked",
			zap.String("client", clientAddr),
			zap.String("identity", identity),
			zap.Int("version", version),
			zap.String("fingerprint", fingerprint),
			zap.Bool("cache_hit", cacheHit))
		s.logEvent("conn_rejected", clientAddr, fingerprint, identity, version, cacheHit, "certificate_revoked", startTime)
		return
	}

	// Connect to backend
	backend, err := net.DialTimeout("tcp", s.cfg.Proxy.BackendAddress, 5*time.Second)
	if err != nil {
		s.logger.Error("backend connection failed",
			zap.String("backend", s.cfg.Proxy.BackendAddress),
			zap.Error(err))
		s.logEvent("conn_rejected", clientAddr, fingerprint, identity, version, cacheHit, "backend_unreachable", startTime)
		return
	}
	defer func() { _ = backend.Close() }()

	s.logger.Info("connection accepted",
		zap.String("client", clientAddr),
		zap.String("identity", identity),
		zap.Int("version", version),
		zap.Bool("cache_hit", cacheHit),
		zap.String("backend", s.cfg.Proxy.BackendAddress))

	// Bidirectional relay with optional periodic revocation checks
	var bytesTx, bytesRx int64
	var revoked bool

	interval := s.cfg.Proxy.RevocationCheckInterval
	if interval > 0 {
		bytesTx, bytesRx, revoked = s.relayWithRevocationCheck(ctx, tlsConn, backend, fingerprint, interval)
	} else {
		bytesTx, bytesRx = s.relaySimple(tlsConn, backend)
	}

	duration := time.Since(startTime)

	if revoked {
		s.logger.Warn("connection terminated: certificate revoked during session",
			zap.String("client", clientAddr),
			zap.String("identity", identity),
			zap.Int("version", version),
			zap.Duration("duration", duration),
			zap.Int64("bytes_tx", bytesTx),
			zap.Int64("bytes_rx", bytesRx),
			zap.String("fingerprint", fingerprint))
		s.logEvent("conn_revoked", clientAddr, fingerprint, identity, version, false, "certificate_revoked_during_session", startTime)
		return
	}

	s.logger.Info("connection closed",
		zap.String("client", clientAddr),
		zap.String("identity", identity),
		zap.Int("version", version),
		zap.Duration("duration", duration),
		zap.Int64("bytes_tx", bytesTx),
		zap.Int64("bytes_rx", bytesRx))
}

// relaySimple performs a simple bidirectional relay without revocation checks.
func (s *Server) relaySimple(client, backend net.Conn) (bytesTx, bytesRx int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bytesTx, _ = io.Copy(backend, client)
	}()
	go func() {
		defer wg.Done()
		bytesRx, _ = io.Copy(client, backend)
	}()

	wg.Wait()
	return
}

// checkRevocation checks whether a certificate is still active.
// Returns true if the certificate is active, false if revoked or on error (fail-closed).
func (s *Server) checkRevocation(ctx context.Context, fingerprint string) bool {
	// Try cache first
	if status, ok := s.cache.GetStatus(fingerprint); ok {
		return status == store.StatusActive
	}

	// Cache miss — query DB
	cert, err := s.store.GetCertByFingerprint(ctx, fingerprint)
	if err != nil {
		s.logger.Error("revocation re-check: database error (fail-closed)",
			zap.String("fingerprint", fingerprint),
			zap.Error(err))
		return false
	}
	if cert == nil {
		return false
	}

	// Update cache with fresh data
	s.cache.Put(fingerprint, cert.Status, cert.Identity, cert.Version)
	return cert.Status == store.StatusActive
}

// relayWithRevocationCheck performs a bidirectional relay that periodically
// checks whether the client certificate has been revoked. If revoked, both
// connections are closed immediately.
func (s *Server) relayWithRevocationCheck(ctx context.Context, client, backend net.Conn, fingerprint string, interval time.Duration) (bytesTx, bytesRx int64, revoked bool) {
	done := make(chan struct{})
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			close(done)
			_ = client.Close()
			_ = backend.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// client → backend
	go func() {
		defer wg.Done()
		bytesTx = s.copyWithDeadline(client, backend, interval, done)
	}()

	// backend → client
	go func() {
		defer wg.Done()
		bytesRx = s.copyWithDeadline(backend, client, interval, done)
	}()

	// Revocation check ticker
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			wg.Wait()
			return bytesTx, bytesRx, false
		case <-ctx.Done():
			closeAll()
			wg.Wait()
			return bytesTx, bytesRx, false
		case <-ticker.C:
			if !s.checkRevocation(ctx, fingerprint) {
				revoked = true
				closeAll()
				wg.Wait()
				return bytesTx, bytesRx, true
			}
		}
	}
}

// copyWithDeadline copies data from src to dst using deadline-driven reads.
// On each read deadline timeout, it checks whether done has been signalled.
// Returns total bytes copied.
func (s *Server) copyWithDeadline(src, dst net.Conn, deadline time.Duration, done chan struct{}) int64 {
	buf := make([]byte, 32*1024)
	var total int64

	for {
		_ = src.SetReadDeadline(time.Now().Add(deadline))
		n, readErr := src.Read(buf)
		if n > 0 {
			nw, writeErr := dst.Write(buf[:n])
			total += int64(nw)
			if writeErr != nil {
				s.signalDone(done)
				return total
			}
		}

		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				// Read deadline hit — check if we should stop
				select {
				case <-done:
					return total
				default:
					continue
				}
			}
			// Real error or EOF
			s.signalDone(done)
			return total
		}
	}
}

// signalDone non-blocking close of done channel.
func (s *Server) signalDone(done chan struct{}) {
	select {
	case <-done:
	default:
		close(done)
	}
}

func (s *Server) logEvent(event, clientAddr, fingerprint, identity string, version int, cacheHit bool, reason string, startTime time.Time) {
	s.logger.Info("audit",
		zap.String("event", event),
		zap.String("client_ip", clientAddr),
		zap.String("cert_fingerprint", fingerprint),
		zap.String("identity", identity),
		zap.Int("cert_version", version),
		zap.Bool("cache_hit", cacheHit),
		zap.String("reason", reason),
		zap.String("backend", s.cfg.Proxy.BackendAddress),
	)
}

func parseTLSVersion(v string) (uint16, error) {
	switch v {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s (use 1.2 or 1.3)", v)
	}
}
