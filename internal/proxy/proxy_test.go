package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/config"
	"github.com/upsidr/talos/internal/store"
)

func TestProxy_AcceptActiveCert(t *testing.T) {
	pki := testPKI(t)
	mockStore := store.NewMockStore()

	mockStore.InsertCert(context.Background(), &store.Certificate{
		ID:                "cert-1",
		Identity:          "test@example.com",
		Version:           1,
		FingerprintSHA256: pki.ClientFingerprint,
		Status:            store.StatusActive,
	})

	proxyAddr, cleanup := setupProxyDirect(t, pki, mockStore)
	defer cleanup()

	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		Certificates:       []tls.Certificate{pki.ClientTLSCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello talos")
	conn.Write(msg)

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "hello talos" {
		t.Errorf("got %q, want %q", buf[:n], "hello talos")
	}
}

func TestProxy_RejectRevokedCert(t *testing.T) {
	pki := testPKI(t)
	mockStore := store.NewMockStore()

	mockStore.InsertCert(context.Background(), &store.Certificate{
		ID:                "cert-1",
		Identity:          "test@example.com",
		Version:           1,
		FingerprintSHA256: pki.ClientFingerprint,
		Status:            store.StatusRevoked,
	})

	proxyAddr, cleanup := setupProxyDirect(t, pki, mockStore)
	defer cleanup()

	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		Certificates:       []tls.Certificate{pki.ClientTLSCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return // Acceptable — rejected at connection level
	}
	defer conn.Close()

	conn.Write([]byte("hello"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1024))
	if err == nil {
		t.Error("expected read to fail for revoked cert, but succeeded")
	}
}

func TestProxy_FailClosedOnDBError(t *testing.T) {
	pki := testPKI(t)
	mockStore := store.NewMockStore()
	mockStore.ErrOnGet = fmt.Errorf("database connection lost")

	proxyAddr, cleanup := setupProxyDirect(t, pki, mockStore)
	defer cleanup()

	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		Certificates:       []tls.Certificate{pki.ClientTLSCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return // Acceptable
	}
	defer conn.Close()

	conn.Write([]byte("hello"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1024))
	if err == nil {
		t.Error("expected read to fail on DB error (fail-closed), but succeeded")
	}
}

func TestProxy_MaxConnections(t *testing.T) {
	pki := testPKI(t)
	mockStore := store.NewMockStore()

	mockStore.InsertCert(context.Background(), &store.Certificate{
		ID:                "cert-1",
		Identity:          "test@example.com",
		Version:           1,
		FingerprintSHA256: pki.ClientFingerprint,
		Status:            store.StatusActive,
	})

	proxyAddr, cleanup := setupProxyDirectWithMaxConns(t, pki, mockStore, 2)
	defer cleanup()

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{pki.ClientTLSCert},
		InsecureSkipVerify: true,
	}

	// Open 2 connections (at the limit)
	conns := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		conn, err := tls.Dial("tcp", proxyAddr, tlsCfg)
		if err != nil {
			t.Fatalf("connection %d failed: %v", i, err)
		}
		conn.Write([]byte("ping"))
		buf := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf)
		conns = append(conns, conn)
	}

	// 3rd connection should be rejected
	conn3, err := tls.Dial("tcp", proxyAddr, tlsCfg)
	if err == nil {
		conn3.Write([]byte("ping"))
		conn3.SetReadDeadline(time.Now().Add(time.Second))
		_, err := conn3.Read(make([]byte, 1024))
		conn3.Close()
		if err == nil {
			t.Error("expected 3rd connection to be rejected at max connections, but it succeeded")
		}
	}

	for _, c := range conns {
		c.Close()
	}
}

// setupProxyDirect creates a test proxy with pre-configured TLS listener.
func setupProxyDirect(t *testing.T, pki *testPKIResult, mockStore *store.MockStore) (string, context.CancelFunc) {
	return setupProxyDirectWithMaxConns(t, pki, mockStore, 10)
}

func setupProxyDirectWithMaxConns(t *testing.T, pki *testPKIResult, mockStore *store.MockStore, maxConns int) (string, context.CancelFunc) {
	t.Helper()

	// Start fake backend (echo server)
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	tlsCfg := &tls.Config{
		Certificates:           []tls.Certificate{pki.ServerTLSCert},
		ClientAuth:             tls.RequireAnyClientCert,
		ClientCAs:              pki.CAPool,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		Proxy: config.ProxyConfig{
			ListenAddress:  listener.Addr().String(),
			BackendAddress: backendListener.Addr().String(),
			MaxConnections: maxConns,
		},
		Cache: config.CacheConfig{
			TTL:        60 * time.Second,
			MaxEntries: 100,
		},
	}

	logger, _ := zap.NewDevelopment()
	srv := &Server{
		cfg:      cfg,
		store:    mockStore,
		cache:    NewCache(cfg.Cache.TTL, cfg.Cache.MaxEntries),
		logger:   logger,
		listener: listener,
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			if cfg.Proxy.MaxConnections > 0 {
				srv.mu.Lock()
				if srv.connCount >= cfg.Proxy.MaxConnections {
					srv.mu.Unlock()
					conn.Close()
					continue
				}
				srv.connCount++
				srv.mu.Unlock()
			}

			go srv.handleConnection(ctx, conn)
		}
	}()

	cleanup := func() {
		cancel()
		backendListener.Close()
	}

	return listener.Addr().String(), cleanup
}
