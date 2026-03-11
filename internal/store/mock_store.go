package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockStore is an in-memory CertificateStore implementation for testing.
type MockStore struct {
	mu    sync.RWMutex
	certs map[string]*Certificate // keyed by ID
	cas   map[string]*CertificateAuthority

	// ErrOnGet causes GetCertByFingerprint to return this error (simulates DB failure).
	ErrOnGet error
}

// NewMockStore creates a new in-memory store.
func NewMockStore() *MockStore {
	return &MockStore{
		certs: make(map[string]*Certificate),
		cas:   make(map[string]*CertificateAuthority),
	}
}

func (m *MockStore) GetCertByFingerprint(_ context.Context, fingerprint string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ErrOnGet != nil {
		return nil, m.ErrOnGet
	}

	for _, c := range m.certs {
		if c.FingerprintSHA256 == fingerprint {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *MockStore) InsertCert(_ context.Context, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *cert
	m.certs[cert.ID] = &cp
	return nil
}

func (m *MockStore) UpdateCertStatus(_ context.Context, id string, status CertificateStatus, reason *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, ok := m.certs[id]
	if !ok {
		return fmt.Errorf("certificate %s not found", id)
	}
	cert.Status = status
	if status == StatusRevoked {
		now := time.Now()
		cert.RevokedAt = &now
	}
	cert.RevocationReason = reason
	return nil
}

func (m *MockStore) ListCerts(_ context.Context, opts ListCertsOptions) ([]Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []Certificate
	for _, c := range m.certs {
		if opts.Identity != nil && c.Identity != *opts.Identity {
			continue
		}
		if opts.Status != nil && c.Status != *opts.Status {
			continue
		}
		if opts.Version != nil && c.Version != *opts.Version {
			continue
		}
		result = append(result, *c)
	}
	return result, nil
}

func (m *MockStore) GetNextVersion(_ context.Context, identity string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	maxVersion := 0
	for _, c := range m.certs {
		if c.Identity == identity && c.Version > maxVersion {
			maxVersion = c.Version
		}
	}
	return maxVersion + 1, nil
}

func (m *MockStore) InsertCA(_ context.Context, ca *CertificateAuthority) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *ca
	m.cas[ca.ID] = &cp
	return nil
}

func (m *MockStore) GetActiveCA(_ context.Context) (*CertificateAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ca := range m.cas {
		if ca.IsActive {
			cp := *ca
			return &cp, nil
		}
	}
	return nil, nil
}
