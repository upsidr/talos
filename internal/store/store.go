package store

import (
	"context"
	"time"
)

// CertificateStatus represents the status of a certificate.
type CertificateStatus string

const (
	StatusActive  CertificateStatus = "active"
	StatusRevoked CertificateStatus = "revoked"
)

// Certificate represents a certificate record in the catalog.
type Certificate struct {
	ID                string
	SerialNumber      string
	Identity          string
	Version           int
	CAID              string
	FingerprintSHA256 string
	SubjectDN         string
	Status            CertificateStatus
	IssuedAt          time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	RevocationReason  *string
	IssuedBy          string
}

// CertificateAuthority represents a CA record.
type CertificateAuthority struct {
	ID                 string
	KMSKeyResourceName string
	SubjectDN          string
	CertificatePEM     string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	IsActive           bool
}

// CertificateStore defines the interface for certificate catalog persistence.
type CertificateStore interface {
	// GetCertByFingerprint looks up a certificate by its SHA-256 fingerprint.
	// This is the hot-path query used by the proxy on every TLS handshake (cache miss).
	GetCertByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error)

	// InsertCert inserts a new certificate record.
	InsertCert(ctx context.Context, cert *Certificate) error

	// UpdateCertStatus updates the status of a certificate (e.g., active → revoked).
	UpdateCertStatus(ctx context.Context, id string, status CertificateStatus, reason *string) error

	// ListCerts returns certificates, optionally filtered by identity and/or status.
	ListCerts(ctx context.Context, opts ListCertsOptions) ([]Certificate, error)

	// GetNextVersion returns the next version number for a given identity.
	GetNextVersion(ctx context.Context, identity string) (int, error)

	// InsertCA inserts a new certificate authority record.
	InsertCA(ctx context.Context, ca *CertificateAuthority) error

	// GetActiveCA returns the currently active CA.
	GetActiveCA(ctx context.Context) (*CertificateAuthority, error)
}

// ListCertsOptions are filters for listing certificates.
type ListCertsOptions struct {
	Identity *string
	Status   *CertificateStatus
	Version  *int
}
