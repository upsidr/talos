package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements CertificateStore backed by PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgresStore with the given connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) GetCertByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, serial_number, identity, version, ca_id, fingerprint_sha256,
		        subject_dn, status, issued_at, expires_at, revoked_at,
		        revocation_reason, issued_by
		 FROM certificates WHERE fingerprint_sha256 = $1`, fingerprint)

	cert := &Certificate{}
	err := row.Scan(
		&cert.ID, &cert.SerialNumber, &cert.Identity, &cert.Version,
		&cert.CAID, &cert.FingerprintSHA256, &cert.SubjectDN, &cert.Status,
		&cert.IssuedAt, &cert.ExpiresAt, &cert.RevokedAt,
		&cert.RevocationReason, &cert.IssuedBy,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query certificate by fingerprint: %w", err)
	}
	return cert, nil
}

func (s *PostgresStore) InsertCert(ctx context.Context, cert *Certificate) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO certificates
		 (id, serial_number, identity, version, ca_id, fingerprint_sha256,
		  subject_dn, status, issued_at, expires_at, issued_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		cert.ID, cert.SerialNumber, cert.Identity, cert.Version,
		cert.CAID, cert.FingerprintSHA256, cert.SubjectDN, cert.Status,
		cert.IssuedAt, cert.ExpiresAt, cert.IssuedBy,
	)
	if err != nil {
		return fmt.Errorf("insert certificate: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateCertStatus(ctx context.Context, id string, status CertificateStatus, reason *string) error {
	var revokedAt *time.Time
	if status == StatusRevoked {
		now := time.Now()
		revokedAt = &now
	}

	_, err := s.pool.Exec(ctx,
		`UPDATE certificates SET status = $1, revoked_at = $2, revocation_reason = $3
		 WHERE id = $4`,
		status, revokedAt, reason, id,
	)
	if err != nil {
		return fmt.Errorf("update certificate status: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListCerts(ctx context.Context, opts ListCertsOptions) ([]Certificate, error) {
	query := `SELECT id, serial_number, identity, version, ca_id, fingerprint_sha256,
	                 subject_dn, status, issued_at, expires_at, revoked_at,
	                 revocation_reason, issued_by
	          FROM certificates WHERE 1=1`
	args := []any{}
	argIdx := 1

	if opts.Identity != nil {
		query += fmt.Sprintf(" AND identity = $%d", argIdx)
		args = append(args, *opts.Identity)
		argIdx++
	}
	if opts.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, *opts.Status)
		argIdx++
	}
	if opts.Version != nil {
		query += fmt.Sprintf(" AND version = $%d", argIdx)
		args = append(args, *opts.Version)
	}

	query += " ORDER BY identity, version"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		var cert Certificate
		err := rows.Scan(
			&cert.ID, &cert.SerialNumber, &cert.Identity, &cert.Version,
			&cert.CAID, &cert.FingerprintSHA256, &cert.SubjectDN, &cert.Status,
			&cert.IssuedAt, &cert.ExpiresAt, &cert.RevokedAt,
			&cert.RevocationReason, &cert.IssuedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan certificate row: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

func (s *PostgresStore) GetNextVersion(ctx context.Context, identity string) (int, error) {
	var maxVersion *int
	err := s.pool.QueryRow(ctx,
		`SELECT MAX(version) FROM certificates WHERE identity = $1`, identity,
	).Scan(&maxVersion)
	if err != nil {
		return 0, fmt.Errorf("get max version: %w", err)
	}
	if maxVersion == nil {
		return 1, nil
	}
	return *maxVersion + 1, nil
}

func (s *PostgresStore) InsertCA(ctx context.Context, ca *CertificateAuthority) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO certificate_authorities
		 (id, kms_key_resource_name, subject_dn, certificate_pem, created_at, expires_at, is_active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ca.ID, ca.KMSKeyResourceName, ca.SubjectDN, ca.CertificatePEM,
		ca.CreatedAt, ca.ExpiresAt, ca.IsActive,
	)
	if err != nil {
		return fmt.Errorf("insert CA: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetActiveCA(ctx context.Context) (*CertificateAuthority, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, kms_key_resource_name, subject_dn, certificate_pem,
		        created_at, expires_at, is_active
		 FROM certificate_authorities WHERE is_active = true
		 ORDER BY created_at DESC LIMIT 1`)

	ca := &CertificateAuthority{}
	err := row.Scan(
		&ca.ID, &ca.KMSKeyResourceName, &ca.SubjectDN, &ca.CertificatePEM,
		&ca.CreatedAt, &ca.ExpiresAt, &ca.IsActive,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query active CA: %w", err)
	}
	return ca, nil
}
