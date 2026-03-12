CREATE TABLE IF NOT EXISTS certificate_authorities (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kms_key_resource_name TEXT NOT NULL,
    subject_dn            TEXT NOT NULL,
    certificate_pem       TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ NOT NULL,
    is_active             BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS certificates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number       TEXT NOT NULL UNIQUE,
    identity            TEXT NOT NULL,
    version             INTEGER NOT NULL,
    ca_id               UUID NOT NULL REFERENCES certificate_authorities(id),
    fingerprint_sha256  TEXT NOT NULL UNIQUE,
    subject_dn          TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'revoked')),
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,
    issued_by           TEXT NOT NULL,

    UNIQUE(identity, version)
);

CREATE INDEX IF NOT EXISTS idx_certificates_identity ON certificates(identity);
CREATE INDEX IF NOT EXISTS idx_certificates_fingerprint ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action          TEXT NOT NULL,
    identity        TEXT,
    certificate_id  UUID REFERENCES certificates(id),
    actor           TEXT NOT NULL,
    details         JSONB,
    client_ip       INET
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_identity ON audit_log(identity);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
