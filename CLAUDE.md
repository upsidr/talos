# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Talos is a certificate-authenticated mTLS TCP proxy written in Go. It sits in front of backend TCP services (Redis, PostgreSQL, MongoDB, etc.) and authenticates every connection using client certificates with real-time revocation checks against a PostgreSQL database. Named after the bronze guardian of Crete in Greek mythology.

Talos is a sub-project within the Elpis workspace (FreeIPA + Cloudflare Tunnel infrastructure on GCP).

## Build & Run

```bash
# Build
go build ./cmd/talos

# Run tests (none exist yet)
go test ./...

# Run a single package's tests
go test ./internal/proxy/
```

No Makefile exists — use standard Go toolchain commands.

## Architecture

```
CLI (Cobra) → Config → Proxy Server
                          ├── TLS Listener (mTLS, RequireAndVerifyClientCert)
                          ├── Certificate Cache (in-memory, TTL-based)
                          └── CertificateStore interface
                              └── PostgresStore (pgx connection pool)
```

**Key design decisions:**

- **Fail-closed**: connections are rejected if the database is unreachable
- **Direct DB revocation** (not CRL/OCSP): near-instant revocation with no distribution lag
- **In-memory cache** with configurable TTL (default 60s) balances performance vs. revocation latency
- **GCP KMS** for CA signing (private key never leaves HSM) — not yet implemented
- **TLS 1.3 minimum** (configurable down to 1.2)
- **Session tickets disabled** to force full handshake on every connection

## Package Structure

- **`cmd/talos/`** — Cobra CLI entry point. Defines command groups: `proxy start`, `cert {issue,revoke,reissue,list,show}`, `ca init`, `version`. Most commands are stubs returning "not implemented".
- **`internal/config/`** — YAML-mapped configuration structs (proxy, TLS, cache, database, KMS, certificate defaults, logging). Config loading/parsing is not yet implemented.
- **`internal/proxy/`** — Core mTLS proxy server (`proxy.go`) and TTL cache (`cache.go`). Handles TLS listener, client cert validation via DB lookup, bidirectional TCP relay, and structured JSON audit logging.
- **`internal/store/`** — `CertificateStore` interface (`store.go`), PostgreSQL implementation (`postgres.go`), and database schema (`schema.sql`). The interface enables swapping backends for testing.
- **`internal/cert/`** — Empty; intended for certificate issuance logic (X.509 generation + KMS signing).
- **`pkg/`** — Empty; intended for shared libraries.
- **`docs/`** — Design document `design.md` (comprehensive spec and implementation roadmap).

## Database Schema

Defined in `internal/store/schema.sql` with 3 tables:

- **certificate_authorities** — CA records with KMS key references
- **certificates** — Client certs with fingerprint index (hot path for proxy lookups), status (`active`|`revoked`), identity+version uniqueness
- **audit_log** — Connection and cert lifecycle events (JSONB details)

## Dependencies

3 direct dependencies: `pgx/v5` (PostgreSQL), `cobra` (CLI), `zap` (structured logging).

## Conventions

- All comments and documentation in the parent Elpis project are in Japanese; Talos documentation is in English
- Design document serves as the implementation roadmap — refer to `docs/002-Talos-CertAuthTCPProxy.md` for detailed specs
- Dev certificates go in `dev/` (gitignored)
