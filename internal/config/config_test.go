package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Proxy.ListenAddress != ":8443" {
		t.Errorf("ListenAddress = %q, want %q", cfg.Proxy.ListenAddress, ":8443")
	}
	if cfg.Proxy.MaxConnections != 1000 {
		t.Errorf("MaxConnections = %d, want %d", cfg.Proxy.MaxConnections, 1000)
	}
	if cfg.Cache.TTL != 60*time.Second {
		t.Errorf("Cache.TTL = %v, want %v", cfg.Cache.TTL, 60*time.Second)
	}
	if cfg.Database.Port != 5432 {
		t.Errorf("Database.Port = %d, want %d", cfg.Database.Port, 5432)
	}
	if cfg.TLS.MinVersion != "1.3" {
		t.Errorf("TLS.MinVersion = %q, want %q", cfg.TLS.MinVersion, "1.3")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q, want %q", cfg.Logging.Format, "json")
	}
}

func TestDefaultConfig_RevocationCheckInterval(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Proxy.RevocationCheckInterval != 30*time.Second {
		t.Errorf("RevocationCheckInterval = %v, want %v", cfg.Proxy.RevocationCheckInterval, 30*time.Second)
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	yaml := `
proxy:
  listen_address: ":9443"
  backend_address: "localhost:6379"
  max_connections: 500
tls:
  ca_certificate_path: "/etc/talos/ca.crt"
  server_certificate_path: "/etc/talos/server.crt"
  server_key_path: "/etc/talos/server.key"
  min_version: "1.2"
cache:
  ttl: 30s
  max_entries: 5000
database:
  host: "db.example.com"
  port: 5433
  name: "talos_prod"
  user: "talos_user"
  password: "secret"
logging:
  level: "debug"
  format: "console"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Proxy.ListenAddress != ":9443" {
		t.Errorf("ListenAddress = %q, want %q", cfg.Proxy.ListenAddress, ":9443")
	}
	if cfg.Proxy.BackendAddress != "localhost:6379" {
		t.Errorf("BackendAddress = %q, want %q", cfg.Proxy.BackendAddress, "localhost:6379")
	}
	if cfg.Proxy.MaxConnections != 500 {
		t.Errorf("MaxConnections = %d, want %d", cfg.Proxy.MaxConnections, 500)
	}
	if cfg.TLS.MinVersion != "1.2" {
		t.Errorf("TLS.MinVersion = %q, want %q", cfg.TLS.MinVersion, "1.2")
	}
	if cfg.Cache.TTL != 30*time.Second {
		t.Errorf("Cache.TTL = %v, want %v", cfg.Cache.TTL, 30*time.Second)
	}
	if cfg.Database.Host != "db.example.com" {
		t.Errorf("Database.Host = %q, want %q", cfg.Database.Host, "db.example.com")
	}
	if cfg.Database.Port != 5433 {
		t.Errorf("Database.Port = %d, want %d", cfg.Database.Port, 5433)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "debug")
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	// Minimal config — only required fields
	yaml := `
proxy:
  backend_address: "localhost:6379"
tls:
  ca_certificate_path: "/etc/talos/ca.crt"
  server_certificate_path: "/etc/talos/server.crt"
  server_key_path: "/etc/talos/server.key"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Defaults should be preserved for unset fields
	if cfg.Proxy.ListenAddress != ":8443" {
		t.Errorf("ListenAddress = %q, want default %q", cfg.Proxy.ListenAddress, ":8443")
	}
	if cfg.Cache.TTL != 60*time.Second {
		t.Errorf("Cache.TTL = %v, want default %v", cfg.Cache.TTL, 60*time.Second)
	}
	if cfg.Database.Port != 5432 {
		t.Errorf("Database.Port = %d, want default %d", cfg.Database.Port, 5432)
	}
}

func TestLoad_RevocationCheckInterval(t *testing.T) {
	yamlContent := `
proxy:
  backend_address: "localhost:6379"
  revocation_check_interval: 15s
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
`
	path := writeTemp(t, yamlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Proxy.RevocationCheckInterval != 15*time.Second {
		t.Errorf("RevocationCheckInterval = %v, want %v", cfg.Proxy.RevocationCheckInterval, 15*time.Second)
	}
}

func TestLoad_RevocationCheckIntervalDisabled(t *testing.T) {
	yamlContent := `
proxy:
  backend_address: "localhost:6379"
  revocation_check_interval: 0s
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
`
	path := writeTemp(t, yamlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Proxy.RevocationCheckInterval != 0 {
		t.Errorf("RevocationCheckInterval = %v, want 0", cfg.Proxy.RevocationCheckInterval)
	}
}

func TestLoad_RevocationCheckIntervalTooSmall(t *testing.T) {
	yamlContent := `
proxy:
  backend_address: "localhost:6379"
  revocation_check_interval: 500ms
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
`
	path := writeTemp(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for interval < 1s, got nil")
	}
	if !contains(err.Error(), "revocation_check_interval") {
		t.Errorf("error = %q, want to mention revocation_check_interval", err.Error())
	}
}

func TestLoad_RevocationCheckIntervalEnvOverride(t *testing.T) {
	yamlContent := `
proxy:
  backend_address: "localhost:6379"
  revocation_check_interval: 15s
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
`
	path := writeTemp(t, yamlContent)
	t.Setenv("TALOS_PROXY_REVOCATION_CHECK_INTERVAL", "45s")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Proxy.RevocationCheckInterval != 45*time.Second {
		t.Errorf("RevocationCheckInterval = %v, want %v", cfg.Proxy.RevocationCheckInterval, 45*time.Second)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing backend_address",
			yaml: `
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
`,
			want: "proxy.backend_address is required",
		},
		{
			name: "missing TLS paths",
			yaml: `
proxy:
  backend_address: "localhost:6379"
`,
			want: "tls.ca_certificate_path is required",
		},
		{
			name: "invalid TLS version",
			yaml: `
proxy:
  backend_address: "localhost:6379"
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
  min_version: "1.1"
`,
			want: "tls.min_version must be 1.2 or 1.3",
		},
		{
			name: "invalid log level",
			yaml: `
proxy:
  backend_address: "localhost:6379"
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
logging:
  level: "trace"
`,
			want: "logging.level must be debug/info/warn/error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemp(t, tt.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() expected error, got nil")
			}
			if got := err.Error(); !contains(got, tt.want) {
				t.Errorf("error = %q, want to contain %q", got, tt.want)
			}
		})
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	yaml := `
proxy:
  backend_address: "localhost:6379"
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
database:
  password: "from-yaml"
`
	path := writeTemp(t, yaml)

	t.Setenv("TALOS_DATABASE_PASSWORD", "from-env")
	t.Setenv("TALOS_DATABASE_PORT", "5434")
	t.Setenv("TALOS_PROXY_LISTEN_ADDRESS", ":7443")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Database.Password != "from-env" {
		t.Errorf("Database.Password = %q, want %q", cfg.Database.Password, "from-env")
	}
	if cfg.Database.Port != 5434 {
		t.Errorf("Database.Port = %d, want %d", cfg.Database.Port, 5434)
	}
	if cfg.Proxy.ListenAddress != ":7443" {
		t.Errorf("ListenAddress = %q, want %q", cfg.Proxy.ListenAddress, ":7443")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/talos.yaml")
	if err == nil {
		t.Fatal("Load() expected error for missing file")
	}
}

func TestDatabaseConfig_DSN(t *testing.T) {
	cfg := DatabaseConfig{
		Host:    "db.example.com",
		Port:    5432,
		Name:    "talos",
		User:    "app",
		SSLMode: "require",
	}
	got := cfg.DSN()
	want := "host=db.example.com port=5432 dbname=talos user=app sslmode=require"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}

	cfg.Password = "secret"
	got = cfg.DSN()
	if !contains(got, "password=secret") {
		t.Errorf("DSN() = %q, want to contain password", got)
	}
}

func TestLoad_IssuanceConfig(t *testing.T) {
	yaml := `
proxy:
  backend_address: "localhost:6379"
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
issuance:
  listen_address: ":8443"
  tls:
    certificate_path: "/etc/talos/issuance-server.crt"
    key_path: "/etc/talos/issuance-server.key"
  kerberos:
    keytab_path: "/etc/krb5.keytab"
    service_principal: "HTTP/talos.upsidr.local@DIRECTORY.UPSIDR.LOCAL"
    allowed_realms:
      - DIRECTORY.UPSIDR.LOCAL
    allowed_principals:
      - johndoe@DIRECTORY.UPSIDR.LOCAL
  identity_mapping:
    strategy: principal
  certificate:
    expires_in: 90d
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Issuance == nil {
		t.Fatal("Issuance config should not be nil")
	}
	if cfg.Issuance.ListenAddress != ":8443" {
		t.Errorf("ListenAddress = %q, want %q", cfg.Issuance.ListenAddress, ":8443")
	}
	if cfg.Issuance.TLS.CertificatePath != "/etc/talos/issuance-server.crt" {
		t.Errorf("TLS.CertificatePath = %q", cfg.Issuance.TLS.CertificatePath)
	}
	if cfg.Issuance.Kerberos.KeytabPath != "/etc/krb5.keytab" {
		t.Errorf("KeytabPath = %q", cfg.Issuance.Kerberos.KeytabPath)
	}
	if cfg.Issuance.Kerberos.ServicePrincipal != "HTTP/talos.upsidr.local@DIRECTORY.UPSIDR.LOCAL" {
		t.Errorf("ServicePrincipal = %q", cfg.Issuance.Kerberos.ServicePrincipal)
	}
	if len(cfg.Issuance.Kerberos.AllowedRealms) != 1 || cfg.Issuance.Kerberos.AllowedRealms[0] != "DIRECTORY.UPSIDR.LOCAL" {
		t.Errorf("AllowedRealms = %v", cfg.Issuance.Kerberos.AllowedRealms)
	}
	if len(cfg.Issuance.Kerberos.AllowedPrincipals) != 1 || cfg.Issuance.Kerberos.AllowedPrincipals[0] != "johndoe@DIRECTORY.UPSIDR.LOCAL" {
		t.Errorf("AllowedPrincipals = %v", cfg.Issuance.Kerberos.AllowedPrincipals)
	}
	if cfg.Issuance.IdentityMapping.Strategy != "principal" {
		t.Errorf("Strategy = %q", cfg.Issuance.IdentityMapping.Strategy)
	}
	if cfg.Issuance.Certificate.ExpiresIn != "90d" {
		t.Errorf("ExpiresIn = %q", cfg.Issuance.Certificate.ExpiresIn)
	}
}

func TestLoad_IssuanceNil(t *testing.T) {
	yaml := `
proxy:
  backend_address: "localhost:6379"
tls:
  ca_certificate_path: "/ca.crt"
  server_certificate_path: "/server.crt"
  server_key_path: "/server.key"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Issuance != nil {
		t.Error("Issuance config should be nil when not configured")
	}
}

func TestLoad_IssuanceMissingRequired(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing listen_address",
			yaml: `
issuance:
  tls:
    certificate_path: "/cert.pem"
    key_path: "/key.pem"
  kerberos:
    keytab_path: "/keytab"
    service_principal: "HTTP/host@REALM"
    allowed_realms: [REALM]
`,
			want: "issuance.listen_address is required",
		},
		{
			name: "missing tls cert",
			yaml: `
issuance:
  listen_address: ":8443"
  tls:
    key_path: "/key.pem"
  kerberos:
    keytab_path: "/keytab"
    service_principal: "HTTP/host@REALM"
    allowed_realms: [REALM]
`,
			want: "issuance.tls.certificate_path is required",
		},
		{
			name: "missing keytab_path",
			yaml: `
issuance:
  listen_address: ":8443"
  tls:
    certificate_path: "/cert.pem"
    key_path: "/key.pem"
  kerberos:
    service_principal: "HTTP/host@REALM"
    allowed_realms: [REALM]
`,
			want: "issuance.kerberos.keytab_path is required",
		},
		{
			name: "missing service_principal",
			yaml: `
issuance:
  listen_address: ":8443"
  tls:
    certificate_path: "/cert.pem"
    key_path: "/key.pem"
  kerberos:
    keytab_path: "/keytab"
    allowed_realms: [REALM]
`,
			want: "issuance.kerberos.service_principal is required",
		},
		{
			name: "missing allowed_realms",
			yaml: `
issuance:
  listen_address: ":8443"
  tls:
    certificate_path: "/cert.pem"
    key_path: "/key.pem"
  kerberos:
    keytab_path: "/keytab"
    service_principal: "HTTP/host@REALM"
`,
			want: "issuance.kerberos.allowed_realms is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemp(t, tt.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() expected error, got nil")
			}
			if got := err.Error(); !contains(got, tt.want) {
				t.Errorf("error = %q, want to contain %q", got, tt.want)
			}
		})
	}
}

func TestLoad_IssuanceEnvOverride(t *testing.T) {
	yaml := `
issuance:
  listen_address: ":8443"
  tls:
    certificate_path: "/cert.pem"
    key_path: "/key.pem"
  kerberos:
    keytab_path: "/keytab"
    service_principal: "HTTP/host@REALM"
    allowed_realms: [REALM]
  identity_mapping:
    strategy: principal
`
	path := writeTemp(t, yaml)
	t.Setenv("TALOS_ISSUANCE_LISTEN_ADDRESS", ":9443")
	t.Setenv("TALOS_ISSUANCE_KERBEROS_KEYTAB_PATH", "/alt/keytab")
	t.Setenv("TALOS_ISSUANCE_IDENTITY_MAPPING_STRATEGY", "username")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Issuance.ListenAddress != ":9443" {
		t.Errorf("ListenAddress = %q, want %q", cfg.Issuance.ListenAddress, ":9443")
	}
	if cfg.Issuance.Kerberos.KeytabPath != "/alt/keytab" {
		t.Errorf("KeytabPath = %q, want %q", cfg.Issuance.Kerberos.KeytabPath, "/alt/keytab")
	}
	if cfg.Issuance.IdentityMapping.Strategy != "username" {
		t.Errorf("Strategy = %q, want %q", cfg.Issuance.IdentityMapping.Strategy, "username")
	}
}

func TestLoad_IssuanceInvalidStrategy(t *testing.T) {
	yaml := `
issuance:
  listen_address: ":8443"
  tls:
    certificate_path: "/cert.pem"
    key_path: "/key.pem"
  kerberos:
    keytab_path: "/keytab"
    service_principal: "HTTP/host@REALM"
    allowed_realms: [REALM]
  identity_mapping:
    strategy: invalid
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for invalid strategy, got nil")
	}
	if !contains(err.Error(), "issuance.identity_mapping.strategy") {
		t.Errorf("error = %q, want to mention strategy", err.Error())
	}
}

func TestLoad_IssuanceOnlyMode(t *testing.T) {
	yaml := `
issuance:
  listen_address: ":8443"
  tls:
    certificate_path: "/cert.pem"
    key_path: "/key.pem"
  kerberos:
    keytab_path: "/keytab"
    service_principal: "HTTP/host@REALM"
    allowed_realms: [REALM]
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v (issuance-only mode should not require proxy fields)", err)
	}
	if cfg.Issuance == nil {
		t.Fatal("Issuance config should not be nil")
	}
	if cfg.Proxy.BackendAddress != "" {
		t.Error("BackendAddress should be empty in issuance-only mode")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "talos.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
