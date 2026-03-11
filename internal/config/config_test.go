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
