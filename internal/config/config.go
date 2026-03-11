package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level application configuration.
type Config struct {
	Proxy       ProxyConfig       `yaml:"proxy"`
	TLS         TLSConfig         `yaml:"tls"`
	Cache       CacheConfig       `yaml:"cache"`
	Database    DatabaseConfig    `yaml:"database"`
	KMS         KMSConfig         `yaml:"kms"`
	Certificate CertificateConfig `yaml:"certificate"`
	Logging     LoggingConfig     `yaml:"logging"`
}

type ProxyConfig struct {
	ListenAddress     string        `yaml:"listen_address"`
	BackendAddress    string        `yaml:"backend_address"`
	BackendTLS        bool          `yaml:"backend_tls"`
	MaxConnections    int           `yaml:"max_connections"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
}

type TLSConfig struct {
	CACertificatePath     string `yaml:"ca_certificate_path"`
	MinVersion            string `yaml:"min_version"`
	ServerCertificatePath string `yaml:"server_certificate_path"`
	ServerKeyPath         string `yaml:"server_key_path"`
}

type CacheConfig struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}

type DatabaseConfig struct {
	Host                  string        `yaml:"host"`
	Port                  int           `yaml:"port"`
	Name                  string        `yaml:"name"`
	User                  string        `yaml:"user"`
	Password              string        `yaml:"password"`
	PasswordSecret        string        `yaml:"password_secret"`
	MaxOpenConnections    int           `yaml:"max_open_connections"`
	MaxIdleConnections    int           `yaml:"max_idle_connections"`
	ConnectionMaxLifetime time.Duration `yaml:"connection_max_lifetime"`
	SSLMode               string        `yaml:"sslmode"`
	SSLRootCert           string        `yaml:"sslrootcert"`
}

type KMSConfig struct {
	KeyResourceName string `yaml:"key_resource_name"`
}

type CertificateConfig struct {
	DefaultValidity time.Duration `yaml:"default_validity"`
	MaxValidity     time.Duration `yaml:"max_validity"`
	Organization    string        `yaml:"organization"`
}

type LoggingConfig struct {
	Format string `yaml:"format"`
	Level  string `yaml:"level"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Proxy: ProxyConfig{
			ListenAddress:     ":8443",
			MaxConnections:    1000,
			KeepaliveInterval: 30 * time.Second,
		},
		TLS: TLSConfig{
			MinVersion: "1.3",
		},
		Cache: CacheConfig{
			TTL:        60 * time.Second,
			MaxEntries: 10000,
		},
		Database: DatabaseConfig{
			Host:                  "localhost",
			Port:                  5432,
			Name:                  "talos",
			User:                  "talos",
			MaxOpenConnections:    10,
			MaxIdleConnections:    5,
			ConnectionMaxLifetime: 30 * time.Minute,
			SSLMode:               "disable",
		},
		Certificate: CertificateConfig{
			DefaultValidity: 90 * 24 * time.Hour,
			MaxValidity:     365 * 24 * time.Hour,
		},
		Logging: LoggingConfig{
			Format: "json",
			Level:  "info",
		},
	}
}

// Load reads configuration from a YAML file, overlays environment variables,
// and validates the result.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	applyEnvOverrides(&cfg)

	if err := validate(cfg); err != nil {
		return Config{}, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// applyEnvOverrides overlays TALOS_ prefixed environment variables onto the config.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("TALOS_PROXY_LISTEN_ADDRESS"); v != "" {
		cfg.Proxy.ListenAddress = v
	}
	if v := os.Getenv("TALOS_PROXY_BACKEND_ADDRESS"); v != "" {
		cfg.Proxy.BackendAddress = v
	}
	if v := os.Getenv("TALOS_DATABASE_HOST"); v != "" {
		cfg.Database.Host = v
	}
	if v := os.Getenv("TALOS_DATABASE_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Database.Port = port
		}
	}
	if v := os.Getenv("TALOS_DATABASE_NAME"); v != "" {
		cfg.Database.Name = v
	}
	if v := os.Getenv("TALOS_DATABASE_USER"); v != "" {
		cfg.Database.User = v
	}
	if v := os.Getenv("TALOS_DATABASE_PASSWORD"); v != "" {
		cfg.Database.Password = v
	}
	if v := os.Getenv("TALOS_DATABASE_SSLMODE"); v != "" {
		cfg.Database.SSLMode = v
	}
	if v := os.Getenv("TALOS_TLS_CA_CERTIFICATE_PATH"); v != "" {
		cfg.TLS.CACertificatePath = v
	}
	if v := os.Getenv("TALOS_TLS_SERVER_CERTIFICATE_PATH"); v != "" {
		cfg.TLS.ServerCertificatePath = v
	}
	if v := os.Getenv("TALOS_TLS_SERVER_KEY_PATH"); v != "" {
		cfg.TLS.ServerKeyPath = v
	}
	if v := os.Getenv("TALOS_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("TALOS_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
}

// validate checks that required fields are set and values are within valid ranges.
func validate(cfg Config) error {
	var errs []string

	if cfg.Proxy.BackendAddress == "" {
		errs = append(errs, "proxy.backend_address is required")
	}
	if cfg.TLS.CACertificatePath == "" {
		errs = append(errs, "tls.ca_certificate_path is required")
	}
	if cfg.TLS.ServerCertificatePath == "" {
		errs = append(errs, "tls.server_certificate_path is required")
	}
	if cfg.TLS.ServerKeyPath == "" {
		errs = append(errs, "tls.server_key_path is required")
	}
	if cfg.Database.Host == "" {
		errs = append(errs, "database.host is required")
	}

	if v := cfg.TLS.MinVersion; v != "" && v != "1.2" && v != "1.3" {
		errs = append(errs, fmt.Sprintf("tls.min_version must be 1.2 or 1.3, got %q", v))
	}
	if v := cfg.Logging.Level; v != "" {
		switch v {
		case "debug", "info", "warn", "error":
		default:
			errs = append(errs, fmt.Sprintf("logging.level must be debug/info/warn/error, got %q", v))
		}
	}
	if v := cfg.Logging.Format; v != "" {
		switch v {
		case "json", "console":
		default:
			errs = append(errs, fmt.Sprintf("logging.format must be json or console, got %q", v))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// DSN returns a PostgreSQL connection string from the database config.
func (d DatabaseConfig) DSN() string {
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=%s",
		d.Host, d.Port, d.Name, d.User, d.SSLMode)
	if d.Password != "" {
		dsn += fmt.Sprintf(" password=%s", d.Password)
	}
	if d.SSLRootCert != "" {
		dsn += fmt.Sprintf(" sslrootcert=%s", d.SSLRootCert)
	}
	return dsn
}
