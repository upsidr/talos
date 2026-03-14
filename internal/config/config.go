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
	Issuance    *IssuanceConfig   `yaml:"issuance,omitempty"`
}

// IssuanceConfig configures the Kerberos-authenticated certificate issuance server.
type IssuanceConfig struct {
	ListenAddress   string                  `yaml:"listen_address"`
	TLS             IssuanceTLSConfig       `yaml:"tls"`
	Kerberos        KerberosConfig          `yaml:"kerberos"`
	IdentityMapping IdentityMappingConfig   `yaml:"identity_mapping"`
	Certificate     IssuanceCertificateConfig `yaml:"certificate"`
}

// IssuanceTLSConfig configures TLS for the issuance endpoint (standard TLS, not mTLS).
type IssuanceTLSConfig struct {
	CertificatePath string `yaml:"certificate_path"`
	KeyPath         string `yaml:"key_path"`
}

// KerberosConfig configures Kerberos/SPNEGO authentication.
type KerberosConfig struct {
	KeytabPath        string   `yaml:"keytab_path"`
	ServicePrincipal  string   `yaml:"service_principal"`
	AllowedRealms     []string `yaml:"allowed_realms"`
	AllowedPrincipals []string `yaml:"allowed_principals"`
}

// IdentityMappingConfig configures how Kerberos principals map to certificate identities.
type IdentityMappingConfig struct {
	Strategy string `yaml:"strategy"`
}

// IssuanceCertificateConfig overrides certificate defaults for Kerberos-issued certs.
type IssuanceCertificateConfig struct {
	ExpiresIn string `yaml:"expires_in"`
}

type ProxyConfig struct {
	ListenAddress            string        `yaml:"listen_address"`
	BackendAddress           string        `yaml:"backend_address"`
	BackendTLS               bool          `yaml:"backend_tls"`
	MaxConnections           int           `yaml:"max_connections"`
	KeepaliveInterval        time.Duration `yaml:"keepalive_interval"`
	RevocationCheckInterval  time.Duration `yaml:"revocation_check_interval"`
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
			ListenAddress:           ":8443",
			MaxConnections:          1000,
			KeepaliveInterval:       30 * time.Second,
			RevocationCheckInterval: 30 * time.Second,
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
	if v := os.Getenv("TALOS_PROXY_REVOCATION_CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Proxy.RevocationCheckInterval = d
		}
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

	// Issuance env overrides
	if cfg.Issuance != nil {
		if v := os.Getenv("TALOS_ISSUANCE_LISTEN_ADDRESS"); v != "" {
			cfg.Issuance.ListenAddress = v
		}
		if v := os.Getenv("TALOS_ISSUANCE_KERBEROS_KEYTAB_PATH"); v != "" {
			cfg.Issuance.Kerberos.KeytabPath = v
		}
		if v := os.Getenv("TALOS_ISSUANCE_KERBEROS_SERVICE_PRINCIPAL"); v != "" {
			cfg.Issuance.Kerberos.ServicePrincipal = v
		}
		if v := os.Getenv("TALOS_ISSUANCE_IDENTITY_MAPPING_STRATEGY"); v != "" {
			cfg.Issuance.IdentityMapping.Strategy = v
		}
	}
}

// validate checks that required fields are set and values are within valid ranges.
func validate(cfg Config) error {
	var errs []string

	// In issuance-only mode, skip proxy-specific validation
	isIssuanceOnly := cfg.Issuance != nil && cfg.Proxy.BackendAddress == ""

	if !isIssuanceOnly {
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
	}

	if cfg.Database.Host == "" {
		errs = append(errs, "database.host is required")
	}

	if v := cfg.Proxy.RevocationCheckInterval; v != 0 && v < time.Second {
		errs = append(errs, fmt.Sprintf("proxy.revocation_check_interval must be 0 (disabled) or >= 1s, got %v", v))
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

	// Issuance-specific validation
	if cfg.Issuance != nil {
		iss := cfg.Issuance
		if iss.ListenAddress == "" {
			errs = append(errs, "issuance.listen_address is required")
		}
		if iss.TLS.CertificatePath == "" {
			errs = append(errs, "issuance.tls.certificate_path is required")
		}
		if iss.TLS.KeyPath == "" {
			errs = append(errs, "issuance.tls.key_path is required")
		}
		if iss.Kerberos.KeytabPath == "" {
			errs = append(errs, "issuance.kerberos.keytab_path is required")
		}
		if iss.Kerberos.ServicePrincipal == "" {
			errs = append(errs, "issuance.kerberos.service_principal is required")
		}
		if len(iss.Kerberos.AllowedRealms) == 0 {
			errs = append(errs, "issuance.kerberos.allowed_realms is required")
		}
		if s := iss.IdentityMapping.Strategy; s != "" && s != "principal" && s != "username" {
			errs = append(errs, fmt.Sprintf("issuance.identity_mapping.strategy must be principal or username, got %q", s))
		}
		if iss.Certificate.ExpiresIn != "" {
			if _, err := parseDurationString(iss.Certificate.ExpiresIn); err != nil {
				errs = append(errs, fmt.Sprintf("issuance.certificate.expires_in is invalid: %v", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// parseDurationString parses duration strings like "90d", "365d", "10y" in addition to Go durations.
func parseDurationString(s string) (time.Duration, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty duration string")
	}
	last := s[len(s)-1]
	switch last {
	case 'd':
		return parseDurationMultiple(s[:len(s)-1], 24*time.Hour)
	case 'y':
		return parseDurationMultiple(s[:len(s)-1], 365*24*time.Hour)
	default:
		return time.ParseDuration(s)
	}
}

func parseDurationMultiple(numStr string, unit time.Duration) (time.Duration, error) {
	var n int
	for _, c := range numStr {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid duration: %s", numStr)
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return time.Duration(n) * unit, nil
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
