package config

import "time"

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
