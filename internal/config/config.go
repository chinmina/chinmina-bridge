package config

import (
	"context"
	"fmt"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	Authorization AuthorizationConfig
	Buildkite     BuildkiteConfig
	Cache         CacheConfig
	Github        GithubConfig
	Observe       ObserveConfig
	Server        ServerConfig
}

type ServerConfig struct {
	Port                   int `env:"SERVER_PORT, default=8080"`
	ShutdownTimeoutSeconds int `env:"SERVER_SHUTDOWN_TIMEOUT_SECS, default=25"`

	OutgoingHTTPMaxIdleConns    int    `env:"SERVER_OUTGOING_MAX_IDLE_CONNS, default=100"`
	OutgoingHTTPMaxConnsPerHost int    `env:"SERVER_OUTGOING_MAX_CONNS_PER_HOST, default=20"`
	OrgProfile                  string `env:"GITHUB_ORG_PROFILE"`
}

// CacheConfig specifies cache configuration.
type CacheConfig struct {
	// Type selects the cache implementation: "memory" (default) or "valkey"
	Type string `env:"CACHE_TYPE, default=memory"`

	// Valkey holds distributed cache settings.
	Valkey ValkeyConfig

	// Encryption holds cache encryption settings.
	// Only supported with valkey cache type.
	Encryption CacheEncryptionConfig
}

// ValkeyConfig specifies distributed cache configuration.
type ValkeyConfig struct {
	// Address is the Valkey server address (host:port).
	Address string `env:"VALKEY_ADDRESS"`

	// TLS enables TLS connection to Valkey. Defaults to true so the secure option
	// is the default.
	TLS bool `env:"VALKEY_TLS, default=true"`

	// Username for Valkey authentication.
	Username string `env:"VALKEY_USERNAME"`

	// Password for Valkey authentication.
	Password string `env:"VALKEY_PASSWORD"`
}

// CacheEncryptionConfig holds settings for cache encryption.
type CacheEncryptionConfig struct {
	// Enabled turns on encryption for cached tokens.
	// Requires CACHE_TYPE=valkey.
	Enabled bool `env:"CACHE_ENCRYPTION_ENABLED, default=false"`

	// KeysetURI is the URI to the encrypted Tink keyset.
	// Format: aws-secretsmanager://secret-name
	KeysetURI string `env:"CACHE_ENCRYPTION_KEYSET_URI"`

	// KMSEnvelopeKeyURI is the AWS KMS key URI for envelope encryption.
	// Format: aws-kms://arn:aws:kms:region:account:key/key-id
	KMSEnvelopeKeyURI string `env:"CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI"`
}

type AuthorizationConfig struct {
	Audience                  string `env:"JWT_AUDIENCE, default=app-token-issuer"`
	BuildkiteOrganizationSlug string `env:"JWT_BUILDKITE_ORGANIZATION_SLUG, required"`
	IssuerURL                 string `env:"JWT_ISSUER_URL, default=https://agent.buildkite.com"`
	ConfigurationStatic       string `env:"JWT_JWKS_STATIC"`
}

type BuildkiteConfig struct {
	APIURL string // internal only
	Token  string `env:"BUILDKITE_API_TOKEN, required"`
}

type GithubConfig struct {
	APIURL string // internal only

	PrivateKey    string `env:"GITHUB_APP_PRIVATE_KEY"`
	PrivateKeyARN string `env:"GITHUB_APP_PRIVATE_KEY_ARN"`

	ApplicationID  int64 `env:"GITHUB_APP_ID, required"`
	InstallationID int64 `env:"GITHUB_APP_INSTALLATION_ID, required"`
}

type ObserveConfig struct {
	SDKLogLevel                string `env:"OBSERVE_OTEL_LOG_LEVEL, default=info"`
	Enabled                    bool   `env:"OBSERVE_ENABLED, default=false"`
	MetricsEnabled             bool   `env:"OBSERVE_METRICS_ENABLED, default=true"`
	Type                       string `env:"OBSERVE_TYPE, default=grpc"`
	ServiceName                string `env:"OBSERVE_SERVICE_NAME, default=chinmina-bridge"`
	TraceBatchTimeoutSeconds   int    `env:"OBSERVE_TRACE_BATCH_TIMEOUT_SECS, default=20"`
	MetricReadIntervalSeconds  int    `env:"OBSERVE_METRIC_READ_INTERVAL_SECS, default=60"`
	HTTPTransportEnabled       bool   `env:"OBSERVE_HTTP_TRANSPORT_ENABLED, default=true"`
	HTTPConnectionTraceEnabled bool   `env:"OBSERVE_CONNECTION_TRACE_ENABLED, default=true"`
}

func Load(ctx context.Context) (Config, error) {
	return load(ctx, nil) // load from OS environment
}

func load(ctx context.Context, lookup envconfig.Lookuper) (Config, error) {
	var cfg Config
	err := envconfig.ProcessWith(ctx, &envconfig.Config{
		Target:   &cfg,
		Lookuper: lookup, // nil defaults to OS environment
	})
	if err != nil {
		return cfg, err
	}

	err = cfg.Cache.Validate()
	if err != nil {
		return cfg, fmt.Errorf("invalid cache configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks that the cache configuration is valid.
func (c *CacheConfig) Validate() error {
	// Encryption requires distributed cache
	if c.Encryption.Enabled && c.Type != "valkey" {
		return fmt.Errorf("cache encryption requires CACHE_TYPE=valkey")
	}

	// Encryption requires keyset and KMS URIs
	if c.Encryption.Enabled {
		if c.Encryption.KeysetURI == "" {
			return fmt.Errorf("CACHE_ENCRYPTION_KEYSET_URI required when encryption enabled")
		}
		if c.Encryption.KMSEnvelopeKeyURI == "" {
			return fmt.Errorf("CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI required when encryption enabled")
		}
	}

	// Valkey requires address
	if c.Type == "valkey" && c.Valkey.Address == "" {
		return fmt.Errorf("VALKEY_ADDRESS required when CACHE_TYPE=valkey")
	}

	return nil
}
