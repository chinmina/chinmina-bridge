package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

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
	BasePath                    string `env:"SERVER_BASE_PATH"`
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

	// IAMEnabled enables IAM-based authentication for AWS ElastiCache.
	// When true, Username is used as the IAM user ID and must be set,
	// IAMCacheName is required, Password must be empty, and TLS is
	// automatically enabled.
	IAMEnabled bool `env:"VALKEY_IAM_ENABLED, default=false"`

	// IAMCacheName is the ElastiCache replication group ID or serverless cache
	// name. Required when IAMEnabled is true.
	IAMCacheName string `env:"VALKEY_IAM_CACHE_NAME"`

	// IAMServerless marks the target as an ElastiCache serverless cache.
	IAMServerless bool `env:"VALKEY_IAM_SERVERLESS, default=false"`
}

// CacheEncryptionConfig holds settings for cache encryption.
type CacheEncryptionConfig struct {
	// Enabled turns on encryption for cached tokens.
	// Requires CACHE_TYPE=valkey.
	Enabled bool `env:"CACHE_ENCRYPTION_ENABLED, default=false"`

	// KeysetURI is the URI to the encrypted Tink keyset.
	// Format: aws-secretsmanager://secret-name
	// Mutually exclusive with KeysetFile.
	KeysetURI string `env:"CACHE_ENCRYPTION_KEYSET_URI"`

	// KMSEnvelopeKeyURI is the AWS KMS key URI for envelope encryption.
	// Format: aws-kms://arn:aws:kms:region:account:key/key-id
	// Required when KeysetURI is set.
	KMSEnvelopeKeyURI string `env:"CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI"`

	// KeysetFile is a path to a cleartext Tink keyset JSON file.
	// For local development only — mutually exclusive with KeysetURI/KMSEnvelopeKeyURI.
	KeysetFile string `env:"CACHE_ENCRYPTION_KEYSET_FILE"`
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

	// Apps holds the named GitHub App registry as raw JSON: its schema,
	// validation and redaction rules belong with the registry, not with
	// environment loading. Empty means the default app above vends every token.
	Apps string `env:"GITHUB_APPS"`
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
	PyroscopeEnabled           bool   `env:"OBSERVE_PYROSCOPE_ENABLED, default=false"`
	PyroscopeServerAddress     string `env:"OBSERVE_PYROSCOPE_SERVER_ADDRESS"`
	PyroscopeBasicAuthUser     string `env:"OBSERVE_PYROSCOPE_BASIC_AUTH_USER"`
	PyroscopeBasicAuthPassword string `env:"OBSERVE_PYROSCOPE_BASIC_AUTH_PASSWORD"`
	// PyroscopeExperimentFlag allows tagging profiling data with an experiment label at
	// runtime, overriding the compile-time experiment tag set via build flags.
	PyroscopeExperimentFlag string `env:"OBSERVE_PYROSCOPE_EXPERIMENT"`
}

func Load(ctx context.Context) (Config, error) {
	lookup := newFileContentLookuper(envconfig.OsLookuper(), "JWT_JWKS_STATIC", "GITHUB_APP_PRIVATE_KEY")
	return load(ctx, lookup)
}

// errLookuper is implemented by lookupers that may accumulate an error while
// resolving values (e.g. a "_FILE" decoder failing to read its target file).
// load checks for this after ProcessWith completes, since [envconfig.Lookuper.Lookup]
// itself has no way to report an error.
type errLookuper interface {
	Err() error
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
	if el, ok := lookup.(errLookuper); ok && el.Err() != nil {
		return cfg, fmt.Errorf("invalid configuration: %w", el.Err())
	}

	err = cfg.Cache.Validate()
	if err != nil {
		return cfg, fmt.Errorf("invalid cache configuration: %w", err)
	}

	err = cfg.Observe.Validate()
	if err != nil {
		return cfg, fmt.Errorf("invalid observe configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks that the cache configuration is valid.
func (c *CacheConfig) Validate() error {
	if c.Encryption.Enabled {
		if err := c.validateEncryption(); err != nil {
			return err
		}
	}

	if c.Type == "valkey" {
		if c.Valkey.Address == "" {
			return fmt.Errorf("VALKEY_ADDRESS required when CACHE_TYPE=valkey")
		}
		if c.Valkey.IAMEnabled {
			if err := c.Valkey.validateIAM(); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateEncryption checks encryption-specific field constraints. Called only
// when Encryption.Enabled is true.
func (c *CacheConfig) validateEncryption() error {
	if c.Type != "valkey" {
		return fmt.Errorf("cache encryption requires CACHE_TYPE=valkey")
	}

	hasAWS := c.Encryption.KeysetURI != "" || c.Encryption.KMSEnvelopeKeyURI != ""
	hasFile := c.Encryption.KeysetFile != ""

	if hasFile && hasAWS {
		return fmt.Errorf("CACHE_ENCRYPTION_KEYSET_FILE is mutually exclusive with CACHE_ENCRYPTION_KEYSET_URI/CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI")
	}

	if !hasFile && !hasAWS {
		return fmt.Errorf("encryption enabled but no keyset source configured: set CACHE_ENCRYPTION_KEYSET_FILE or CACHE_ENCRYPTION_KEYSET_URI with CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI")
	}

	if hasAWS {
		if c.Encryption.KeysetURI == "" {
			return fmt.Errorf("CACHE_ENCRYPTION_KEYSET_URI required when CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI is set")
		}
		if c.Encryption.KMSEnvelopeKeyURI == "" {
			return fmt.Errorf("CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI required when CACHE_ENCRYPTION_KEYSET_URI is set")
		}
	}

	return nil
}

// Validate checks that the observe configuration is valid.
func (c *ObserveConfig) Validate() error {
	if c.PyroscopeEnabled && c.PyroscopeServerAddress == "" {
		return fmt.Errorf("OBSERVE_PYROSCOPE_SERVER_ADDRESS required when OBSERVE_PYROSCOPE_ENABLED=true")
	}
	return nil
}

// validateIAM checks IAM-specific field constraints and forces TLS on.
// Called only when IAMEnabled is true.
func (v *ValkeyConfig) validateIAM() error {
	if v.Username == "" {
		return fmt.Errorf("VALKEY_USERNAME required as IAM user ID when VALKEY_IAM_ENABLED=true")
	}
	if v.IAMCacheName == "" {
		return fmt.Errorf("VALKEY_IAM_CACHE_NAME required when VALKEY_IAM_ENABLED=true")
	}
	if v.Password != "" {
		return fmt.Errorf("VALKEY_PASSWORD must be empty when IAM authentication is enabled")
	}
	// IAM auth requires in-transit encryption; force it on rather than
	// treating a mismatch as a configuration error.
	v.TLS = true
	return nil
}

// fileContentLookuper decorates a [envconfig.Lookuper] with the "_FILE"
// convention for a fixed allowlist of keys: for each allowed key K, if K
// itself is unset, K_FILE is checked; when present, its value is treated as
// a path and the file's contents (trimmed of surrounding whitespace) are
// used as K's value. This lets specific secret-bearing fields — currently
// GITHUB_APP_PRIVATE_KEY and JWT_JWKS_STATIC — be supplied via a mounted
// secret file instead of an inline environment variable. Keys outside the
// allowlist pass straight through to the wrapped lookuper.
//
// Setting both K and K_FILE is rejected, since the intended source is
// ambiguous. Lookup cannot itself return an error, so failures (a bad path,
// or both variants set) are accumulated and surfaced via Err, which the
// caller must check after processing completes.
type fileContentLookuper struct {
	next    envconfig.Lookuper
	allowed map[string]struct{}
	err     error
}

func newFileContentLookuper(next envconfig.Lookuper, allowedKeys ...string) *fileContentLookuper {
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}

	return &fileContentLookuper{next: next, allowed: allowed}
}

// Err returns the accumulated errors from all Lookup calls, joined via
// [errors.Join], if any.
func (f *fileContentLookuper) Err() error {
	return f.err
}

func (f *fileContentLookuper) Lookup(key string) (string, bool) {
	value, valueSet := f.next.Lookup(key)

	if _, ok := f.allowed[key]; !ok {
		return value, valueSet
	}

	path, pathSet := f.next.Lookup(key + "_FILE")
	if !pathSet || path == "" {
		return value, valueSet
	}

	if valueSet {
		f.err = errors.Join(f.err, fmt.Errorf("%s and %s_FILE are mutually exclusive", key, key))
		return value, valueSet
	}

	//nolint:gosec // G304: path is an operator-supplied config value (an
	// allowlisted "<KEY>_FILE" environment variable), not user input.
	content, err := os.ReadFile(path)
	if err != nil {
		f.err = errors.Join(f.err, fmt.Errorf("read %s_FILE: %w", key, err))
		return "", false
	}

	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		f.err = errors.Join(f.err, fmt.Errorf("%s_FILE at %q is empty", key, path))
		return "", false
	}

	return trimmed, true
}
