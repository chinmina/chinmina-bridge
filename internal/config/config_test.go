package config

import (
	"context"
	"testing"

	"github.com/sethvargo/go-envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requiredConfig returns a map with all required configuration values
var requiredConfig = map[string]string{
	"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
	"BUILDKITE_API_TOKEN":             "test-token",
	"GITHUB_APP_ID":                   "123",
	"GITHUB_APP_INSTALLATION_ID":      "456",
	"GITHUB_APP_PRIVATE_KEY":          "test-key",
}

func TestCacheConfig_Defaults(t *testing.T) {
	lookuper := envconfig.MapLookuper(requiredConfig)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)
	assert.Equal(t, "memory", cfg.Cache.Type)
}

func TestValkeyConfig(t *testing.T) {
	configMap := map[string]string{
		"CACHE_TYPE":      "valkey",
		"VALKEY_ADDRESS":  "localhost:6379",
		"VALKEY_USERNAME": "testuser",
		"VALKEY_PASSWORD": "testpass",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)

	assert.Equal(t, "valkey", cfg.Cache.Type)
	expected := ValkeyConfig{
		Address:  "localhost:6379",
		Username: "testuser",
		Password: "testpass",
		TLS:      true, // default
	}
	assert.Equal(t, expected, cfg.Cache.Valkey)
}

func TestValkeyConfig_TLSTrue(t *testing.T) {
	configMap := map[string]string{
		"VALKEY_ADDRESS": "localhost:6379",
		"VALKEY_TLS":     "true",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)

	expected := ValkeyConfig{
		Address: "localhost:6379",
		TLS:     true,
	}
	assert.Equal(t, expected, cfg.Cache.Valkey)
}

func TestValkeyConfig_TLSFalse(t *testing.T) {
	configMap := map[string]string{
		"VALKEY_ADDRESS": "localhost:6379",
		"VALKEY_TLS":     "false",
	}
	lookuper := envconfig.MultiLookuper(
		envconfig.MapLookuper(requiredConfig),
		envconfig.MapLookuper(configMap),
	)

	cfg, err := load(context.Background(), lookuper)
	assert.NoError(t, err)

	expected := ValkeyConfig{
		Address: "localhost:6379",
		TLS:     false,
	}
	assert.Equal(t, expected, cfg.Cache.Valkey)
}

func TestCacheConfig_Validate_Success(t *testing.T) {
	tests := []struct {
		name   string
		config CacheConfig
	}{
		{
			name: "memory cache",
			config: CacheConfig{
				Type: "memory",
			},
		},
		{
			name: "valkey without encryption",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
			},
		},
		{
			name: "valkey with encryption",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:           true,
					KeysetURI:         "aws-secretsmanager://my-keyset",
					KMSEnvelopeKeyURI: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestCacheConfig_Validate_Failures(t *testing.T) {
	tests := []struct {
		name        string
		config      CacheConfig
		expectedErr string
	}{
		{
			name: "encryption requires valkey",
			config: CacheConfig{
				Type: "memory",
				Encryption: CacheEncryptionConfig{
					Enabled:           true,
					KeysetURI:         "aws-secretsmanager://my-keyset",
					KMSEnvelopeKeyURI: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
			expectedErr: "cache encryption requires CACHE_TYPE=valkey",
		},
		{
			name: "encryption requires keyset URI",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:           true,
					KMSEnvelopeKeyURI: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
			expectedErr: "CACHE_ENCRYPTION_KEYSET_URI required when encryption enabled",
		},
		{
			name: "encryption requires KMS URI",
			config: CacheConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address: "localhost:6379",
				},
				Encryption: CacheEncryptionConfig{
					Enabled:   true,
					KeysetURI: "aws-secretsmanager://my-keyset",
				},
			},
			expectedErr: "CACHE_ENCRYPTION_KMS_ENVELOPE_KEY_URI required when encryption enabled",
		},
		{
			name: "valkey requires address",
			config: CacheConfig{
				Type: "valkey",
			},
			expectedErr: "VALKEY_ADDRESS required when CACHE_TYPE=valkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name        string
		configMap   map[string]string
		expectedErr string
	}{
		{
			name: "missing required env var",
			configMap: map[string]string{
				"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
				// BUILDKITE_API_TOKEN is missing
				"GITHUB_APP_ID":              "123",
				"GITHUB_APP_INSTALLATION_ID": "456",
				"GITHUB_APP_PRIVATE_KEY":     "test-key",
			},
			expectedErr: "BUILDKITE_API_TOKEN",
		},
		{
			name: "invalid cache configuration",
			configMap: map[string]string{
				"JWT_BUILDKITE_ORGANIZATION_SLUG": "test-org",
				"BUILDKITE_API_TOKEN":             "test-token",
				"GITHUB_APP_ID":                   "123",
				"GITHUB_APP_INSTALLATION_ID":      "456",
				"GITHUB_APP_PRIVATE_KEY":          "test-key",
				// Enable valkey without address
				"CACHE_TYPE": "valkey",
			},
			expectedErr: "invalid cache configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookuper := envconfig.MapLookuper(tt.configMap)
			_, err := load(context.Background(), lookuper)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}
