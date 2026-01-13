package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCacheConfig_Defaults(t *testing.T) {
	t.Setenv("JWT_BUILDKITE_ORGANIZATION_SLUG", "test-org")
	t.Setenv("BUILDKITE_API_TOKEN", "test-token")
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "456")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "test-key")

	cfg, err := Load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "memory", cfg.Cache.Type)
}

func TestCacheConfig_Valkey(t *testing.T) {
	t.Setenv("JWT_BUILDKITE_ORGANIZATION_SLUG", "test-org")
	t.Setenv("BUILDKITE_API_TOKEN", "test-token")
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "456")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "test-key")
	t.Setenv("CACHE_TYPE", "valkey")

	cfg, err := Load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "valkey", cfg.Cache.Type)
}

func TestValkeyConfig(t *testing.T) {
	t.Setenv("JWT_BUILDKITE_ORGANIZATION_SLUG", "test-org")
	t.Setenv("BUILDKITE_API_TOKEN", "test-token")
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "456")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "test-key")
	t.Setenv("VALKEY_ADDRESS", "localhost:6379")
	t.Setenv("VALKEY_USE_IAM_AUTH", "true")

	cfg, err := Load(context.Background())
	assert.NoError(t, err)

	expected := ValkeyConfig{
		Address:    "localhost:6379",
		UseIAMAuth: true,
		TLS:        true, // default
	}
	assert.Equal(t, expected, cfg.Valkey)
}

func TestValkeyConfig_TLSFalse(t *testing.T) {
	t.Setenv("JWT_BUILDKITE_ORGANIZATION_SLUG", "test-org")
	t.Setenv("BUILDKITE_API_TOKEN", "test-token")
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "456")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "test-key")
	t.Setenv("VALKEY_ADDRESS", "localhost:6379")
	t.Setenv("VALKEY_TLS", "false")

	cfg, err := Load(context.Background())
	assert.NoError(t, err)

	expected := ValkeyConfig{
		Address:    "localhost:6379",
		UseIAMAuth: false,
		TLS:        false,
	}
	assert.Equal(t, expected, cfg.Valkey)
}
