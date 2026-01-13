package cache

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testToken struct {
	Value string
}

func TestNewFromConfig_Memory(t *testing.T) {
	ctx := context.Background()
	cacheConfig := config.CacheConfig{Type: "memory"}
	valkeyConfig := config.ValkeyConfig{}

	cache, cleanup, err := NewFromConfig[testToken](
		ctx,
		cacheConfig,
		valkeyConfig,
		1*time.Minute,
		100,
	)

	require.NoError(t, err)
	assert.NotNil(t, cache)
	assert.NotNil(t, cleanup)

	// Verify cleanup is a no-op
	err = cleanup()
	assert.NoError(t, err)
}

func TestNewFromConfig_InvalidType(t *testing.T) {
	ctx := context.Background()
	cacheConfig := config.CacheConfig{Type: "redis"}
	valkeyConfig := config.ValkeyConfig{}

	cache, cleanup, err := NewFromConfig[testToken](
		ctx,
		cacheConfig,
		valkeyConfig,
		1*time.Minute,
		100,
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cache type")
	assert.Contains(t, err.Error(), "redis")
	assert.Nil(t, cache)
	assert.Nil(t, cleanup)
}

func TestNewFromConfig_ValkeyRequiresAddress(t *testing.T) {
	ctx := context.Background()
	cacheConfig := config.CacheConfig{Type: "valkey"}
	valkeyConfig := config.ValkeyConfig{
		Address: "", // Missing address
		TLS:     true,
	}

	cache, cleanup, err := NewFromConfig[testToken](
		ctx,
		cacheConfig,
		valkeyConfig,
		1*time.Minute,
		100,
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "valkey address is required")
	assert.Nil(t, cache)
	assert.Nil(t, cleanup)
}
