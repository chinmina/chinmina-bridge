//go:build integration

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationNewFromConfig_Valkey(t *testing.T) {
	ctx := context.Background()

	// Start Valkey container
	address := testhelpers.RunValkeyContainer(t)

	cacheConfig := config.CacheConfig{Type: "valkey"}
	valkeyConfig := config.ValkeyConfig{
		Address: address,
		TLS:     false,
	}

	cache, cleanup, err := NewFromConfig[testToken](
		ctx,
		cacheConfig,
		valkeyConfig,
		1*time.Minute,
		100,
	)

	require.NoError(t, err)
	require.NotNil(t, cache)
	require.NotNil(t, cleanup)

	// Verify cache works
	key := "test-key"
	value := testToken{Value: "test-value"}

	err = cache.Set(ctx, key, value)
	require.NoError(t, err)

	retrieved, found, err := cache.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, value, retrieved)

	// Cleanup
	err = cleanup()
	assert.NoError(t, err)
}

func TestIntegrationNewFromConfig_ValkeyWithTLS(t *testing.T) {
	ctx := context.Background()

	// Start Valkey container (without TLS for simplicity in tests)
	address := testhelpers.RunValkeyContainer(t)

	cacheConfig := config.CacheConfig{Type: "valkey"}
	valkeyConfig := config.ValkeyConfig{
		Address: address,
		TLS:     true, // Enable TLS config (though container doesn't use it)
	}

	_, _, err := NewFromConfig[testToken](
		ctx,
		cacheConfig,
		valkeyConfig,
		1*time.Minute,
		100,
	)

	// This will fail because the container doesn't have TLS enabled,
	// but it proves the TLS configuration code path is exercised
	require.Error(t, err)
}
