//go:build integration

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valkey-io/valkey-go"
)

func setupValkey(t *testing.T) (valkey.Client, func()) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "valkey/valkey:8-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	endpoint, err := container.Endpoint(ctx, "")
	require.NoError(t, err)

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{endpoint},
	})
	require.NoError(t, err)

	cleanup := func() {
		client.Close()
		_ = container.Terminate(ctx)
	}

	return client, cleanup
}

func TestIntegrationDistributed_SetAndGet(t *testing.T) {
	client, cleanup := setupValkey(t)
	defer cleanup()

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	expected := CacheTestDummy{
		Data: "test-value",
	}

	// Set token
	err = cache.Set(ctx, key, expected)
	require.NoError(t, err)

	// Get token
	result, found, err := cache.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, expected, result)
}

func TestIntegrationDistributed_GetNotFound(t *testing.T) {
	client, cleanup := setupValkey(t)
	defer cleanup()

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()

	result, found, err := cache.Get(ctx, "nonexistent-key")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, CacheTestDummy{}, result)
}

func TestIntegrationDistributed_Invalidate(t *testing.T) {
	client, cleanup := setupValkey(t)
	defer cleanup()

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	dummy := CacheTestDummy{
		Data: "test-value",
	}

	// Set token
	err = cache.Set(ctx, key, dummy)
	require.NoError(t, err)

	// Verify it's there
	_, found, err := cache.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, found)

	// Invalidate
	err = cache.Invalidate(ctx, key)
	require.NoError(t, err)

	// Verify it's gone by polling (as invalidate may be eventually consistent)
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err = cache.Get(ctx, key)
		require.NoError(collect, err)
		assert.False(collect, found)
	}, time.Second*2, time.Millisecond*50, "cache entry should be eventually invalidated")
}

func TestIntegrationDistributed_TTL(t *testing.T) {
	client, cleanup := setupValkey(t)
	defer cleanup()

	// Short TTL for testing
	cache, err := NewDistributed[CacheTestDummy](client, 1*time.Second)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	dummy := CacheTestDummy{
		Data: "test-value",
	}

	// Set token
	err = cache.Set(ctx, key, dummy)
	require.NoError(t, err)

	// Verify it's there immediately
	_, found, err := cache.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, found)

	// Verify it's expired
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err = cache.Get(ctx, key)
		require.NoError(collect, err)
		assert.False(collect, found)
	}, time.Second*2, time.Millisecond*100, "cache entry should expire after TTL")
}

func TestIntegrationDistributed_JSONRoundTrip(t *testing.T) {
	client, cleanup := setupValkey(t)
	defer cleanup()

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()

	testCases := []struct {
		name  string
		dummy CacheTestDummy
	}{
		{
			name:  "simple value",
			dummy: CacheTestDummy{Data: "test"},
		},
		{
			name:  "empty value",
			dummy: CacheTestDummy{Data: ""},
		},
		{
			name:  "special characters",
			dummy: CacheTestDummy{Data: "special: !@#$%^&*(){}[]|\\:\";<>?,./"},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			key := "json-test-" + tt.name

			err := cache.Set(ctx, key, tt.dummy)
			require.NoError(t, err)

			result, found, err := cache.Get(ctx, key)
			require.NoError(t, err)
			assert.True(t, found)
			assert.Equal(t, tt.dummy, result)
		})
	}
}
