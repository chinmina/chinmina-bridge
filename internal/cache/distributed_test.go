//go:build integration

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"
)

func setupValkey(t *testing.T) valkey.Client {
	t.Helper()

	endpoint := testhelpers.RunValkeyContainer(t)

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{endpoint},
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

func TestIntegrationDistributed_SetAndGet(t *testing.T) {
	client := setupValkey(t)

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
	assertEventuallyExists(t, cache, key)
}

func TestIntegrationDistributed_GetNotFound(t *testing.T) {
	client := setupValkey(t)

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
	client := setupValkey(t)

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
	assertEventuallyExists(t, cache, key)

	// Invalidate
	err = cache.Invalidate(ctx, key)
	require.NoError(t, err)

	// Verify it's gone by polling (as invalidate may be eventually consistent)
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err := cache.Get(ctx, key)
		require.NoError(collect, err)
		assert.False(collect, found)
	}, time.Second*2, time.Millisecond*50, "cache entry should be eventually invalidated")
}

func TestIntegrationDistributed_TTL(t *testing.T) {
	client := setupValkey(t)

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
	assertEventuallyExists(t, cache, key)

	// Verify it's expired
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err := cache.Get(ctx, key)
		require.NoError(collect, err)
		assert.False(collect, found)
	}, time.Second*2, time.Millisecond*100, "cache entry should expire after TTL")
}

func TestIntegrationDistributed_JSONRoundTrip(t *testing.T) {
	client := setupValkey(t)

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

			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				result, found, err := cache.Get(ctx, key)
				require.NoError(collect, err)
				assert.True(collect, found)
				assert.Equal(collect, tt.dummy, result)
			}, time.Second*2, time.Millisecond*100, "cache entry should be eventually available")
		})
	}
}

func assertEventuallyExists(t *testing.T, cache TokenCache[CacheTestDummy], key string) {
	t.Helper()

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err := cache.Get(context.Background(), key)
		require.NoError(collect, err)
		assert.True(collect, found)
	}, time.Second*2, time.Millisecond*100, "cache entry should be eventually available")
}
