package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryGet_NotFound(t *testing.T) {
	ctx := context.Background()
	cache, err := NewMemory[CacheTestDummy](time.Minute, 100)
	require.NoError(t, err)

	token, found, err := cache.Get(ctx, "nonexistent")

	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, CacheTestDummy{}, token)
}

func TestMemorySetAndGet_Success(t *testing.T) {
	ctx := context.Background()
	cache, err := NewMemory[CacheTestDummy](time.Minute, 100)
	require.NoError(t, err)

	expectedToken := CacheTestDummy{Data: "testdata"}

	err = cache.Set(ctx, "test-key", expectedToken)
	require.NoError(t, err)

	token, found, err := cache.Get(ctx, "test-key")

	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, expectedToken, token)
}

func TestMemoryInvalidate_RemovesToken(t *testing.T) {
	ctx := context.Background()
	cache, err := NewMemory[CacheTestDummy](time.Minute, 100)
	require.NoError(t, err)

	dummy := CacheTestDummy{Data: "testdata"}

	err = cache.Set(ctx, "test-key", dummy)
	require.NoError(t, err)

	err = cache.Invalidate(ctx, "test-key")
	require.NoError(t, err)

	_, found, err := cache.Get(ctx, "test-key")
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestMemoryTTLExpiry(t *testing.T) {
	ctx := context.Background()
	// Use very short TTL for testing
	cache, err := NewMemory[CacheTestDummy](100*time.Millisecond, 100)
	require.NoError(t, err)

	dummy := CacheTestDummy{Data: "testdata"}

	err = cache.Set(ctx, "test-key", dummy)
	require.NoError(t, err)

	// Verify token is present immediately
	_, found, err := cache.Get(ctx, "test-key")
	assert.NoError(t, err)
	assert.True(t, found)

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Verify token is no longer present
	_, found, err = cache.Get(ctx, "test-key")
	assert.NoError(t, err)
	assert.False(t, found)
}

// CacheTestDummy is a simple struct used for testing the generic memory cache.
// It is used instead of ProfileToken to avoid a cyclic dependency in tests.
type CacheTestDummy struct {
	Data string
}
