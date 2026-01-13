package cache

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryGet_NotFound(t *testing.T) {
	ctx := context.Background()
	cache, err := NewMemory(time.Minute, 100)
	require.NoError(t, err)

	token, found, err := cache.Get(ctx, "nonexistent")

	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, vendor.ProfileToken{}, token)
}

func TestMemorySetAndGet_Success(t *testing.T) {
	ctx := context.Background()
	cache, err := NewMemory(time.Minute, 100)
	require.NoError(t, err)

	expectedToken := vendor.ProfileToken{
		OrganizationSlug:    "acme",
		Profile:             "default",
		VendedRepositoryURL: "https://github.com/acme/repo",
		Repositories:        []string{"acme/repo"},
		Permissions:         []string{"contents:read"},
		Token:               "ghs_test123",
		Expiry:              time.Now().Add(time.Hour),
	}

	err = cache.Set(ctx, "test-key", expectedToken)
	require.NoError(t, err)

	token, found, err := cache.Get(ctx, "test-key")

	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, expectedToken, token)
}

func TestMemoryInvalidate_RemovesToken(t *testing.T) {
	ctx := context.Background()
	cache, err := NewMemory(time.Minute, 100)
	require.NoError(t, err)

	token := vendor.ProfileToken{
		OrganizationSlug: "acme",
		Token:            "ghs_test123",
		Expiry:           time.Now().Add(time.Hour),
	}

	err = cache.Set(ctx, "test-key", token)
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
	cache, err := NewMemory(100*time.Millisecond, 100)
	require.NoError(t, err)

	token := vendor.ProfileToken{
		OrganizationSlug: "acme",
		Token:            "ghs_test123",
		Expiry:           time.Now().Add(time.Hour),
	}

	err = cache.Set(ctx, "test-key", token)
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
