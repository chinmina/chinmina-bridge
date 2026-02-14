package cache

import (
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/cache/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDistributed_NilAEAD(t *testing.T) {
	cache, err := NewDistributed[CacheTestDummy](nil, 5*time.Minute, nil)
	require.NoError(t, err)
	assert.NotNil(t, cache)
	assert.Nil(t, cache.aead)
}

func TestNewDistributed_WithAEAD(t *testing.T) {
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	cache, err := NewDistributed[CacheTestDummy](nil, 5*time.Minute, testAEAD)
	require.NoError(t, err)
	assert.NotNil(t, cache)
	assert.NotNil(t, cache.aead)
}

func TestDistributedStorageKey(t *testing.T) {
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{name: "simple key", key: "test-key", expected: "enc:test-key"},
		{name: "key with colons", key: "digest:profile://org/repo", expected: "enc:digest:profile://org/repo"},
		{name: "empty key", key: "", expected: "enc:"},
	}

	cache, err := NewDistributed[CacheTestDummy](nil, 5*time.Minute, testAEAD)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, cache.storageKey(tt.key))
		})
	}
}

func TestDistributedStorageKey_NilAEAD(t *testing.T) {
	cache, err := NewDistributed[CacheTestDummy](nil, 5*time.Minute, nil)
	require.NoError(t, err)

	tests := []struct {
		name string
		key  string
	}{
		{name: "simple key", key: "test-key"},
		{name: "key with colons", key: "digest:profile://org/repo"},
		{name: "empty key", key: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.key, cache.storageKey(tt.key))
		})
	}
}
