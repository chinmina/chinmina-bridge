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
