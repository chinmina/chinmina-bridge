package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDistributed_NilStrategy(t *testing.T) {
	cache, err := NewDistributed[CacheTestDummy](nil, 5*time.Minute, nil)
	require.NoError(t, err)
	assert.NotNil(t, cache)
	assert.IsType(t, &NoEncryptionStrategy{}, cache.strategy)
}

func TestNewDistributed_WithStrategy(t *testing.T) {
	strategy := &NoEncryptionStrategy{}

	cache, err := NewDistributed[CacheTestDummy](nil, 5*time.Minute, strategy)
	require.NoError(t, err)
	assert.NotNil(t, cache)
	assert.Same(t, strategy, cache.strategy)
}
