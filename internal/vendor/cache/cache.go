package cache

import (
	"context"

	"github.com/chinmina/chinmina-bridge/internal/vendor"
)

// TokenCache defines the interface for token caching implementations.
type TokenCache interface {
	// Get retrieves a token from the cache.
	// Returns the token, whether it was found, and any error.
	Get(ctx context.Context, key string) (vendor.ProfileToken, bool, error)

	// Set stores a token in the cache.
	Set(ctx context.Context, key string, token vendor.ProfileToken) error

	// Invalidate removes a token from the cache.
	Invalidate(ctx context.Context, key string) error
}

// Digester provides a content digest for cache key namespacing.
// When configuration changes, the digest changes, effectively
// invalidating all cached tokens from the old configuration.
type Digester interface {
	Digest() string
}
