package cache

import (
	"context"
)

// TokenCache defines the interface for token caching implementations.
// The generic type T represents the token type being cached.
type TokenCache[T any] interface {
	// Get retrieves a token from the cache.
	// Returns the token, whether it was found, and any error.
	Get(ctx context.Context, key string) (T, bool, error)

	// Set stores a token in the cache.
	Set(ctx context.Context, key string, token T) error

	// Invalidate removes a token from the cache.
	Invalidate(ctx context.Context, key string) error

	// Close releases any resources held by the cache.
	Close() error
}
