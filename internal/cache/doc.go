// Package cache provides generic token storage backed by memory or Valkey.
// TokenCache is the storage boundary; the vendor package owns cache keys,
// authorization, and decisions about which vending results may be reused.
//
// NewFromConfig selects and instruments a backend. Valkey supports static or
// IAM authentication and optional authenticated encryption; keyset loading and
// refresh live in the encryption subpackage. Close releases connections and
// any encryption refresh resources owned by the cache.
//
// Integration tests exercise real Valkey containers through testcontainers;
// unit tests cover the storage, instrumentation, and encryption boundaries
// without requiring a running service stack.
package cache
