# Cache Encryption Implementation Plan

This document outlines the implementation plan for adding encrypted token caching to chinmina-bridge using Google Tink and AWS KMS.

## Overview

The goal is to encrypt cached GitHub tokens at rest in the distributed cache (Valkey) using envelope encryption. This addresses:
- Unauthorized access during cache compromise
- Insider threats from cache administrators
- Compliance requirements for credential storage

## Current Architecture

The caching system consists of:
- **`TokenCache[T]` interface** (`internal/cache/cache.go`) - generic cache abstraction
- **`Distributed[T]`** (`internal/cache/distributed.go`) - Valkey-backed implementation with JSON serialization
- **`Memory[T]`** (`internal/cache/memory.go`) - In-process cache using otter library
- **`Instrumented[T]`** (`internal/cache/instrumented.go`) - Metrics wrapper
- **`NewFromConfig`** (`internal/cache/factory.go`) - Factory function selecting implementation

Token flow:
1. `main.go` calls `cache.NewFromConfig[vendor.ProfileToken]()`
2. Factory creates `Distributed` or `Memory` cache, wraps with `Instrumented`
3. `vendor.Cached()` wraps the cache for token vending logic
4. Cache keys are `{digest}:{profileRef.String()}` format

## Proposed Architecture

### Encryption Approach

**Envelope Encryption with Tink + AWS KMS:**
1. AWS KMS manages the Key Encryption Key (KEK)
2. Tink keyset contains the Data Encryption Key (DEK), encrypted by the KEK
3. Keyset stored in AWS Secrets Manager (encrypted by KMS)
4. At startup, keyset is loaded and decrypted via KMS
5. All cache operations use AES-256-GCM via Tink AEAD primitive

### Data Flow

```
Token → JSON Marshal → Encrypt(AEAD, plaintext, AAD) → Base64 Encode → Store in Valkey
Retrieve from Valkey → Base64 Decode → Decrypt(AEAD, ciphertext, AAD) → JSON Unmarshal → Token
```

**Additional Authenticated Data (AAD):** Cache key is bound to ciphertext, preventing ciphertext swapping attacks between cache entries.

## Implementation Phases

### Phase 1: Core Encryption Layer

#### 1.1 New Package: `internal/encryption`

Create a new package for Tink AEAD wrapper. This keeps encryption concerns isolated and testable.

**File: `internal/encryption/aead.go`**

```go
package encryption

import (
    "bytes"
    "context"
    "fmt"
    "strings"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
    "github.com/tink-crypto/tink-go-awskms/v2/integration/awskms"
    "github.com/tink-crypto/tink-go/v2/aead"
    "github.com/tink-crypto/tink-go/v2/keyset"
    "github.com/tink-crypto/tink-go/v2/tink"
)

// AEAD provides authenticated encryption with associated data.
// This interface abstracts Tink's AEAD primitive for easier testing.
type AEAD interface {
    Encrypt(plaintext, associatedData []byte) ([]byte, error)
    Decrypt(ciphertext, associatedData []byte) ([]byte, error)
}

// tinkAEAD wraps a Tink AEAD primitive.
type tinkAEAD struct {
    primitive tink.AEAD
}

func (t *tinkAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
    return t.primitive.Encrypt(plaintext, associatedData)
}

func (t *tinkAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
    return t.primitive.Decrypt(ciphertext, associatedData)
}

// Validate performs a test encryption/decryption cycle to verify the AEAD is working.
// Call this at startup to fail fast if encryption is misconfigured.
func (t *tinkAEAD) Validate() error {
    testPlaintext := []byte("chinmina-bridge-encryption-test")
    testAAD := []byte("validation")

    ciphertext, err := t.Encrypt(testPlaintext, testAAD)
    if err != nil {
        return fmt.Errorf("validation encrypt failed: %w", err)
    }

    decrypted, err := t.Decrypt(ciphertext, testAAD)
    if err != nil {
        return fmt.Errorf("validation decrypt failed: %w", err)
    }

    if !bytes.Equal(testPlaintext, decrypted) {
        return fmt.Errorf("validation round-trip failed: plaintext mismatch")
    }

    return nil
}

// NewAEADFromKMS creates an AEAD primitive from a keyset stored in
// AWS Secrets Manager, encrypted with an AWS KMS key.
//
// keysetURI format: aws-secretsmanager://secret-name
// kmsKeyURI format: aws-kms://arn:aws:kms:region:account:key/key-id
func NewAEADFromKMS(ctx context.Context, keysetURI, kmsKeyURI string) (AEAD, error) {
    // Create AWS KMS client for Tink
    awsClient, err := awskms.NewClientWithOptions(kmsKeyURI)
    if err != nil {
        return nil, fmt.Errorf("creating AWS KMS client: %w", err)
    }

    // Get the KMS AEAD for envelope decryption of the keyset
    kmsAEAD, err := awsClient.GetAEAD(kmsKeyURI)
    if err != nil {
        return nil, fmt.Errorf("getting KMS AEAD: %w", err)
    }

    // Read encrypted keyset from Secrets Manager
    keysetReader, err := readKeysetFromSecretsManager(ctx, keysetURI)
    if err != nil {
        return nil, fmt.Errorf("reading keyset: %w", err)
    }

    // Decrypt keyset using KMS
    handle, err := keyset.Read(keysetReader, kmsAEAD)
    if err != nil {
        return nil, fmt.Errorf("decrypting keyset: %w", err)
    }

    // Get AEAD primitive from keyset
    primitive, err := aead.New(handle)
    if err != nil {
        return nil, fmt.Errorf("creating AEAD primitive: %w", err)
    }

    result := &tinkAEAD{primitive: primitive}

    // Validate the AEAD works before returning
    if err := result.Validate(); err != nil {
        return nil, fmt.Errorf("validating AEAD: %w", err)
    }

    return result, nil
}

// readKeysetFromSecretsManager reads a Tink keyset from AWS Secrets Manager.
// URI format: aws-secretsmanager://secret-name
func readKeysetFromSecretsManager(ctx context.Context, uri string) (keyset.Reader, error) {
    const prefix = "aws-secretsmanager://"
    if !strings.HasPrefix(uri, prefix) {
        return nil, fmt.Errorf("invalid secrets manager URI %q: must start with %s", uri, prefix)
    }
    secretName := strings.TrimPrefix(uri, prefix)

    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, fmt.Errorf("loading AWS config: %w", err)
    }

    client := secretsmanager.NewFromConfig(cfg)

    result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
        SecretId: &secretName,
    })
    if err != nil {
        return nil, fmt.Errorf("getting secret %q: %w", secretName, err)
    }

    if result.SecretString == nil {
        return nil, fmt.Errorf("secret %q has no string value", secretName)
    }

    return keyset.NewJSONReader(strings.NewReader(*result.SecretString)), nil
}
```

#### 1.2 Configuration Changes

**File: `internal/config/config.go`**

Nest encryption configuration inside `CacheConfig` since encryption is cache-specific:

```go
// CacheConfig specifies which cache backend to use.
type CacheConfig struct {
    // Type selects the cache implementation: "memory" (default) or "valkey"
    Type string `env:"CACHE_TYPE, default=memory"`

    // Encryption holds settings for cache encryption.
    // Only supported with valkey cache type.
    Encryption CacheEncryptionConfig
}

// CacheEncryptionConfig holds settings for cache encryption.
type CacheEncryptionConfig struct {
    // Enabled turns on encryption for cached tokens.
    // Requires CACHE_TYPE=valkey.
    Enabled bool `env:"CACHE_ENCRYPTION_ENABLED, default=false"`

    // KeysetURI is the URI to the encrypted Tink keyset.
    // Format: aws-secretsmanager://secret-name
    KeysetURI string `env:"CACHE_ENCRYPTION_KEYSET_URI"`

    // KMSKeyURI is the AWS KMS key URI for envelope encryption.
    // Format: aws-kms://arn:aws:kms:region:account:key/key-id
    KMSKeyURI string `env:"CACHE_ENCRYPTION_KMS_KEY_URI"`
}
```

Add validation method to `CacheConfig`:

```go
func (c *CacheConfig) Validate() error {
    // Encryption requires distributed cache
    if c.Encryption.Enabled && c.Type != "valkey" {
        return fmt.Errorf("cache encryption requires CACHE_TYPE=valkey")
    }

    // Encryption requires keyset and KMS URIs
    if c.Encryption.Enabled {
        if c.Encryption.KeysetURI == "" {
            return fmt.Errorf("CACHE_ENCRYPTION_KEYSET_URI required when encryption enabled")
        }
        if c.Encryption.KMSKeyURI == "" {
            return fmt.Errorf("CACHE_ENCRYPTION_KMS_KEY_URI required when encryption enabled")
        }
    }

    return nil
}
```

Call validation in `main.go` after loading config:

```go
if err := cfg.Cache.Validate(); err != nil {
    log.Fatal().Err(err).Msg("invalid cache configuration")
}
```

### Phase 2: Distributed Cache Encryption

Encryption is only supported for the distributed (Valkey) cache. The in-memory cache
does not support encryption as it operates within the same process boundary.

#### 2.1 Modify `internal/cache/distributed.go`

Add optional AEAD to the Distributed cache. Changes from current implementation:
- Add `aead` field
- Add `storageKey()` method for `enc:` prefix
- Encrypt in Set, decrypt in Get
- Handle decryption failures gracefully (invalidate, warn, treat as miss)

```go
package cache

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "time"

    "github.com/chinmina/chinmina-bridge/internal/encryption"
    "github.com/rs/zerolog/log"
    "github.com/valkey-io/valkey-go"
)

// Distributed implements TokenCache using Valkey with server-assisted
// client-side caching.
type Distributed[T any] struct {
    client valkey.Client
    ttl    time.Duration
    aead   encryption.AEAD // nil means no encryption
}

// NewDistributed creates a new Valkey-backed cache with optional encryption.
func NewDistributed[T any](client valkey.Client, ttl time.Duration, aead encryption.AEAD) (*Distributed[T], error) {
    return &Distributed[T]{
        client: client,
        ttl:    ttl,
        aead:   aead,
    }, nil
}

// Get retrieves a token from the cache using server-assisted client-side caching.
func (d *Distributed[T]) Get(ctx context.Context, key string) (T, bool, error) {
    var zero T

    storageKey := d.storageKey(key)
    cmd := d.client.B().Get().Key(storageKey).Cache()
    result := d.client.DoCache(ctx, cmd, d.ttl)

    if err := result.Error(); err != nil {
        if valkey.IsValkeyNil(err) {
            return zero, false, nil
        }
        return zero, false, fmt.Errorf("failed to get cached value: %w", err)
    }

    val, err := result.ToString()
    if err != nil {
        return zero, false, fmt.Errorf("failed to convert cached value to string: %w", err)
    }

    // Decrypt if encryption is enabled
    data := []byte(val)
    if d.aead != nil {
        decoded, err := base64.StdEncoding.DecodeString(val)
        if err != nil {
            // Decryption failure: invalidate, warn, treat as cache miss
            d.handleDecryptionFailure(ctx, key, storageKey, "base64 decode failed", err)
            return zero, false, nil
        }
        data, err = d.aead.Decrypt(decoded, []byte(key))
        if err != nil {
            // Decryption failure: invalidate, warn, treat as cache miss
            d.handleDecryptionFailure(ctx, key, storageKey, "decryption failed", err)
            return zero, false, nil
        }
    }

    var token T
    if err := json.Unmarshal(data, &token); err != nil {
        return zero, false, fmt.Errorf("failed to unmarshal cached token: %w", err)
    }

    return token, true, nil
}

// handleDecryptionFailure invalidates the corrupted entry and logs a warning.
// The caller should treat this as a cache miss.
func (d *Distributed[T]) handleDecryptionFailure(ctx context.Context, key, storageKey, reason string, err error) {
    log.Warn().
        Err(err).
        Str("key", key).
        Str("reason", reason).
        Msg("cache decryption failure, invalidating entry")

    // Best-effort invalidation
    _ = d.client.Do(ctx, d.client.B().Del().Key(storageKey).Build()).Error()
}

// Set stores a token in the cache with the configured TTL.
func (d *Distributed[T]) Set(ctx context.Context, key string, token T) error {
    data, err := json.Marshal(token)
    if err != nil {
        return fmt.Errorf("failed to marshal token: %w", err)
    }

    // Encrypt if encryption is enabled
    if d.aead != nil {
        ciphertext, err := d.aead.Encrypt(data, []byte(key))
        if err != nil {
            return fmt.Errorf("failed to encrypt token: %w", err)
        }
        data = []byte(base64.StdEncoding.EncodeToString(ciphertext))
    }

    storageKey := d.storageKey(key)
    cmd := d.client.B().Set().Key(storageKey).Value(string(data)).ExSeconds(int64(d.ttl.Seconds())).Build()
    if err := d.client.Do(ctx, cmd).Error(); err != nil {
        return fmt.Errorf("failed to set cached value: %w", err)
    }
    return nil
}

// Invalidate removes a token from the cache.
func (d *Distributed[T]) Invalidate(ctx context.Context, key string) error {
    storageKey := d.storageKey(key)
    cmd := d.client.B().Del().Key(storageKey).Build()
    if err := d.client.Do(ctx, cmd).Error(); err != nil {
        return fmt.Errorf("failed to invalidate cached value: %w", err)
    }
    return nil
}

// storageKey returns the key with appropriate prefix.
// Encrypted entries use "enc:" prefix for namespace separation.
func (d *Distributed[T]) storageKey(key string) string {
    if d.aead != nil {
        return "enc:" + key
    }
    return key
}

// Close releases resources associated with the cache client.
func (d *Distributed[T]) Close() error {
    d.client.Close()
    return nil
}
```

**Key design decisions:**
1. Decryption failures are treated as cache misses (graceful degradation)
2. Corrupted entries are invalidated to prevent repeated failures
3. Warnings logged for visibility without failing the request
4. `enc:` key prefix enables safe rollout alongside plaintext entries

### Phase 3: Factory and Initialization Updates

#### 3.1 Update Cache Factory

**File: `internal/cache/factory.go`**

The factory initializes AEAD if encryption is enabled (valkey only), then passes it to the distributed cache.

```go
package cache

import (
    "context"
    "fmt"
    "time"

    "github.com/chinmina/chinmina-bridge/internal/config"
    "github.com/chinmina/chinmina-bridge/internal/encryption"
    "github.com/rs/zerolog/log"
)

// NewFromConfig creates a TokenCache based on configuration.
// Encryption is only supported for valkey cache type.
func NewFromConfig[T any](
    ctx context.Context,
    cacheConfig config.CacheConfig,
    valkeyConfig config.ValkeyConfig,
    ttl time.Duration,
    maxMemorySize int,
) (TokenCache[T], error) {
    switch cacheConfig.Type {
    case "valkey":
        // Initialize AEAD if encryption enabled
        var aead encryption.AEAD
        if cacheConfig.Encryption.Enabled {
            var err error
            aead, err = encryption.NewAEADFromKMS(
                ctx,
                cacheConfig.Encryption.KeysetURI,
                cacheConfig.Encryption.KMSKeyURI,
            )
            if err != nil {
                return nil, fmt.Errorf("initializing encryption: %w", err)
            }
        }

        log.Info().
            Str("cache_type", "valkey").
            Str("address", valkeyConfig.Address).
            Bool("tls", valkeyConfig.TLS).
            Bool("encryption", aead != nil).
            Msg("initializing distributed cache")

        if valkeyConfig.Address == "" {
            return nil, fmt.Errorf("valkey address required when cache type is valkey")
        }

        client, err := newValkeyClient(ctx, valkeyConfig)
        if err != nil {
            return nil, fmt.Errorf("creating valkey client: %w", err)
        }

        cache, err := NewDistributed[T](client, ttl, aead)
        if err != nil {
            return nil, fmt.Errorf("creating distributed cache: %w", err)
        }

        return NewInstrumented[T](cache, "distributed"), nil

    case "memory", "":
        log.Info().
            Str("cache_type", "memory").
            Msg("initializing in-memory cache")

        cache, err := NewMemory[T](ttl, maxMemorySize)
        if err != nil {
            return nil, fmt.Errorf("creating memory cache: %w", err)
        }

        return NewInstrumented[T](cache, "memory"), nil

    default:
        return nil, fmt.Errorf("invalid cache type %q: must be \"memory\" or \"valkey\"", cacheConfig.Type)
    }
}
```

#### 3.2 Update main.go Initialization

**File: `main.go`**

Add config validation before cache creation. The cache initialization call is unchanged:

```go
// Validate cache configuration (includes encryption validation)
if err := cfg.Cache.Validate(); err != nil {
    log.Fatal().Err(err).Msg("invalid cache configuration")
}

// Create token cache - encryption handled internally based on cfg.Cache.Encryption
tokenCache, err := cache.NewFromConfig[vendor.ProfileToken](
    ctx,
    cfg.Cache,
    cfg.Valkey,
    45*time.Minute,
    10_000,
)
if err != nil {
    log.Fatal().Err(err).Msg("creating token cache")
}
defer tokenCache.Close()
```

The factory logs encryption status internally, so no additional logging needed in main.go.

### Phase 4: Observability

#### 4.1 Encryption Metrics

Add decryption failure metric to `internal/cache/instrumented.go` using existing OTEL pattern:

```go
var (
    metricsOnce          sync.Once
    cacheOperations      metric.Int64Counter
    cacheDuration        metric.Float64Histogram
    decryptionFailures   metric.Int64Counter  // NEW
)

func initMetrics() {
    metricsOnce.Do(func() {
        meter := otel.Meter("github.com/chinmina/chinmina-bridge/internal/cache")

        // ... existing metrics ...

        decryptionFailures, err = meter.Int64Counter(
            "cache.decryption.failures",
            metric.WithDescription("Cache decryption failures (corrupted or invalid entries)"),
        )
        if err != nil {
            otel.Handle(err)
        }
    })
}
```

The decryption failure metric is recorded from `Distributed.handleDecryptionFailure()`:

```go
// In distributed.go, update handleDecryptionFailure to record metric
func (d *Distributed[T]) handleDecryptionFailure(ctx context.Context, key, storageKey, reason string, err error) {
    log.Warn().
        Err(err).
        Str("key", key).
        Str("reason", reason).
        Msg("cache decryption failure, invalidating entry")

    // Record metric
    if decryptionFailures != nil {
        decryptionFailures.Add(ctx, 1,
            metric.WithAttributes(
                attribute.String("cache.failure.reason", reason),
            ),
        )
    }

    // Best-effort invalidation
    _ = d.client.Do(ctx, d.client.B().Del().Key(storageKey).Build()).Error()
}
```

#### 4.2 Startup Validation

Startup validation is handled by `tinkAEAD.Validate()` (shown in Phase 1), which is called
automatically by `NewAEADFromKMS()`. This ensures fail-fast behavior if encryption is misconfigured.

### Phase 5: Testing Strategy

#### 5.1 Unit Tests

**File: `internal/encryption/aead.go`** - Add test helper function:

```go
// NewTestAEAD creates an AEAD for testing without KMS.
// Only use in tests - keys are not persisted or protected.
func NewTestAEAD() (AEAD, error) {
    handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
    if err != nil {
        return nil, err
    }
    primitive, err := aead.New(handle)
    if err != nil {
        return nil, err
    }
    return &tinkAEAD{primitive: primitive}, nil
}
```

**File: `internal/encryption/aead_test.go`**

```go
package encryption_test

import (
    "testing"

    "github.com/chinmina/chinmina-bridge/internal/encryption"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestAEADEncryptDecrypt(t *testing.T) {
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    tests := []struct {
        name      string
        plaintext []byte
        aad       []byte
    }{
        {
            name:      "simple token",
            plaintext: []byte(`{"token":"ghp_xxx","expiry":"2024-01-01T00:00:00Z"}`),
            aad:       []byte("digest:profile://organization/test/profile/default"),
        },
        {
            name:      "empty AAD",
            plaintext: []byte(`{"data":"test"}`),
            aad:       []byte{},
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ciphertext, err := testAEAD.Encrypt(tt.plaintext, tt.aad)
            require.NoError(t, err)
            assert.NotEqual(t, tt.plaintext, ciphertext)

            decrypted, err := testAEAD.Decrypt(ciphertext, tt.aad)
            require.NoError(t, err)
            assert.Equal(t, tt.plaintext, decrypted)
        })
    }
}

func TestAEADDecryptWrongAAD(t *testing.T) {
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    plaintext := []byte(`{"token":"ghp_xxx"}`)
    correctAAD := []byte("correct-key")
    wrongAAD := []byte("wrong-key")

    ciphertext, err := testAEAD.Encrypt(plaintext, correctAAD)
    require.NoError(t, err)

    // Decryption with wrong AAD should fail
    _, err = testAEAD.Decrypt(ciphertext, wrongAAD)
    assert.Error(t, err)
}
```

**File: `internal/cache/distributed_test.go`** - Add encryption tests:

```go
func TestDistributedEncryption(t *testing.T) {
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    cache, err := NewDistributed[vendor.ProfileToken](mockClient, 45*time.Minute, testAEAD)
    require.NoError(t, err)

    token := vendor.ProfileToken{
        Token:  "ghp_test123",
        Expiry: time.Now().Add(time.Hour),
    }
    key := "digest:profile://org/test/profile/default"

    // Set should encrypt
    err = cache.Set(ctx, key, token)
    require.NoError(t, err)

    // Get should decrypt
    result, found, err := cache.Get(ctx, key)
    require.NoError(t, err)
    assert.True(t, found)
    assert.Equal(t, token.Token, result.Token)
}

func TestDistributedEncryptionKeyPrefix(t *testing.T) {
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    cache, err := NewDistributed[vendor.ProfileToken](mockClient, 45*time.Minute, testAEAD)
    require.NoError(t, err)

    key := "digest:profile://org/test/profile/default"
    expectedStorageKey := "enc:" + key

    // Verify storageKey adds prefix when encryption enabled
    assert.Equal(t, expectedStorageKey, cache.storageKey(key))
}

func TestDistributedDecryptionFailure(t *testing.T) {
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    cache, err := NewDistributed[vendor.ProfileToken](mockClient, 45*time.Minute, testAEAD)
    require.NoError(t, err)

    key := "digest:profile://org/test/profile/default"

    // Store invalid ciphertext directly (simulating corruption)
    storageKey := cache.storageKey(key)
    mockClient.Set(storageKey, "not-valid-base64-ciphertext")

    // Get should treat as cache miss, not error
    result, found, err := cache.Get(ctx, key)
    assert.NoError(t, err)  // No error returned
    assert.False(t, found)  // Treated as miss
    assert.Zero(t, result)
}

func TestDistributedNoEncryption(t *testing.T) {
    cache, err := NewDistributed[vendor.ProfileToken](mockClient, 45*time.Minute, nil)
    require.NoError(t, err)

    key := "test-key"

    // Verify storageKey has no prefix when encryption disabled
    assert.Equal(t, key, cache.storageKey(key))

    token := vendor.ProfileToken{Token: "ghp_test"}
    err = cache.Set(ctx, key, token)
    require.NoError(t, err)

    result, found, err := cache.Get(ctx, key)
    require.NoError(t, err)
    assert.True(t, found)
    assert.Equal(t, token.Token, result.Token)
}
```

#### 5.2 Integration Tests

Add integration tests in `api_integration_test.go` that verify:
1. Encrypted tokens can be stored and retrieved through the full API flow
2. Decryption failures are handled gracefully (treated as cache miss, entry invalidated)

### Phase 6: Migration Considerations

#### 6.1 Namespace Separation

Encrypted entries use `enc:` key prefix for clear namespace separation:
- **Plaintext key**: `digest:profile://org/pipeline/uuid/slug/profile/default`
- **Encrypted key**: `enc:digest:profile://org/pipeline/uuid/slug/profile/default`

This provides:
- Clear identification of encrypted vs plaintext entries
- Safe rollout alongside existing plaintext cache
- No collision between old plaintext and new encrypted entries

#### 6.2 Cache Value Format

When encryption is enabled (valkey only), the stored value format changes:
- **Plaintext**: JSON string (e.g., `{"token":"ghp_xxx","expiry":"..."}`)
- **Encrypted**: Base64-encoded ciphertext string

Combined with the key prefix, this means:
- Existing plaintext entries are untouched (different keys)
- New encrypted entries use `enc:` prefixed keys
- Short TTL (45 min) means plaintext entries expire naturally
- No explicit migration required

#### 6.3 Rollout Strategy

1. **Deploy with encryption disabled** - verify no regressions
2. **Enable encryption in staging** - monitor metrics and logs
3. **Enable encryption in production** - new entries use `enc:` prefix, old plaintext entries expire naturally (45 min TTL)
4. **No migration needed** - namespace separation means no conflicts

## File Summary

### New Files

| File | Purpose |
|------|---------|
| `internal/encryption/aead.go` | Tink AEAD wrapper, KMS integration, Secrets Manager keyset loading, `NewTestAEAD()` helper |
| `internal/encryption/aead_test.go` | Unit tests for AEAD encrypt/decrypt and AAD binding |

### Modified Files

| File | Changes |
|------|---------|
| `internal/config/config.go` | Add `CacheEncryptionConfig` struct nested in `CacheConfig`, add `Validate()` method requiring valkey |
| `internal/cache/distributed.go` | Add `aead` field, `storageKey()` method, `handleDecryptionFailure()`, encrypt/decrypt logic |
| `internal/cache/distributed_test.go` | Add tests for encryption, key prefix, decryption failure handling |
| `internal/cache/factory.go` | Initialize AEAD for valkey only, pass to distributed cache constructor |
| `internal/cache/instrumented.go` | Add `cache.decryption.failures` counter metric |
| `main.go` | Add `cfg.Cache.Validate()` call before cache creation |
| `go.mod` | Add Tink and AWS Secrets Manager dependencies |

## Dependencies

Add to `go.mod` (aws-sdk-go-v2/config already present):

```
github.com/tink-crypto/tink-go/v2 v2.x.x
github.com/tink-crypto/tink-go-awskms/v2 v2.x.x
github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.x.x
```

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CACHE_ENCRYPTION_ENABLED` | No | `false` | Enable cache encryption |
| `CACHE_ENCRYPTION_KEYSET_URI` | If enabled | - | URI to encrypted Tink keyset (e.g., `aws-secretsmanager://chinmina/keyset`) |
| `CACHE_ENCRYPTION_KMS_KEY_URI` | If enabled | - | AWS KMS key URI (e.g., `aws-kms://arn:aws:kms:us-east-1:123456789:key/abc-123`) |

## Keyset Rotation

### Rotation Procedure

Tink keysets support seamless rotation by maintaining multiple keys:

1. **Add new key to keyset** (external to this application):
   ```bash
   # Generate new keyset with rotated key using tinkey CLI
   tinkey rotate-keyset --in encrypted-keyset.json --out rotated-keyset.json \
     --master-key-uri aws-kms://arn:aws:kms:... --key-template AES256_GCM
   ```

2. **Update keyset in Secrets Manager**:
   ```bash
   aws secretsmanager update-secret --secret-id chinmina/keyset \
     --secret-string file://rotated-keyset.json
   ```

3. **Rolling restart of bridge instances**:
   - New instances load updated keyset from Secrets Manager
   - New keyset's primary key used for new encryptions
   - Old keys in keyset still decrypt existing cache entries

4. **Wait for cache TTL** (45 minutes):
   - All cache entries refresh with new key
   - Old key no longer needed for decryption

5. **Remove old key** (optional, external):
   - After TTL, old key can be disabled in keyset
   - Provides forward secrecy

### Keyset Refresh Without Restart

For zero-downtime rotation, the application could periodically refresh the keyset:

**Option A: Periodic refresh** (recommended for future enhancement):
```go
// In internal/encryption/aead.go

type RefreshableAEAD struct {
    mu        sync.RWMutex
    aead      tink.AEAD
    keysetURI string
    kmsKeyURI string
}

func (r *RefreshableAEAD) Refresh(ctx context.Context) error {
    newAEAD, err := loadAEAD(ctx, r.keysetURI, r.kmsKeyURI)
    if err != nil {
        return err
    }
    r.mu.Lock()
    r.aead = newAEAD
    r.mu.Unlock()
    return nil
}
```

**Option B: Rolling restart** (current implementation):
- Simplest approach, acceptable given 45-minute cache TTL
- Use orchestrator (Kubernetes, ECS) for rolling deployments
- No code changes required beyond initial implementation

### KMS Failure Recovery

If KMS is unavailable at startup:
- Application fails to start (fail-fast)
- Alerts trigger on startup failures
- Cache falls back to generating new tokens (no cached data)

If KMS becomes unavailable after startup:
- Existing AEAD continues to work (keyset already decrypted in memory)
- No impact until next restart
- Monitor KMS availability separately

## Security Considerations

1. **AAD Binding**: Cache key is used as AAD, preventing ciphertext from being moved between keys
2. **Key Rotation**: Tink keysets support multiple keys - new primary for encryption, old keys for decryption
3. **KMS Access**: Only bridge service should have `kms:Decrypt` permission for the KEK
4. **Keyset Protection**: Keyset in Secrets Manager is encrypted by KMS - double protection
5. **Memory Safety**: Plaintext tokens exist only briefly in memory during en/decryption
6. **Forward Secrecy**: After rotation and TTL expiry, old key can be removed

## Performance Impact

- **Startup**: ~100ms additional for KMS keyset decryption (one-time)
- **Per-operation**: ~10-20 microseconds for AES-256-GCM (negligible vs network latency)
- **Memory**: Minimal additional memory for AEAD primitive
