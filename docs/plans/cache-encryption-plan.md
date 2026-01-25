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
    // Applies to both memory and valkey cache types.
    Encryption CacheEncryptionConfig
}

// CacheEncryptionConfig holds settings for cache encryption.
type CacheEncryptionConfig struct {
    // Enabled turns on encryption for cached tokens.
    // When false, tokens are stored in plaintext.
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

### Phase 2: Encrypted Cache Wrapper

#### 2.1 New File: `internal/cache/encrypted.go`

Create an encryption wrapper that works with any cache implementation (memory or valkey).
The wrapper stores an `EncryptedValue` struct containing the ciphertext, which the underlying
cache serializes normally.

```go
package cache

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"

    "github.com/chinmina/chinmina-bridge/internal/encryption"
)

// EncryptedValue holds encrypted token data for cache storage.
// The underlying cache stores this struct, which gets JSON-serialized.
type EncryptedValue struct {
    // Ciphertext is the base64-encoded encrypted token JSON.
    Ciphertext string `json:"ciphertext"`
}

// Encrypted wraps a TokenCache with encryption/decryption.
// It encrypts tokens before storage and decrypts on retrieval.
// Works with any cache implementation (memory or valkey).
type Encrypted[T any] struct {
    wrapped TokenCache[EncryptedValue]
    aead    encryption.AEAD
}

// NewEncrypted creates an encrypting cache wrapper.
func NewEncrypted[T any](wrapped TokenCache[EncryptedValue], aead encryption.AEAD) *Encrypted[T] {
    return &Encrypted[T]{
        wrapped: wrapped,
        aead:    aead,
    }
}

func (e *Encrypted[T]) Get(ctx context.Context, key string) (T, bool, error) {
    var zero T

    // Get encrypted value from underlying cache
    encValue, found, err := e.wrapped.Get(ctx, key)
    if err != nil || !found {
        return zero, found, err
    }

    // Decode base64 ciphertext
    ciphertext, err := base64.StdEncoding.DecodeString(encValue.Ciphertext)
    if err != nil {
        return zero, false, fmt.Errorf("decoding ciphertext: %w", err)
    }

    // Decrypt with cache key as AAD
    plaintext, err := e.aead.Decrypt(ciphertext, []byte(key))
    if err != nil {
        return zero, false, fmt.Errorf("decrypting token: %w", err)
    }

    // Unmarshal decrypted JSON to result type
    var result T
    if err := json.Unmarshal(plaintext, &result); err != nil {
        return zero, false, fmt.Errorf("unmarshaling token: %w", err)
    }

    return result, true, nil
}

func (e *Encrypted[T]) Set(ctx context.Context, key string, token T) error {
    // Marshal token to JSON
    plaintext, err := json.Marshal(token)
    if err != nil {
        return fmt.Errorf("marshaling token: %w", err)
    }

    // Encrypt with cache key as AAD (prevents ciphertext swapping)
    ciphertext, err := e.aead.Encrypt(plaintext, []byte(key))
    if err != nil {
        return fmt.Errorf("encrypting token: %w", err)
    }

    // Store base64-encoded ciphertext in wrapper struct
    encValue := EncryptedValue{
        Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
    }

    return e.wrapped.Set(ctx, key, encValue)
}

func (e *Encrypted[T]) Invalidate(ctx context.Context, key string) error {
    return e.wrapped.Invalidate(ctx, key)
}

func (e *Encrypted[T]) Close() error {
    return e.wrapped.Close()
}
```

This design:
1. Works with both memory and valkey caches
2. Keeps the `TokenCache[T]` interface unchanged for callers
3. Uses `EncryptedValue` as an intermediate type that the underlying cache stores
4. Base64-encodes ciphertext for safe JSON serialization

### Phase 3: Factory and Initialization Updates

#### 3.1 Update Cache Factory

**File: `internal/cache/factory.go`**

The factory creates the base cache (memory or valkey), then wraps it with encryption if enabled.
When encryption is enabled, the base cache stores `EncryptedValue` instead of `T` directly.

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
// When encryption is enabled, wraps the base cache with the Encrypted wrapper.
func NewFromConfig[T any](
    ctx context.Context,
    cacheConfig config.CacheConfig,
    valkeyConfig config.ValkeyConfig,
    ttl time.Duration,
    maxMemorySize int,
) (TokenCache[T], error) {
    // If encryption enabled, we need to initialize AEAD first
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
        log.Info().Msg("cache encryption enabled")
    }

    // Create base cache - type depends on whether encryption is enabled
    if aead != nil {
        // With encryption: base cache stores EncryptedValue
        baseCache, err := newBaseCache[EncryptedValue](ctx, cacheConfig, valkeyConfig, ttl, maxMemorySize)
        if err != nil {
            return nil, err
        }
        encrypted := NewEncrypted[T](baseCache, aead)
        return NewInstrumented[T](encrypted, cacheConfig.Type), nil
    }

    // Without encryption: base cache stores T directly
    baseCache, err := newBaseCache[T](ctx, cacheConfig, valkeyConfig, ttl, maxMemorySize)
    if err != nil {
        return nil, err
    }
    return NewInstrumented[T](baseCache, cacheConfig.Type), nil
}

// newBaseCache creates the underlying memory or valkey cache.
func newBaseCache[T any](
    ctx context.Context,
    cacheConfig config.CacheConfig,
    valkeyConfig config.ValkeyConfig,
    ttl time.Duration,
    maxMemorySize int,
) (TokenCache[T], error) {
    switch cacheConfig.Type {
    case "valkey":
        log.Info().
            Str("cache_type", "valkey").
            Str("address", valkeyConfig.Address).
            Bool("tls", valkeyConfig.TLS).
            Msg("initializing distributed cache")

        if valkeyConfig.Address == "" {
            return nil, fmt.Errorf("valkey address required when cache type is valkey")
        }

        client, err := newValkeyClient(ctx, valkeyConfig)
        if err != nil {
            return nil, fmt.Errorf("creating valkey client: %w", err)
        }

        return NewDistributed[T](client, ttl)

    case "memory", "":
        log.Info().
            Str("cache_type", "memory").
            Msg("initializing in-memory cache")

        return NewMemory[T](ttl, maxMemorySize)

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

Add metrics to track encryption operations in `internal/cache/instrumented.go`:

```go
// Additional metrics for encryption operations
var (
    encryptionDuration = stats.Float64(
        "cache.encryption.duration",
        "Duration of encryption/decryption operations",
        stats.UnitMilliseconds,
    )
    encryptionResult = stats.Int64(
        "cache.encryption.operations",
        "Count of encryption operations",
        stats.UnitDimensionless,
    )
)

// Tags for encryption metrics
var (
    OperationTypeKey = tag.MustNewKey("operation") // "encrypt" or "decrypt"
    ResultKey        = tag.MustNewKey("result")    // "success" or "error"
)
```

#### 4.2 Startup Validation

Add encryption health check at startup:

```go
// internal/encryption/aead.go

// Validate performs a test encryption/decryption cycle to verify the AEAD is working.
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
```

### Phase 5: Testing Strategy

#### 5.1 Unit Tests

**File: `internal/encryption/aead_test.go`**

```go
package encryption_test

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/tink-crypto/tink-go/v2/aead"
    "github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
    "github.com/tink-crypto/tink-go/v2/keyset"
)

func TestAEADEncryptDecrypt(t *testing.T) {
    // Create a test keyset (not KMS-encrypted, for testing only)
    handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
    require.NoError(t, err)

    primitive, err := aead.New(handle)
    require.NoError(t, err)

    testAEAD := &tinkAEAD{primitive: primitive}

    tests := []struct {
        name       string
        plaintext  []byte
        aad        []byte
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
    handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
    require.NoError(t, err)

    primitive, err := aead.New(handle)
    require.NoError(t, err)

    testAEAD := &tinkAEAD{primitive: primitive}

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

**File: `internal/cache/distributed_test.go`**

Add tests for encrypted distributed cache operations.

#### 5.2 Integration Tests

Add integration tests that verify:
1. Encrypted tokens can be stored and retrieved
2. Cache entries with different keys cannot be swapped
3. Encryption metrics are recorded
4. Graceful handling of decryption failures

### Phase 6: Migration Considerations

#### 6.1 Cache Key Handling

When encryption is enabled, the underlying cache stores `EncryptedValue` structs instead of
`ProfileToken` directly. The cache keys remain the same, but the stored value format changes.

This means:
- Encrypted and plaintext caches use different value schemas
- Existing plaintext entries will fail to deserialize if encryption is enabled mid-flight
- Short TTL (45 min) means all entries refresh quickly after config change

#### 6.2 Rollout Strategy

1. **Deploy with encryption disabled** - verify no regressions
2. **Enable encryption in staging** - monitor metrics and logs
3. **Enable encryption in production** - existing plaintext entries expire naturally (45 min TTL)
4. **No migration needed** - short TTL means all entries refresh within 45 minutes

## File Summary

### New Files

| File | Purpose |
|------|---------|
| `internal/encryption/aead.go` | Tink AEAD wrapper, KMS integration, and Secrets Manager keyset loading |
| `internal/encryption/aead_test.go` | Unit tests for encryption |
| `internal/cache/encrypted.go` | `Encrypted[T]` wrapper that adds encryption to any cache implementation |
| `internal/cache/encrypted_test.go` | Unit tests for encrypted cache wrapper |

### Modified Files

| File | Changes |
|------|---------|
| `internal/config/config.go` | Add `CacheEncryptionConfig` struct nested in `CacheConfig`, add `Validate()` method |
| `internal/cache/factory.go` | Initialize AEAD, wrap base cache with `Encrypted` when encryption enabled |
| `internal/cache/instrumented.go` | Add encryption metrics (optional) |
| `main.go` | Add config validation call |
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

## Security Considerations

1. **AAD Binding**: Cache key is used as AAD, preventing ciphertext from being moved between keys
2. **Key Rotation**: Tink supports keyset rotation - old keys remain for decryption while new key used for encryption
3. **KMS Access**: Only bridge service should have `kms:Decrypt` permission for the KEK
4. **Keyset Protection**: Keyset in Secrets Manager is encrypted by KMS - double protection
5. **Memory Safety**: Plaintext tokens exist only briefly in memory during en/decryption

## Performance Impact

- **Startup**: ~100ms additional for KMS keyset decryption (one-time)
- **Per-operation**: ~10-20 microseconds for AES-256-GCM (negligible vs network latency)
- **Memory**: Minimal additional memory for AEAD primitive
