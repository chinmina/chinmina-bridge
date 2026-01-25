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

### Phase 2: Cache Component Encryption

The component model injects AEAD as a dependency into each cache implementation.
Each cache handles encryption internally - no wrapper or intermediate types needed.

#### 2.1 Modify `internal/cache/distributed.go`

Add optional AEAD to the Distributed cache:

```go
package cache

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "time"

    "github.com/chinmina/chinmina-bridge/internal/encryption"
    "github.com/valkey-io/valkey-go"
)

type Distributed[T any] struct {
    client valkey.Client
    ttl    time.Duration
    aead   encryption.AEAD // nil means no encryption
}

// NewDistributed creates a distributed cache with optional encryption.
func NewDistributed[T any](client valkey.Client, ttl time.Duration, aead encryption.AEAD) *Distributed[T] {
    return &Distributed[T]{
        client: client,
        ttl:    ttl,
        aead:   aead,
    }
}

func (d *Distributed[T]) Get(ctx context.Context, key string) (T, bool, error) {
    var result T

    storageKey := d.storageKey(key)
    cmd := d.client.DoCache(ctx,
        d.client.B().Get().Key(storageKey).Cache(),
        d.ttl,
    )

    data, err := cmd.AsBytes()
    if err != nil {
        if valkey.IsValkeyNil(err) {
            return result, false, nil
        }
        return result, false, fmt.Errorf("cache get: %w", err)
    }

    // Decrypt if encryption is enabled
    plaintext := data
    if d.aead != nil {
        decoded, err := base64.StdEncoding.DecodeString(string(data))
        if err != nil {
            return result, false, fmt.Errorf("decoding ciphertext: %w", err)
        }
        plaintext, err = d.aead.Decrypt(decoded, []byte(key))
        if err != nil {
            return result, false, fmt.Errorf("decrypting token: %w", err)
        }
    }

    if err := json.Unmarshal(plaintext, &result); err != nil {
        return result, false, fmt.Errorf("unmarshaling token: %w", err)
    }

    return result, true, nil
}

func (d *Distributed[T]) Set(ctx context.Context, key string, token T) error {
    plaintext, err := json.Marshal(token)
    if err != nil {
        return fmt.Errorf("marshaling token: %w", err)
    }

    // Encrypt if encryption is enabled
    data := plaintext
    if d.aead != nil {
        ciphertext, err := d.aead.Encrypt(plaintext, []byte(key))
        if err != nil {
            return fmt.Errorf("encrypting token: %w", err)
        }
        // Base64 encode for safe storage as string
        data = []byte(base64.StdEncoding.EncodeToString(ciphertext))
    }

    storageKey := d.storageKey(key)
    cmd := d.client.Do(ctx,
        d.client.B().Set().Key(storageKey).Value(string(data)).Ex(d.ttl).Build(),
    )

    return cmd.Error()
}

func (d *Distributed[T]) Invalidate(ctx context.Context, key string) error {
    storageKey := d.storageKey(key)
    return d.client.Do(ctx, d.client.B().Del().Key(storageKey).Build()).Error()
}

// storageKey returns the key with appropriate prefix.
// Encrypted entries use "enc:" prefix for namespace separation.
func (d *Distributed[T]) storageKey(key string) string {
    if d.aead != nil {
        return "enc:" + key
    }
    return key
}

// Close method unchanged
```

#### 2.2 Modify `internal/cache/memory.go`

Add optional AEAD to the Memory cache:

```go
package cache

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/chinmina/chinmina-bridge/internal/encryption"
    "github.com/maypok86/otter/v2"
)

// encryptedEntry stores encrypted data in the memory cache.
// When encryption is disabled, we store T directly via the unencrypted path.
type encryptedEntry struct {
    ciphertext []byte
}

type Memory[T any] struct {
    // When aead is nil, cache stores T directly
    // When aead is set, cache stores encryptedEntry
    cache *otter.Cache[string, any]
    ttl   time.Duration
    aead  encryption.AEAD
}

// NewMemory creates a memory cache with optional encryption.
func NewMemory[T any](ttl time.Duration, maxSize int, aead encryption.AEAD) (*Memory[T], error) {
    cache, err := otter.NewBuilder[string, any](maxSize).
        WithTTL(ttl).
        Build()
    if err != nil {
        return nil, fmt.Errorf("creating otter cache: %w", err)
    }

    return &Memory[T]{
        cache: cache,
        ttl:   ttl,
        aead:  aead,
    }, nil
}

func (m *Memory[T]) Get(ctx context.Context, key string) (T, bool, error) {
    var zero T

    storageKey := m.storageKey(key)
    value, found := m.cache.Get(storageKey)
    if !found {
        return zero, false, nil
    }

    // If encryption disabled, value is T directly
    if m.aead == nil {
        result, ok := value.(T)
        if !ok {
            return zero, false, fmt.Errorf("unexpected cache value type")
        }
        return result, true, nil
    }

    // Encryption enabled - value is encryptedEntry
    entry, ok := value.(encryptedEntry)
    if !ok {
        return zero, false, fmt.Errorf("unexpected cache value type")
    }

    plaintext, err := m.aead.Decrypt(entry.ciphertext, []byte(key))
    if err != nil {
        return zero, false, fmt.Errorf("decrypting token: %w", err)
    }

    var result T
    if err := json.Unmarshal(plaintext, &result); err != nil {
        return zero, false, fmt.Errorf("unmarshaling token: %w", err)
    }

    return result, true, nil
}

func (m *Memory[T]) Set(ctx context.Context, key string, token T) error {
    storageKey := m.storageKey(key)

    // If encryption disabled, store T directly
    if m.aead == nil {
        m.cache.Set(storageKey, token)
        return nil
    }

    // Encryption enabled - marshal, encrypt, store as encryptedEntry
    plaintext, err := json.Marshal(token)
    if err != nil {
        return fmt.Errorf("marshaling token: %w", err)
    }

    ciphertext, err := m.aead.Encrypt(plaintext, []byte(key))
    if err != nil {
        return fmt.Errorf("encrypting token: %w", err)
    }

    m.cache.Set(storageKey, encryptedEntry{ciphertext: ciphertext})
    return nil
}

func (m *Memory[T]) Invalidate(ctx context.Context, key string) error {
    storageKey := m.storageKey(key)
    m.cache.Delete(storageKey)
    return nil
}

// storageKey returns the key with appropriate prefix.
// Encrypted entries use "enc:" prefix for namespace separation.
func (m *Memory[T]) storageKey(key string) string {
    if m.aead != nil {
        return "enc:" + key
    }
    return key
}

// Close method unchanged
```

**Component model benefits:**
1. Each cache handles its own encryption - no wrapper indirection
2. Simpler type system - no intermediate `EncryptedValue` type for callers
3. AEAD is a clear dependency, nil means disabled
4. Encryption logic lives with storage logic

### Phase 3: Factory and Initialization Updates

#### 3.1 Update Cache Factory

**File: `internal/cache/factory.go`**

The factory initializes AEAD if encryption is enabled, then passes it to whichever cache is created.

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
// AEAD is initialized once and passed to the cache implementation.
func NewFromConfig[T any](
    ctx context.Context,
    cacheConfig config.CacheConfig,
    valkeyConfig config.ValkeyConfig,
    ttl time.Duration,
    maxMemorySize int,
) (TokenCache[T], error) {
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
        log.Info().Msg("cache encryption enabled")
    }

    // Create cache with AEAD dependency (nil if encryption disabled)
    var cache TokenCache[T]
    var err error

    switch cacheConfig.Type {
    case "valkey":
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

        cache = NewDistributed[T](client, ttl, aead)

    case "memory", "":
        log.Info().
            Str("cache_type", "memory").
            Bool("encryption", aead != nil).
            Msg("initializing in-memory cache")

        cache, err = NewMemory[T](ttl, maxMemorySize, aead)
        if err != nil {
            return nil, fmt.Errorf("creating memory cache: %w", err)
        }

    default:
        return nil, fmt.Errorf("invalid cache type %q: must be \"memory\" or \"valkey\"", cacheConfig.Type)
    }

    return NewInstrumented[T](cache, cacheConfig.Type), nil
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
    // Setup test AEAD
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    // Create cache with encryption
    cache := NewDistributed[vendor.ProfileToken](mockClient, 45*time.Minute, testAEAD)

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

func TestDistributedEncryptionAADBinding(t *testing.T) {
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    cache := NewDistributed[vendor.ProfileToken](mockClient, 45*time.Minute, testAEAD)

    token := vendor.ProfileToken{Token: "ghp_test"}
    key1 := "digest:profile://org/test/profile/one"
    key2 := "digest:profile://org/test/profile/two"

    // Store token under key1
    err = cache.Set(ctx, key1, token)
    require.NoError(t, err)

    // Manually copy raw ciphertext from key1 to key2 in mock
    // Then attempt to get from key2 - should fail due to AAD mismatch
    _, _, err = cache.Get(ctx, key2)
    assert.Error(t, err) // AAD binding prevents cross-key access
}
```

**File: `internal/cache/memory_test.go`** - Add encryption tests:

```go
func TestMemoryEncryption(t *testing.T) {
    testAEAD, err := encryption.NewTestAEAD()
    require.NoError(t, err)

    cache, err := NewMemory[vendor.ProfileToken](45*time.Minute, 100, testAEAD)
    require.NoError(t, err)

    token := vendor.ProfileToken{
        Token:  "ghp_test123",
        Expiry: time.Now().Add(time.Hour),
    }
    key := "digest:profile://org/test/profile/default"

    err = cache.Set(ctx, key, token)
    require.NoError(t, err)

    result, found, err := cache.Get(ctx, key)
    require.NoError(t, err)
    assert.True(t, found)
    assert.Equal(t, token.Token, result.Token)
}

func TestMemoryNoEncryption(t *testing.T) {
    // nil AEAD means no encryption
    cache, err := NewMemory[vendor.ProfileToken](45*time.Minute, 100, nil)
    require.NoError(t, err)

    token := vendor.ProfileToken{Token: "ghp_test"}
    key := "test-key"

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
2. Cache entries with different keys cannot be swapped (AAD binding)
3. Graceful handling of decryption failures (corrupted cache entries)

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

When encryption is enabled, the stored value format also changes:
- **Valkey**: Plaintext JSON → Base64-encoded ciphertext string
- **Memory**: Direct `T` storage → `encryptedEntry{ciphertext []byte}`

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
| `internal/config/config.go` | Add `CacheEncryptionConfig` struct nested in `CacheConfig`, add `Validate()` method |
| `internal/cache/distributed.go` | Add `aead` field, `storageKey()` method with `enc:` prefix, encrypt on Set, decrypt on Get |
| `internal/cache/distributed_test.go` | Add tests for encryption and AAD binding |
| `internal/cache/memory.go` | Add `aead` field, `encryptedEntry` type, `storageKey()` method with `enc:` prefix, encrypt on Set, decrypt on Get |
| `internal/cache/memory_test.go` | Add tests for encryption with and without AEAD |
| `internal/cache/factory.go` | Initialize AEAD, pass to cache constructors, log encryption status |
| `internal/cache/instrumented.go` | Add encryption metrics (optional) |
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
