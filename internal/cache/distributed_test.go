//go:build integration

package cache

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/cache/encryption"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"github.com/valkey-io/valkey-go"
)

func newIntegrationTestAEAD(t testing.TB) tink.AEAD {
	t.Helper()
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)
	primitive, err := encryption.NewAEAD(handle)
	require.NoError(t, err)
	return primitive
}

func setupValkey(t *testing.T) valkey.Client {
	t.Helper()

	cacheCfg := testhelpers.RunValkeyContainer(t)

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{cacheCfg.Valkey.Address},
		Username:    cacheCfg.Valkey.Username,
		Password:    cacheCfg.Valkey.Password,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

func TestIntegrationDistributed_SetAndGet(t *testing.T) {
	client := setupValkey(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, nil)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	expected := CacheTestDummy{
		Data: "test-value",
	}

	// Set token
	err = cache.Set(ctx, key, expected)
	require.NoError(t, err)

	// Get token
	assertEventuallyExists(t, cache, key)
}

func TestIntegrationDistributed_GetNotFound(t *testing.T) {
	client := setupValkey(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, nil)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()

	result, found, err := cache.Get(ctx, "nonexistent-key")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, CacheTestDummy{}, result)
}

func TestIntegrationDistributed_Invalidate(t *testing.T) {
	client := setupValkey(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, nil)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	dummy := CacheTestDummy{
		Data: "test-value",
	}

	// Set token
	err = cache.Set(ctx, key, dummy)
	require.NoError(t, err)

	// Verify it's there
	assertEventuallyExists(t, cache, key)

	// Invalidate
	err = cache.Invalidate(ctx, key)
	require.NoError(t, err)

	// Verify it's gone by polling (as invalidate may be eventually consistent)
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err := cache.Get(ctx, key)
		require.NoError(collect, err)
		assert.False(collect, found)
	}, time.Second*2, time.Millisecond*50, "cache entry should be eventually invalidated")
}

func TestIntegrationDistributed_TTL(t *testing.T) {
	client := setupValkey(t)

	// Short TTL for testing
	cache, err := NewDistributed[CacheTestDummy](client, 1*time.Second, nil)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	dummy := CacheTestDummy{
		Data: "test-value",
	}

	// Set token
	err = cache.Set(ctx, key, dummy)
	require.NoError(t, err)

	// Verify it's there immediately
	assertEventuallyExists(t, cache, key)

	// Verify it's expired
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err := cache.Get(ctx, key)
		require.NoError(collect, err)
		assert.False(collect, found)
	}, time.Second*2, time.Millisecond*100, "cache entry should expire after TTL")
}

func TestIntegrationDistributed_JSONRoundTrip(t *testing.T) {
	client := setupValkey(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, nil)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()

	testCases := []struct {
		name     string
		expected CacheTestDummy
	}{
		{
			name:     "simple value",
			expected: CacheTestDummy{Data: "test"},
		},
		{
			name:     "empty value",
			expected: CacheTestDummy{Data: ""},
		},
		{
			name:     "special characters",
			expected: CacheTestDummy{Data: "special: !@#$%^&*(){}[]|\\:\";<>?,./"},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			key := "json-test-" + tt.name

			err := cache.Set(ctx, key, tt.expected)
			require.NoError(t, err)

			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				result, found, err := cache.Get(ctx, key)
				require.NoError(collect, err)
				assert.True(collect, found)
				assert.Equal(collect, tt.expected, result)
			}, time.Second*2, time.Millisecond*100, "cache entry should be eventually available")
		})
	}
}

func TestIntegrationDistributed_EncryptionRoundTrip(t *testing.T) {
	client := setupValkey(t)
	testAEAD := newIntegrationTestAEAD(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, NewTinkEncryptionStrategy(testAEAD))
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "digest:profile://org/test/profile/default"

	expected := CacheTestDummy{Data: "ghp_test123"}

	err = cache.Set(ctx, key, expected)
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		result, found, err := cache.Get(ctx, key)
		require.NoError(collect, err)
		assert.True(collect, found)
		assert.Equal(collect, expected, result)
	}, time.Second*2, time.Millisecond*100, "encrypted value should round-trip")
}

func TestIntegrationDistributed_EncryptionKeyPrefix(t *testing.T) {
	client := setupValkey(t)
	testAEAD := newIntegrationTestAEAD(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, NewTinkEncryptionStrategy(testAEAD))
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	err = cache.Set(ctx, key, CacheTestDummy{Data: "value"})
	require.NoError(t, err)

	// The value should be stored under "enc:test-key", not "test-key"
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		// Check that the enc:-prefixed key exists
		cmd := client.B().Get().Key("enc:" + key).Build()
		result := client.Do(ctx, cmd)
		val, err := result.ToString()
		require.NoError(collect, err)
		assert.True(collect, len(val) > 0, "enc: prefixed key should exist")
	}, time.Second*2, time.Millisecond*100, "enc: prefixed key should exist")
}

func TestIntegrationDistributed_EncryptionValuePrefix(t *testing.T) {
	client := setupValkey(t)
	testAEAD := newIntegrationTestAEAD(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, NewTinkEncryptionStrategy(testAEAD))
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	err = cache.Set(ctx, key, CacheTestDummy{Data: "value"})
	require.NoError(t, err)

	// Read raw value and verify cb-enc: prefix
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		cmd := client.B().Get().Key("enc:" + key).Build()
		val, err := client.Do(ctx, cmd).ToString()
		require.NoError(collect, err)
		assert.True(collect, len(val) > 7 && val[:7] == "cb-enc:", "stored value should have cb-enc: prefix")
	}, time.Second*2, time.Millisecond*100, "stored value should have cb-enc: prefix")
}

func TestIntegrationDistributed_DecryptionFailure_CorruptedCiphertext(t *testing.T) {
	client := setupValkey(t)
	testAEAD := newIntegrationTestAEAD(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, NewTinkEncryptionStrategy(testAEAD))
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	// Write corrupted ciphertext directly with cb-enc: prefix
	storageKey := "enc:" + key
	corruptedValue := "cb-enc:" + base64.StdEncoding.EncodeToString([]byte("not-valid-ciphertext"))
	cmd := client.B().Set().Key(storageKey).Value(corruptedValue).ExSeconds(300).Build()
	err = client.Do(ctx, cmd).Error()
	require.NoError(t, err)

	// Get should return an error for decryption failure
	result, found, err := cache.Get(ctx, key)
	assert.Error(t, err)
	assert.False(t, found)
	assert.Equal(t, CacheTestDummy{}, result)
}

func TestIntegrationDistributed_DecryptionFailure_MissingPrefix(t *testing.T) {
	client := setupValkey(t)
	testAEAD := newIntegrationTestAEAD(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, NewTinkEncryptionStrategy(testAEAD))
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	// Write plaintext value under the enc: key (simulates mixed-mode scenario)
	storageKey := "enc:" + key
	cmd := client.B().Set().Key(storageKey).Value(`{"Data":"plaintext"}`).ExSeconds(300).Build()
	err = client.Do(ctx, cmd).Error()
	require.NoError(t, err)

	// Get should return an error for decryption failure
	result, found, err := cache.Get(ctx, key)
	assert.Error(t, err)
	assert.False(t, found)
	assert.Equal(t, CacheTestDummy{}, result)
}

func TestIntegrationDistributed_DecryptionFailure_InvalidBase64(t *testing.T) {
	client := setupValkey(t)
	testAEAD := newIntegrationTestAEAD(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, NewTinkEncryptionStrategy(testAEAD))
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	// Write value with cb-enc: prefix but invalid base64
	storageKey := "enc:" + key
	cmd := client.B().Set().Key(storageKey).Value("cb-enc:not-valid-base64!!!").ExSeconds(300).Build()
	err = client.Do(ctx, cmd).Error()
	require.NoError(t, err)

	// Get should return an error for decryption failure
	result, found, err := cache.Get(ctx, key)
	assert.Error(t, err)
	assert.False(t, found)
	assert.Equal(t, CacheTestDummy{}, result)
}

func TestIntegrationDistributed_DecryptionFailure_WrongAAD(t *testing.T) {
	client := setupValkey(t)
	testAEAD := newIntegrationTestAEAD(t)

	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, NewTinkEncryptionStrategy(testAEAD))
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	// Encrypt with one key as AAD, store under a different key
	ciphertext, err := testAEAD.Encrypt([]byte(`{"Data":"test"}`), []byte("different-key"))
	require.NoError(t, err)

	storageKey := "enc:" + key
	value := "cb-enc:" + base64.StdEncoding.EncodeToString(ciphertext)
	cmd := client.B().Set().Key(storageKey).Value(value).ExSeconds(300).Build()
	err = client.Do(ctx, cmd).Error()
	require.NoError(t, err)

	// Get should return an error because AAD won't match
	result, found, err := cache.Get(ctx, key)
	assert.Error(t, err)
	assert.False(t, found)
	assert.Equal(t, CacheTestDummy{}, result)
}

func TestIntegrationDistributed_NoEncryptionRoundTrip(t *testing.T) {
	client := setupValkey(t)

	// nil strategy means no encryption
	cache, err := NewDistributed[CacheTestDummy](client, 5*time.Minute, nil)
	require.NoError(t, err)
	defer cache.Close()

	ctx := context.Background()
	key := "test-key"

	expected := CacheTestDummy{Data: "plaintext-value"}

	err = cache.Set(ctx, key, expected)
	require.NoError(t, err)

	// Verify the value is stored as plaintext JSON under the original key
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		cmd := client.B().Get().Key(key).Build()
		val, err := client.Do(ctx, cmd).ToString()
		require.NoError(collect, err)
		assert.Contains(collect, val, "plaintext-value")
		assert.NotContains(collect, val, "cb-enc:")
	}, time.Second*2, time.Millisecond*100, "plaintext value should be stored without prefix")

	// Verify round-trip
	assertEventuallyExists(t, cache, key)
}

func assertEventuallyExists(t *testing.T, cache TokenCache[CacheTestDummy], key string) {
	t.Helper()

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, found, err := cache.Get(context.Background(), key)
		require.NoError(collect, err)
		assert.True(collect, found)
	}, time.Second*2, time.Millisecond*100, "cache entry should be eventually available")
}
