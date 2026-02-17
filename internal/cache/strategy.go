package cache

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// valuePrefix is the marker prepended to encrypted values to distinguish
// them from plaintext entries during rollout.
const valuePrefix = "cb-enc:"

// storageKeyPrefix is prepended to cache keys when encryption is active,
// providing namespace separation between encrypted and plaintext entries.
const storageKeyPrefix = "enc:"

// EncryptionStrategy defines how cache values are encrypted, decrypted,
// and how storage keys are decorated. Two implementations exist:
// NoEncryptionStrategy (pass-through) and TinkEncryptionStrategy (AEAD-based).
type EncryptionStrategy interface {
	// EncryptValue encrypts token bytes for storage. The key parameter is used
	// as associated data to bind ciphertext to a specific cache entry.
	EncryptValue(ctx context.Context, token []byte, key string) (string, error)

	// DecryptValue decrypts a stored value back to token bytes. The key
	// parameter must match the key used during encryption.
	DecryptValue(ctx context.Context, value string, key string) ([]byte, error)

	// StorageKey returns the cache key, potentially decorated with a prefix.
	StorageKey(key string) string

	// Close releases resources held by the strategy.
	Close() error
}

// NoEncryptionStrategy is a pass-through that stores values as-is.
type NoEncryptionStrategy struct{}

func (s *NoEncryptionStrategy) EncryptValue(_ context.Context, token []byte, _ string) (string, error) {
	return string(token), nil
}

func (s *NoEncryptionStrategy) DecryptValue(_ context.Context, value string, _ string) ([]byte, error) {
	return []byte(value), nil
}

func (s *NoEncryptionStrategy) StorageKey(key string) string {
	return key
}

func (s *NoEncryptionStrategy) Close() error {
	return nil
}

// TinkEncryptionStrategy encrypts cache values using a Tink AEAD primitive.
// Values are encrypted with the cache key as AAD (associated data) to prevent
// ciphertext swapping between keys, then base64-encoded and prefixed with
// "cb-enc:" for identification.
type TinkEncryptionStrategy struct {
	aead tink.AEAD
}

// NewTinkEncryptionStrategy creates an encryption strategy backed by a Tink AEAD.
func NewTinkEncryptionStrategy(aead tink.AEAD) *TinkEncryptionStrategy {
	return &TinkEncryptionStrategy{aead: aead}
}

func (s *TinkEncryptionStrategy) EncryptValue(_ context.Context, token []byte, key string) (string, error) {
	ciphertext, err := s.aead.Encrypt(token, []byte(key))
	if err != nil {
		return "", fmt.Errorf("encrypting value: %w", err)
	}
	return valuePrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *TinkEncryptionStrategy) DecryptValue(_ context.Context, value string, key string) ([]byte, error) {
	if !strings.HasPrefix(value, valuePrefix) {
		return nil, fmt.Errorf("missing %q prefix: value may be unencrypted or corrupted", valuePrefix)
	}

	encoded := strings.TrimPrefix(value, valuePrefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	plaintext, err := s.aead.Decrypt(decoded, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (s *TinkEncryptionStrategy) StorageKey(key string) string {
	return storageKeyPrefix + key
}

func (s *TinkEncryptionStrategy) Close() error {
	if closer, ok := s.aead.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
