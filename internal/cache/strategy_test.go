package cache

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/cache/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func newTestAEAD(t testing.TB) tink.AEAD {
	t.Helper()
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)
	primitive, err := encryption.NewAEAD(handle)
	require.NoError(t, err)
	return primitive
}

func TestNoEncryptionStrategy_RoundTrip(t *testing.T) {
	s := &NoEncryptionStrategy{}

	ctx := t.Context()
	input := []byte(`{"token":"abc123"}`)
	encrypted, err := s.EncryptValue(ctx, input, "some-key")
	require.NoError(t, err)
	assert.Equal(t, string(input), encrypted)

	decrypted, err := s.DecryptValue(ctx, encrypted, "some-key")
	require.NoError(t, err)
	assert.Equal(t, input, decrypted)
}

func TestNoEncryptionStrategy_StorageKey(t *testing.T) {
	s := &NoEncryptionStrategy{}

	assert.Equal(t, "my-key", s.StorageKey("my-key"))
	assert.Equal(t, "", s.StorageKey(""))
}

func TestNoEncryptionStrategy_Close(t *testing.T) {
	s := &NoEncryptionStrategy{}
	assert.NoError(t, s.Close())
}

func TestTinkEncryptionStrategy_RoundTrip(t *testing.T) {
	testAEAD := newTestAEAD(t)

	s := NewTinkEncryptionStrategy(testAEAD)

	ctx := t.Context()
	input := []byte(`{"token":"ghp_secret"}`)
	key := "digest:profile://org/repo"

	encrypted, err := s.EncryptValue(ctx, input, key)
	require.NoError(t, err)
	assert.True(t, len(encrypted) > len(valuePrefix), "encrypted value should be longer than prefix")
	assert.Equal(t, valuePrefix, encrypted[:len(valuePrefix)])

	decrypted, err := s.DecryptValue(ctx, encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, input, decrypted)
}

func TestTinkEncryptionStrategy_StorageKey(t *testing.T) {
	testAEAD := newTestAEAD(t)

	s := NewTinkEncryptionStrategy(testAEAD)

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{name: "simple key", key: "test-key", expected: "enc:test-key"},
		{name: "key with colons", key: "digest:profile://org/repo", expected: "enc:digest:profile://org/repo"},
		{name: "empty key", key: "", expected: "enc:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, s.StorageKey(tt.key))
		})
	}
}

func TestTinkEncryptionStrategy_DecryptValue_MissingPrefix(t *testing.T) {
	testAEAD := newTestAEAD(t)

	s := NewTinkEncryptionStrategy(testAEAD)

	_, err := s.DecryptValue(t.Context(), `{"Data":"plaintext"}`, "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
	assert.Contains(t, err.Error(), "prefix")
}

func TestTinkEncryptionStrategy_DecryptValue_InvalidBase64(t *testing.T) {
	testAEAD := newTestAEAD(t)

	s := NewTinkEncryptionStrategy(testAEAD)

	_, err := s.DecryptValue(t.Context(), "cb-enc:not-valid-base64!!!", "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64")
}

func TestTinkEncryptionStrategy_DecryptValue_CorruptedCiphertext(t *testing.T) {
	testAEAD := newTestAEAD(t)

	s := NewTinkEncryptionStrategy(testAEAD)

	corrupted := "cb-enc:" + base64.StdEncoding.EncodeToString([]byte("not-valid-ciphertext"))
	_, err := s.DecryptValue(t.Context(), corrupted, "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestTinkEncryptionStrategy_DecryptValue_WrongAAD(t *testing.T) {
	testAEAD := newTestAEAD(t)

	s := NewTinkEncryptionStrategy(testAEAD)

	ctx := t.Context()

	// Encrypt with one key
	encrypted, err := s.EncryptValue(ctx, []byte(`{"data":"test"}`), "correct-key")
	require.NoError(t, err)

	// Decrypt with a different key
	_, err = s.DecryptValue(ctx, encrypted, "wrong-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestTinkEncryptionStrategy_EncryptValue_AEADError(t *testing.T) {
	s := NewTinkEncryptionStrategy(&failingAEAD{
		encryptErr: errors.New("hardware fault"),
	})

	_, err := s.EncryptValue(t.Context(), []byte("data"), "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypting value")
	assert.Contains(t, err.Error(), "hardware fault")
}

func TestTinkEncryptionStrategy_Close_WithCloser(t *testing.T) {
	closed := false
	mock := &closableAEAD{
		closeFn: func() error { closed = true; return nil },
	}

	s := NewTinkEncryptionStrategy(mock)
	err := s.Close()
	assert.NoError(t, err)
	assert.True(t, closed, "Close should have been called on the underlying AEAD")
}

func TestTinkEncryptionStrategy_Close_WithoutCloser(t *testing.T) {
	testAEAD := newTestAEAD(t)

	s := NewTinkEncryptionStrategy(testAEAD)
	err := s.Close()
	assert.NoError(t, err)
}

// closableAEAD is a test double that implements both tink.AEAD and Close() error.
type closableAEAD struct {
	closeFn func() error
}

func (c *closableAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return plaintext, nil
}

func (c *closableAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return ciphertext, nil
}

func (c *closableAEAD) Close() error {
	return c.closeFn()
}

// failingAEAD is a test double that returns errors on demand.
type failingAEAD struct {
	encryptErr error
}

func (f *failingAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return nil, f.encryptErr
}

func (f *failingAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return ciphertext, nil
}
