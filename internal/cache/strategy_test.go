package cache

import (
	"encoding/base64"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/cache/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoEncryptionStrategy_RoundTrip(t *testing.T) {
	s := &NoEncryptionStrategy{}

	input := []byte(`{"token":"abc123"}`)
	encrypted, err := s.EncryptValue(input, "some-key")
	require.NoError(t, err)
	assert.Equal(t, string(input), encrypted)

	decrypted, err := s.DecryptValue(encrypted, "some-key")
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
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	s := NewTinkEncryptionStrategy(testAEAD)

	input := []byte(`{"token":"ghp_secret"}`)
	key := "digest:profile://org/repo"

	encrypted, err := s.EncryptValue(input, key)
	require.NoError(t, err)
	assert.True(t, len(encrypted) > len(valuePrefix), "encrypted value should be longer than prefix")
	assert.Equal(t, valuePrefix, encrypted[:len(valuePrefix)])

	decrypted, err := s.DecryptValue(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, input, decrypted)
}

func TestTinkEncryptionStrategy_StorageKey(t *testing.T) {
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

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
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	s := NewTinkEncryptionStrategy(testAEAD)

	_, err = s.DecryptValue(`{"Data":"plaintext"}`, "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
	assert.Contains(t, err.Error(), "prefix")
}

func TestTinkEncryptionStrategy_DecryptValue_InvalidBase64(t *testing.T) {
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	s := NewTinkEncryptionStrategy(testAEAD)

	_, err = s.DecryptValue("cb-enc:not-valid-base64!!!", "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64")
}

func TestTinkEncryptionStrategy_DecryptValue_CorruptedCiphertext(t *testing.T) {
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	s := NewTinkEncryptionStrategy(testAEAD)

	corrupted := "cb-enc:" + base64.StdEncoding.EncodeToString([]byte("not-valid-ciphertext"))
	_, err = s.DecryptValue(corrupted, "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestTinkEncryptionStrategy_DecryptValue_WrongAAD(t *testing.T) {
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	s := NewTinkEncryptionStrategy(testAEAD)

	// Encrypt with one key
	encrypted, err := s.EncryptValue([]byte(`{"data":"test"}`), "correct-key")
	require.NoError(t, err)

	// Decrypt with a different key
	_, err = s.DecryptValue(encrypted, "wrong-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
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
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	s := NewTinkEncryptionStrategy(testAEAD)
	err = s.Close()
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
