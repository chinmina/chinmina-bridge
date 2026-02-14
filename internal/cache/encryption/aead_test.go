package encryption_test

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/cache/encryption"
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
			aad:       []byte("cache-key-1"),
		},
		{
			name:      "empty associated data",
			plaintext: []byte("some data"),
			aad:       []byte{},
		},
		{
			name:      "large plaintext",
			plaintext: make([]byte, 4096),
			aad:       []byte("large-key"),
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

	_, err = testAEAD.Decrypt(ciphertext, wrongAAD)
	assert.Error(t, err)
}

func TestAEADDecryptCorruptedCiphertext(t *testing.T) {
	testAEAD, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	plaintext := []byte("test data")
	aad := []byte("key")

	ciphertext, err := testAEAD.Encrypt(plaintext, aad)
	require.NoError(t, err)

	// Corrupt the ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xff

	_, err = testAEAD.Decrypt(ciphertext, aad)
	assert.Error(t, err)
}

func TestAEADDifferentKeysProduceDifferentCiphertext(t *testing.T) {
	aead1, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	aead2, err := encryption.NewTestAEAD()
	require.NoError(t, err)

	plaintext := []byte("same plaintext")
	aad := []byte("same-aad")

	ct1, err := aead1.Encrypt(plaintext, aad)
	require.NoError(t, err)

	ct2, err := aead2.Encrypt(plaintext, aad)
	require.NoError(t, err)

	// Different keys should produce different ciphertexts
	assert.NotEqual(t, ct1, ct2)

	// Cross-decryption should fail
	_, err = aead1.Decrypt(ct2, aad)
	assert.Error(t, err)

	_, err = aead2.Decrypt(ct1, aad)
	assert.Error(t, err)
}
