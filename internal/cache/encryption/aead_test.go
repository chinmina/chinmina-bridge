package encryption_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/cache/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
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

func TestAEADEncryptDecrypt(t *testing.T) {
	testAEAD := newTestAEAD(t)

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
	testAEAD := newTestAEAD(t)

	plaintext := []byte(`{"token":"ghp_xxx"}`)
	correctAAD := []byte("correct-key")
	wrongAAD := []byte("wrong-key")

	ciphertext, err := testAEAD.Encrypt(plaintext, correctAAD)
	require.NoError(t, err)

	_, err = testAEAD.Decrypt(ciphertext, wrongAAD)
	assert.Error(t, err)
}

func TestAEADDecryptCorruptedCiphertext(t *testing.T) {
	testAEAD := newTestAEAD(t)

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
	aead1 := newTestAEAD(t)
	aead2 := newTestAEAD(t)

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

// writeCleartextKeyset writes a keyset handle as cleartext JSON to a temp file
// and returns the path.
func writeCleartextKeyset(t *testing.T, handle *keyset.Handle) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyset.json")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	err = insecurecleartextkeyset.Write(handle, keyset.NewJSONWriter(f))
	require.NoError(t, err)
	return path
}

func TestLoadKeysetFromFile_RoundTrip(t *testing.T) {
	// Generate a keyset, write it, load it back, and verify it works.
	original, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	path := writeCleartextKeyset(t, original)

	loaded, err := encryption.LoadKeysetFromFile(path)
	require.NoError(t, err)

	// Verify the loaded handle produces a working AEAD.
	primitive, err := encryption.NewAEAD(loaded)
	require.NoError(t, err)

	plaintext := []byte("round-trip test")
	aad := []byte("test-aad")
	ct, err := primitive.Encrypt(plaintext, aad)
	require.NoError(t, err)

	decrypted, err := primitive.Decrypt(ct, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestLoadKeysetFromFile_Errors(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string
		expectedErr string
	}{
		{
			name: "missing file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.json")
			},
			expectedErr: "opening keyset file",
		},
		{
			name: "invalid JSON",
			setup: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "bad.json")
				err := os.WriteFile(path, []byte("not json"), 0o600)
				require.NoError(t, err)
				return path
			},
			expectedErr: "reading cleartext keyset",
		},
		{
			name: "empty file",
			setup: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "empty.json")
				err := os.WriteFile(path, []byte{}, 0o600)
				require.NoError(t, err)
				return path
			},
			expectedErr: "reading cleartext keyset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			_, err := encryption.LoadKeysetFromFile(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestNewRefreshableAEADFromFile_EncryptDecrypt(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	path := writeCleartextKeyset(t, handle)

	r, err := encryption.NewRefreshableAEADFromFile(t.Context(), path)
	require.NoError(t, err)
	defer func() { assert.NoError(t, r.Close()) }()

	plaintext := []byte("refreshable file round-trip")
	aad := []byte("test-context")

	ct, err := r.Encrypt(plaintext, aad)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ct)

	decrypted, err := r.Decrypt(ct, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestNewRefreshableAEADFromFile_InvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-keyset.json")
	err := os.WriteFile(path, []byte("not a keyset"), 0o600)
	require.NoError(t, err)

	r, err := encryption.NewRefreshableAEADFromFile(t.Context(), path)
	assert.Nil(t, r)
	assert.Error(t, err)
}

func TestNewRefreshableAEADFromFile_MissingFile(t *testing.T) {
	r, err := encryption.NewRefreshableAEADFromFile(t.Context(), filepath.Join(t.TempDir(), "gone.json"))
	assert.Nil(t, r)
	assert.Error(t, err)
}
