package encryption

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestValidate_Success(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	primitive, err := aead.New(handle)
	require.NoError(t, err)

	assert.NoError(t, Validate(primitive))
}

func TestValidate_EncryptFailure(t *testing.T) {
	err := Validate(&failingAEAD{encryptErr: errors.New("encrypt broken")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation encrypt failed")
}

func TestValidate_DecryptFailure(t *testing.T) {
	err := Validate(&failingAEAD{decryptErr: errors.New("decrypt broken")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation decrypt failed")
}

func TestValidate_RoundTripMismatch(t *testing.T) {
	err := Validate(&mismatchAEAD{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation round-trip failed")
}

func TestReadKeysetFromSecretsManager_InvalidURI(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		errContains string
	}{
		{
			name:        "missing prefix",
			uri:         "https://example.com/secret",
			errContains: "must start with aws-secretsmanager://",
		},
		{
			name:        "wrong scheme",
			uri:         "aws-kms://some-key",
			errContains: "must start with aws-secretsmanager://",
		},
		{
			name:        "empty string",
			uri:         "",
			errContains: "must start with aws-secretsmanager://",
		},
		{
			name:        "prefix only with no secret name",
			uri:         "aws-secretsmanager://",
			errContains: "secret name is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readKeysetFromSecretsManager(context.Background(), tt.uri)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// failingAEAD is a test double implementing tink.AEAD that fails encrypt or
// decrypt on demand.
type failingAEAD struct {
	encryptErr error
	decryptErr error
}

func (f *failingAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if f.encryptErr != nil {
		return nil, f.encryptErr
	}
	return plaintext, nil
}

func (f *failingAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	return ciphertext, nil
}

// mismatchAEAD implements tink.AEAD, encrypting normally but returning wrong
// data on decrypt.
type mismatchAEAD struct{}

func (m *mismatchAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return plaintext, nil
}

func (m *mismatchAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return []byte("wrong data"), nil
}
