package encryption

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go-awskms/v3/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// --- Test doubles ---

// fakeKMS is an identity KMS: Encrypt returns plaintext as ciphertext,
// Decrypt returns ciphertext as plaintext. This is sufficient for
// round-tripping Tink encrypted keysets in tests.
type fakeKMS struct {
	encryptFn func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	decryptFn func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

func (f *fakeKMS) Encrypt(ctx context.Context, input *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if f.encryptFn != nil {
		return f.encryptFn(ctx, input, opts...)
	}
	return &kms.EncryptOutput{
		CiphertextBlob:      input.Plaintext,
		KeyId:               input.KeyId,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	}, nil
}

func (f *fakeKMS) Decrypt(ctx context.Context, input *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if f.decryptFn != nil {
		return f.decryptFn(ctx, input, opts...)
	}
	return &kms.DecryptOutput{
		Plaintext:           input.CiphertextBlob,
		KeyId:               input.KeyId,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	}, nil
}

type fakeSecretsManager struct {
	getSecretValueFn func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func (f *fakeSecretsManager) GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return f.getSecretValueFn(ctx, input, opts...)
}

// --- Test helpers ---

const testKMSKeyURI = "aws-kms://arn:aws:kms:us-east-1:123456789012:key/test-key-id"

// encryptedKeysetJSON creates a keyset handle, encrypts it with the given
// fake KMS client, and returns the JSON bytes and original handle.
func encryptedKeysetJSON(t *testing.T, kmsClient KMSAPI) ([]byte, *keyset.Handle) {
	t.Helper()

	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	kmsAEAD, err := awskms.NewAEADWithContext(testKMSKeyURI, awskms.WithKMS(kmsClient))
	require.NoError(t, err)

	var buf bytes.Buffer
	writer := keyset.NewJSONWriter(&buf)
	err = handle.WriteWithContext(context.Background(), writer, kmsAEAD, nil)
	require.NoError(t, err)

	return buf.Bytes(), handle
}

// --- Validate tests ---

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

// --- NewAEAD tests ---

func TestNewAEAD_Success(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	primitive, err := NewAEAD(handle)
	require.NoError(t, err)

	// Verify the returned AEAD works for encrypt/decrypt
	plaintext := []byte("test data")
	aad := []byte("associated")
	ct, err := primitive.Encrypt(plaintext, aad)
	require.NoError(t, err)

	decrypted, err := primitive.Decrypt(ct, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestNewAEAD_NilHandle(t *testing.T) {
	_, err := NewAEAD(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating AEAD primitive")
}

// --- LoadKeysetFromAWS tests ---

func TestLoadKeysetFromAWS_HappyPath(t *testing.T) {
	fakeKMSClient := &fakeKMS{}
	keysetJSON, _ := encryptedKeysetJSON(t, fakeKMSClient)

	secretString := string(keysetJSON)
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			assert.Equal(t, "my-secret", *input.SecretId)
			return &secretsmanager.GetSecretValueOutput{
				SecretString: &secretString,
			}, nil
		},
	}

	handle, err := LoadKeysetFromAWS(
		context.Background(),
		"aws-secretsmanager://my-secret",
		testKMSKeyURI,
		WithKMSClient(fakeKMSClient),
		WithSecretsManagerClient(fakeSM),
	)
	require.NoError(t, err)

	// The returned handle should produce a working AEAD
	primitive, err := aead.New(handle)
	require.NoError(t, err)

	plaintext := []byte("round-trip test")
	aad := []byte("aad")
	ct, err := primitive.Encrypt(plaintext, aad)
	require.NoError(t, err)

	decrypted, err := primitive.Decrypt(ct, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestLoadKeysetFromAWS_SecretsManagerError(t *testing.T) {
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	_, err := LoadKeysetFromAWS(
		context.Background(),
		"aws-secretsmanager://my-secret",
		testKMSKeyURI,
		WithKMSClient(&fakeKMS{}),
		WithSecretsManagerClient(fakeSM),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading keyset")
	assert.Contains(t, err.Error(), "access denied")
}

func TestLoadKeysetFromAWS_NilSecretString(t *testing.T) {
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: nil,
			}, nil
		},
	}

	_, err := LoadKeysetFromAWS(
		context.Background(),
		"aws-secretsmanager://my-secret",
		testKMSKeyURI,
		WithKMSClient(&fakeKMS{}),
		WithSecretsManagerClient(fakeSM),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no string value")
}

func TestLoadKeysetFromAWS_InvalidKeysetJSON(t *testing.T) {
	garbage := "not valid json"
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: &garbage,
			}, nil
		},
	}

	_, err := LoadKeysetFromAWS(
		context.Background(),
		"aws-secretsmanager://my-secret",
		testKMSKeyURI,
		WithKMSClient(&fakeKMS{}),
		WithSecretsManagerClient(fakeSM),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting keyset")
}

func TestLoadKeysetFromAWS_KMSDecryptError(t *testing.T) {
	// Use a real encrypted keyset but with a KMS that fails on decrypt
	workingKMS := &fakeKMS{}
	keysetJSON, _ := encryptedKeysetJSON(t, workingKMS)

	secretString := string(keysetJSON)
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: &secretString,
			}, nil
		},
	}

	failingKMS := &fakeKMS{
		decryptFn: func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			return nil, errors.New("kms key disabled")
		},
	}

	_, err := LoadKeysetFromAWS(
		context.Background(),
		"aws-secretsmanager://my-secret",
		testKMSKeyURI,
		WithKMSClient(failingKMS),
		WithSecretsManagerClient(fakeSM),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting keyset")
	assert.Contains(t, err.Error(), "kms key disabled")
}

func TestLoadKeysetFromAWS_InvalidSecretsManagerURI(t *testing.T) {
	_, err := LoadKeysetFromAWS(
		context.Background(),
		"https://not-a-sm-uri",
		testKMSKeyURI,
		WithKMSClient(&fakeKMS{}),
		WithSecretsManagerClient(&fakeSecretsManager{}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading keyset")
	assert.Contains(t, err.Error(), "must start with aws-secretsmanager://")
}

func TestLoadKeysetFromAWS_InvalidKMSKeyURI(t *testing.T) {
	_, err := LoadKeysetFromAWS(
		context.Background(),
		"aws-secretsmanager://my-secret",
		"not-a-kms-uri",
		WithKMSClient(&fakeKMS{}),
		WithSecretsManagerClient(&fakeSecretsManager{}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating KMS AEAD")
}

// --- readKeysetFromSecretsManager tests ---

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

	// A nil client is fine here — URI validation happens before any API call.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readKeysetFromSecretsManager(context.Background(), tt.uri, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestReadKeysetFromSecretsManager_Success(t *testing.T) {
	secretValue := `{"some":"json"}`
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			assert.Equal(t, "my-keyset", *input.SecretId)
			return &secretsmanager.GetSecretValueOutput{
				SecretString: &secretValue,
			}, nil
		},
	}

	reader, err := readKeysetFromSecretsManager(context.Background(), "aws-secretsmanager://my-keyset", fakeSM)
	require.NoError(t, err)
	require.NotNil(t, reader)
}

func TestReadKeysetFromSecretsManager_APIError(t *testing.T) {
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, errors.New("throttled")
		},
	}

	_, err := readKeysetFromSecretsManager(context.Background(), "aws-secretsmanager://my-keyset", fakeSM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting secret")
	assert.Contains(t, err.Error(), "throttled")
}

func TestReadKeysetFromSecretsManager_NilSecretString(t *testing.T) {
	fakeSM := &fakeSecretsManager{
		getSecretValueFn: func(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: nil,
			}, nil
		},
	}

	_, err := readKeysetFromSecretsManager(context.Background(), "aws-secretsmanager://my-keyset", fakeSM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no string value")
}

// --- Existing test doubles for Validate ---

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
