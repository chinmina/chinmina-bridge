package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKMSSigner_Algorithm(t *testing.T) {
	signer := kmsSigner{}
	assert.Equal(t, jwa.RS256(), signer.Algorithm())
}

func TestKMSSigner_Sign(t *testing.T) {
	expectedSignature := []byte("kms-signature-bytes")
	mockClient := &mockKMSClient{
		signFunc: func(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			assert.Equal(t, "arn:aws:kms:us-east-1:123456789:key/test-key", *in.KeyId)
			assert.Equal(t, types.MessageTypeDigest, in.MessageType)
			assert.Equal(t, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, in.SigningAlgorithm)
			assert.Len(t, in.Message, sha256.Size)

			return &kms.SignOutput{Signature: expectedSignature}, nil
		},
	}

	key := kmsSigningKey{
		ctx:    context.Background(),
		client: mockClient,
		arn:    "arn:aws:kms:us-east-1:123456789:key/test-key",
	}

	signer := kmsSigner{}
	signature, err := signer.Sign(key, []byte("test payload"))

	require.NoError(t, err)
	assert.Equal(t, expectedSignature, signature)
}

func TestKMSSigner_Sign_WrongKeyType(t *testing.T) {
	signer := kmsSigner{}
	_, err := signer.Sign("wrong-key-type", []byte("payload"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "kmsSigner requires kmsSigningKey")
}

func TestKMSSigner_Sign_KMSError(t *testing.T) {
	mockClient := &mockKMSClient{
		signFunc: func(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return nil, assert.AnError
		},
	}

	key := kmsSigningKey{
		ctx:    context.Background(),
		client: mockClient,
		arn:    "arn:aws:kms:us-east-1:123456789:key/test-key",
	}

	signer := kmsSigner{}
	_, err := signer.Sign(key, []byte("payload"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "KMS signing failed")
}

func TestDelegatingSigner_Algorithm(t *testing.T) {
	signer := &delegatingSigner{}
	assert.Equal(t, jwa.RS256(), signer.Algorithm())
}

func TestDelegatingSigner_Sign_RSAKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	builtinSigner := &rsaSigner{}
	signer := &delegatingSigner{builtinRS256: builtinSigner}

	payload := []byte("test payload for signing")
	signature, err := signer.Sign(privateKey, payload)

	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestDelegatingSigner_Sign_KMSKey(t *testing.T) {
	expectedSignature := []byte("kms-signature-bytes")
	mockClient := &mockKMSClient{
		signFunc: func(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			assert.Equal(t, "arn:aws:kms:us-east-1:123456789:key/test-key", *in.KeyId)
			assert.Equal(t, types.MessageTypeDigest, in.MessageType)
			assert.Equal(t, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, in.SigningAlgorithm)
			assert.Len(t, in.Message, sha256.Size)

			return &kms.SignOutput{Signature: expectedSignature}, nil
		},
	}

	key := kmsSigningKey{
		ctx:    context.Background(),
		client: mockClient,
		arn:    "arn:aws:kms:us-east-1:123456789:key/test-key",
	}

	builtinSigner := &rsaSigner{}
	signer := &delegatingSigner{
		builtinRS256: builtinSigner,
		kmsSigner:    kmsSigner{},
	}

	payload := []byte("test payload for KMS signing")
	signature, err := signer.Sign(key, payload)

	require.NoError(t, err)
	assert.Equal(t, expectedSignature, signature)
}

func TestDelegatingSigner_Sign_UnsupportedKeyType(t *testing.T) {
	builtinSigner := &rsaSigner{}
	signer := &delegatingSigner{builtinRS256: builtinSigner}

	_, err := signer.Sign("invalid-key", []byte("payload"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type for RS256")
}

// mockKMSClient is a mock implementation of KMSClient for testing.
type mockKMSClient struct {
	signFunc func(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *mockKMSClient) Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return m.signFunc(ctx, in, optFns...)
}

// rsaSigner is a simple RS256 signer for testing that bypasses global registration.
type rsaSigner struct{}

func (r *rsaSigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.RS256()
}

func (r *rsaSigner) Sign(key any, payload []byte) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, assert.AnError
	}

	hash := sha256.Sum256(payload)
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
}
