package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppTokenSource_Token_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Convert to JWK as expected by the token source
	jwkKey, err := jwk.Import(privateKey)
	require.NoError(t, err)

	appID := "12345"
	source := newAppTokenSource(jwkKey, appID)

	beforeToken := time.Now()
	token, err := source.Token()
	afterToken := time.Now()

	require.NoError(t, err)
	require.NotNil(t, token)

	// Verify token structure
	assert.NotEmpty(t, token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.True(t, token.Expiry.After(afterToken.Add(9*time.Minute)), "expiry should be ~10 minutes in future")
	assert.True(t, token.Expiry.Before(beforeToken.Add(11*time.Minute)), "expiry should be ~10 minutes in future")

	// Parse the JWT to verify claims
	parsed, err := jwt.Parse([]byte(token.AccessToken), jwt.WithVerify(false))
	require.NoError(t, err)

	issuer, ok := parsed.Issuer()
	assert.True(t, ok, "issuer should be present")
	assert.Equal(t, appID, issuer)

	iat, ok := parsed.IssuedAt()
	assert.True(t, ok, "iat should be present")

	_, ok = parsed.Expiration()
	assert.True(t, ok, "exp should be present")

	// Verify IssuedAt is backdated by ~60 seconds
	assert.True(t, iat.Before(beforeToken), "iat should be backdated")
	assert.True(t, iat.After(beforeToken.Add(-90*time.Second)), "iat should be backdated by ~60 seconds")
}

func TestAppTokenSource_Token_KMS(t *testing.T) {
	mockClient := &mockKMSClient{
		signFunc: func(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			// Return a valid RS256-length signature (256 bytes for 2048-bit key)
			signature := make([]byte, 256)
			for i := range signature {
				signature[i] = byte(i)
			}
			return &kms.SignOutput{Signature: signature}, nil
		},
	}

	key := kmsSigningKey{
		ctx:    context.Background(),
		client: mockClient,
		arn:    "arn:aws:kms:us-east-1:123456789:key/test-key",
	}

	appID := "67890"
	source := newAppTokenSource(key, appID)

	token, err := source.Token()

	require.NoError(t, err)
	require.NotNil(t, token)
	assert.NotEmpty(t, token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
}

func TestAppTokenSource_Token_InvalidKey(t *testing.T) {
	// Use an invalid key type
	source := newAppTokenSource("invalid-key", "12345")

	_, err := source.Token()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign JWT")
}

func TestNewAppTokenSource_ReturnsCachedSource(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.Import(privateKey)
	require.NoError(t, err)

	source := NewAppTokenSource(jwkKey, "99999")

	// Verify it returns a TokenSource (interface type)
	assert.NotNil(t, source)

	// Should be able to get a token
	token, err := source.Token()
	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
}
