package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInstallationTokenSource(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.Import(privateKey)
	require.NoError(t, err)

	appTokenSource := NewAppTokenSource(jwkKey, "12345")

	source := NewInstallationTokenSource(67890, appTokenSource)

	// Verify it returns a TokenSource
	assert.NotNil(t, source)
}

func TestNewInstallationTokenSource_WithOptions(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkKey, err := jwk.Import(privateKey)
	require.NoError(t, err)

	appTokenSource := NewAppTokenSource(jwkKey, "12345")
	httpClient := &http.Client{}

	source := NewInstallationTokenSource(
		67890,
		appTokenSource,
		WithHTTPClient(httpClient),
		WithEnterpriseURL("https://github.example.com"),
	)

	assert.NotNil(t, source)
}

// Tests for key construction functions moved to token_test.go

func TestParsePrivateKeyPEM_PKCS1(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	parsed, err := parsePrivateKeyPEM(string(pemKey))

	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestParsePrivateKeyPEM_PKCS8(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	parsed, err := parsePrivateKeyPEM(string(pemKey))

	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestParsePrivateKeyPEM_InvalidPEM(t *testing.T) {
	_, err := parsePrivateKeyPEM("not a pem block")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse PEM key")
}
