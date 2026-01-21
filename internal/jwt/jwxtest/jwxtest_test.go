package jwxtest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/jwt/jwxtest"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWK(t *testing.T) {
	j := jwxtest.NewJWK(t)

	// Verify key properties
	kid, ok := j.Key().KeyID()
	require.True(t, ok)
	assert.Equal(t, "test-kid", kid)

	alg, ok := j.Key().Algorithm()
	require.True(t, ok)
	assert.Equal(t, "RS256", alg.String())

	usage, ok := j.Key().KeyUsage()
	require.True(t, ok)
	assert.Equal(t, "sig", usage)
}

func TestJWK_PrivateKey(t *testing.T) {
	j := jwxtest.NewJWK(t)

	// Verify private key is accessible
	require.NotNil(t, j.PrivateKey())
	assert.Equal(t, 2048, j.PrivateKey().N.BitLen())
}

func TestJWK_PrivateKeyPEM(t *testing.T) {
	j := jwxtest.NewJWK(t)

	pem := j.PrivateKeyPEM()

	// Verify PEM format
	assert.True(t, strings.HasPrefix(pem, "-----BEGIN RSA PRIVATE KEY-----"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(pem), "-----END RSA PRIVATE KEY-----"))
}

func TestSetupJWKSServer(t *testing.T) {
	j := jwxtest.NewJWK(t)
	server := jwxtest.SetupJWKSServer(t, j)
	defer server.Close()

	t.Run("openid-configuration", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/.well-known/openid-configuration", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var config struct {
			JWKSURI string `json:"jwks_uri"`
		}
		err = json.NewDecoder(resp.Body).Decode(&config)
		require.NoError(t, err)
		assert.Equal(t, server.URL+"/.well-known/jwks.json", config.JWKSURI)
	})

	t.Run("jwks", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/.well-known/jwks.json", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		set, err := jwk.ParseReader(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, 1, set.Len())
	})

	t.Run("unknown endpoint returns error", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/unknown", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

func TestSignToken(t *testing.T) {
	j := jwxtest.NewJWK(t)
	server := jwxtest.SetupJWKSServer(t, j)
	defer server.Close()

	token := jwt.New()
	_ = token.Set(jwt.SubjectKey, "test-subject")

	signed := jwxtest.SignToken(t, j, server.URL, token)

	// Verify the token can be parsed and has expected claims
	parsed, err := jwt.ParseString(signed, jwt.WithVerify(false))
	require.NoError(t, err)

	iss, ok := parsed.Issuer()
	require.True(t, ok)
	assert.Equal(t, server.URL, iss)

	sub, ok := parsed.Subject()
	require.True(t, ok)
	assert.Equal(t, "test-subject", sub)
}

func TestAddTimingClaims(t *testing.T) {
	token := jwt.New()
	before := time.Now().UTC()

	result := jwxtest.AddTimingClaims(token)

	after := time.Now().UTC()

	// Verify timing claims are set within expected window
	iat, ok := result.IssuedAt()
	require.True(t, ok)
	assert.True(t, !iat.Before(before) && !iat.After(after), "IssuedAt should be between before and after")

	nbf, ok := result.NotBefore()
	require.True(t, ok)
	assert.True(t, nbf.Before(before), "NotBefore should be before test started")

	exp, ok := result.Expiration()
	require.True(t, ok)
	assert.True(t, exp.After(after), "Expiration should be after test ended")

	// Verify same token is returned for chaining
	assert.Same(t, token, result)
}
