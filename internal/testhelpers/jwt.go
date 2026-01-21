package testhelpers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// GenerateJWK generates an RSA 2048-bit key pair for JWT signing/verification.
// Returns a jwk.Key suitable for use with lestrrat-go/jwx.
func GenerateJWK(t *testing.T) jwk.Key {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate private key")

	key, err := jwk.Import(privateKey)
	require.NoError(t, err, "failed to import private key as JWK")

	err = key.Set(jwk.KeyIDKey, "test-kid")
	require.NoError(t, err, "failed to set KeyID")

	err = key.Set(jwk.AlgorithmKey, jwa.RS256())
	require.NoError(t, err, "failed to set Algorithm")

	err = key.Set(jwk.KeyUsageKey, "sig")
	require.NoError(t, err, "failed to set KeyUsage")

	return key
}

// CreateJWT signs a JWT token with the provided key.
// The token should be configured with all desired claims before calling this function.
// The issuer will be set on the token.
func CreateJWT(t *testing.T, key jwk.Key, issuer string, token jwt.Token) string {
	t.Helper()

	// Set issuer
	err := token.Set(jwt.IssuerKey, issuer)
	require.NoError(t, err, "failed to set issuer")

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err, "failed to sign JWT")

	return string(signed)
}

// SetupJWKSServer creates a mock OIDC provider server that serves JWKS.
// The server responds to:
// - /.well-known/openid-configuration (OIDC discovery)
// - /.well-known/jwks.json (public key set)
//
// Returns an httptest.Server that should be closed by the caller.
func SetupJWKSServer(t *testing.T, key jwk.Key) *httptest.Server {
	t.Helper()

	var server *httptest.Server

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.String() {
		case "/.well-known/openid-configuration":
			wk := struct {
				JWKSURI string `json:"jwks_uri"`
			}{
				JWKSURI: server.URL + "/.well-known/jwks.json",
			}
			WriteJSON(w, wk)
		case "/.well-known/jwks.json":
			publicKey, err := jwk.PublicKeyOf(key)
			require.NoError(t, err, "failed to get public key")

			set := jwk.NewSet()
			err = set.AddKey(publicKey)
			require.NoError(t, err, "failed to add public key to set")

			jsonBytes, err := json.Marshal(set)
			require.NoError(t, err, "failed to marshal JWKS")

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jsonBytes)
		default:
			http.Error(w, "unexpected JWKS server request: "+r.URL.String(), http.StatusInternalServerError)
		}
	})

	server = httptest.NewServer(handler)
	return server
}

// ValidClaims configures a token with valid timing fields (IssuedAt, NotBefore, Expiration).
// The token is valid from 1 minute ago until 1 minute from now.
// Returns the same token for chaining.
func ValidClaims(token jwt.Token) jwt.Token {
	now := time.Now().UTC()

	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.NotBeforeKey, now.Add(-1*time.Minute))
	_ = token.Set(jwt.ExpirationKey, now.Add(1*time.Minute))

	return token
}
