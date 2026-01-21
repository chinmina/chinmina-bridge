// Package jwxtest provides test utilities for JWT operations using lestrrat-go/jwx.
// This package has no dependency on internal/jwt to avoid import cycles.
package jwxtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// JWK wraps an RSA key pair for JWT signing/verification in tests.
// Use NewJWK to create an instance.
type JWK struct {
	key        jwk.Key
	privateKey *rsa.PrivateKey
}

// NewJWK generates an RSA 2048-bit key pair for JWT signing/verification.
func NewJWK(t *testing.T) JWK {
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

	return JWK{
		key:        key,
		privateKey: privateKey,
	}
}

// Key returns the jwk.Key suitable for use with lestrrat-go/jwx.
func (j JWK) Key() jwk.Key {
	return j.key
}

// PrivateKey returns the raw *rsa.PrivateKey.
func (j JWK) PrivateKey() *rsa.PrivateKey {
	return j.privateKey
}

// PrivateKeyPEM returns the private key encoded as PEM.
func (j JWK) PrivateKeyPEM() string {
	privBytes := x509.MarshalPKCS1PrivateKey(j.privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	return string(privPEM)
}

// SetupJWKSServer creates a mock OIDC provider server that serves JWKS.
// The server responds to:
// - /.well-known/openid-configuration (OIDC discovery)
// - /.well-known/jwks.json (public key set)
//
// Returns an httptest.Server that should be closed by the caller.
func SetupJWKSServer(t *testing.T, j JWK) *httptest.Server {
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
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(wk)
		case "/.well-known/jwks.json":
			publicKey, err := jwk.PublicKeyOf(j.key)
			require.NoError(t, err, "failed to get public key")

			set := jwk.NewSet()
			err = set.AddKey(publicKey)
			require.NoError(t, err, "failed to add public key to set")

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(set)
		default:
			http.Error(w, "unexpected JWKS server request: "+r.URL.String(), http.StatusInternalServerError)
		}
	})

	server = httptest.NewServer(handler)
	return server
}

// SignToken signs a JWT token with the provided key and sets the issuer.
// The token should be configured with all desired claims before calling this function.
func SignToken(t *testing.T, j JWK, issuer string, token jwt.Token) string {
	t.Helper()

	err := token.Set(jwt.IssuerKey, issuer)
	require.NoError(t, err, "failed to set issuer")

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), j.key))
	require.NoError(t, err, "failed to sign JWT")

	return string(signed)
}

// AddTimingClaims configures a token with valid timing fields (IssuedAt, NotBefore, Expiration).
// The token is valid from 1 minute ago until 1 minute from now.
// Returns the same token for chaining.
func AddTimingClaims(token jwt.Token) jwt.Token {
	now := time.Now().UTC()

	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.NotBeforeKey, now.Add(-1*time.Minute))
	_ = token.Set(jwt.ExpirationKey, now.Add(1*time.Minute))

	return token
}
