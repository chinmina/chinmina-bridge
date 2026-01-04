package testhelpers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// GenerateJWK generates an RSA 2048-bit key pair for JWT signing/verification.
// Returns a JSONWebKey suitable for use with go-jose.
func GenerateJWK(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("failed to generate private key")
	}

	return &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "test-kid",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

// CreateJWT signs a JWT token with the provided key and claims.
// The claims parameter accepts variadic claim objects that will be included in the token.
// The issuer is automatically added to the JWT claims.
func CreateJWT(t *testing.T, jwk *jose.JSONWebKey, issuer string, claims ...any) string {
	t.Helper()

	key := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}

	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	builder := josejwt.Signed(signer)

	for _, claim := range claims {
		builder = builder.Claims(claim)
	}

	builder = builder.Claims(josejwt.Claims{
		Issuer: issuer,
	})

	token, err := builder.Serialize()
	require.NoError(t, err)

	return token
}

// SetupJWKSServer creates a mock OIDC provider server that serves JWKS.
// The server responds to:
// - /.well-known/openid-configuration (OIDC discovery)
// - /.well-known/jwks.json (public key set)
//
// Returns an httptest.Server that should be closed by the caller.
func SetupJWKSServer(t *testing.T, jwk *jose.JSONWebKey) *httptest.Server {
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
			if err := json.NewEncoder(w).Encode(wk); err != nil {
				t.Fatal(err)
			}
		case "/.well-known/jwks.json":
			if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{jwk.Public()},
			}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unexpected JWKS server request: %s", r.URL.String())
		}
	})

	server = httptest.NewServer(handler)
	return server
}

// ValidClaims returns JWT claims with valid timing fields (IssuedAt, NotBefore, Expiry).
// The claims are valid from 1 minute ago until 1 minute from now.
func ValidClaims(claims josejwt.Claims) josejwt.Claims {
	now := time.Now().UTC()

	claims.IssuedAt = josejwt.NewNumericDate(now)
	claims.NotBefore = josejwt.NewNumericDate(now.Add(-1 * time.Minute))
	claims.Expiry = josejwt.NewNumericDate(now.Add(1 * time.Minute))

	return claims
}

