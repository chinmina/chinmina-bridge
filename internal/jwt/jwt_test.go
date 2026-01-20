package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/justinas/alice"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
Portions of this file copied from:
	https://github.com/auth0/go-jwt-middleware/blob/b4b1b5f6d1b1eb3c7f4538a29f2caf2889693619/examples/http-jwks-example/main_test.go

Usage licensed under the MIT License (MIT) (see text at end of file).

All modifications are released under the GPL 3.0 license as documented in the project root.
*/

func TestMiddleware(t *testing.T) {
	expectedOrganizationSlug := "test-organization"

	testCases := []struct {
		name           string
		claims         jwt.Claims
		customClaims   BuildkiteClaims
		wantStatusCode int
		wantBodyText   string
		options        []jwtmiddleware.Option
	}{
		{
			name: "has subject",
			claims: valid(jwt.Claims{
				Audience: []string{"audience"},
				Subject:  "subject",
				Issuer:   "issuer",
			}),
			customClaims:   custom(expectedOrganizationSlug, "test-pipeline"),
			wantStatusCode: http.StatusOK,
			wantBodyText:   "",
		},
		{
			name: "does not have subject",
			claims: valid(jwt.Claims{
				Audience: []string{"audience"},
				Subject:  "",
				Issuer:   "issuer",
			}),
			customClaims:   custom(expectedOrganizationSlug, "test-pipeline"),
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "does not have an audience",
			claims: valid(jwt.Claims{
				Audience: []string{},
				Subject:  "",
				Issuer:   "issuer",
			}),
			customClaims:   custom(expectedOrganizationSlug, "test-pipeline"),
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "no validity period",
			claims: jwt.Claims{
				Audience: []string{"audience"},
				Subject:  "subject",
				Issuer:   "issuer",
			},
			customClaims:   custom(expectedOrganizationSlug, "test-pipeline"),
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "mismatched organization",
			claims: valid(jwt.Claims{
				Audience: []string{"audience"},
				Subject:  "subject",
				Issuer:   "issuer",
			}),
			customClaims:   custom("that dog ain't gonna hunt", "test-pipeline"),
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
	}

	jwk := generateJWK(t)

	testServer := setupTestServer(t, jwk)
	defer testServer.Close()

	successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testhelpers.SetupLogger(t)

			ctx, _ := audit.Context(context.Background())

			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "", nil)
			require.NoError(t, err)

			audience := "an-actor-demands-an"
			if len(test.claims.Audience) > 0 {
				audience = test.claims.Audience[0]
			}
			cfg := config.AuthorizationConfig{
				Audience:                  audience,
				IssuerURL:                 testServer.URL,
				BuildkiteOrganizationSlug: expectedOrganizationSlug,
			}

			token := createRequestJWT(t, jwk, testServer.URL, test.claims, test.customClaims)
			request.Header.Set("Authorization", "Bearer "+token)

			responseRecorder := httptest.NewRecorder()

			authMiddleware, err := Middleware(cfg, test.options...)
			require.NoError(t, err)

			testMiddleware := alice.New(audit.Middleware(), authMiddleware)

			handler := testMiddleware.Then(successHandler)
			handler.ServeHTTP(responseRecorder, request)

			assert.Equal(t, test.wantStatusCode, responseRecorder.Code)
			assert.Contains(t, responseRecorder.Body.String(), test.wantBodyText)

			// once the request has been processed, the audit log should have the necessary details
			auditEntry := audit.Log(ctx)
			if test.wantStatusCode == http.StatusOK {
				assert.True(t, auditEntry.Authorized)
				assert.Empty(t, auditEntry.Error)
				assert.NotEmpty(t, auditEntry.AuthIssuer)
				assert.Equal(t, "subject", auditEntry.AuthSubject)
				assert.ElementsMatch(t, []string{"audience"}, auditEntry.AuthAudience)
				assert.NotZero(t, auditEntry.AuthExpirySecs)
			} else {
				assert.False(t, auditEntry.Authorized)
				assert.NotEmpty(t, auditEntry.Error)
				assert.Empty(t, auditEntry.AuthIssuer)
				assert.Empty(t, auditEntry.AuthSubject)
				assert.Empty(t, auditEntry.AuthAudience)
				assert.Zero(t, auditEntry.AuthExpirySecs)
			}
		})
	}
}

func valid(claims jwt.Claims) jwt.Claims {
	now := time.Now().UTC()

	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now.Add(-1 * time.Minute))
	claims.Expiry = jwt.NewNumericDate(now.Add(1 * time.Minute))

	return claims
}

func custom(org, pipeline string) BuildkiteClaims {
	claims := BuildkiteClaims{
		BuildNumber: 0,
		BuildBranch: "default-buildbranch",
		BuildCommit: "default-buildcommit",
		StepKey:     "default-stepkey",
		JobID:       "default-jobid",
		AgentID:     "default-agentid",
	}

	claims.OrganizationSlug = org
	claims.PipelineSlug = pipeline
	claims.PipelineID = pipeline + "--UUID"

	return claims
}

func generateJWK(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("failed to generate private key")
	}

	return &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "kid",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

func setupTestServer(t *testing.T, jwk *jose.JSONWebKey) (server *httptest.Server) {
	t.Helper()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			t.Fatalf("was not expecting to handle the following url: %s", r.URL.String())
		}
	})

	return httptest.NewServer(handler)
}

func createRequestJWT(t *testing.T, jwk *jose.JSONWebKey, issuer string, claims ...any) string {
	t.Helper()

	key := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}

	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	builder := jwt.Signed(signer)

	for _, claim := range claims {
		builder = builder.Claims(claim)
	}

	builder = builder.Claims(jwt.Claims{
		Issuer: issuer,
	})

	token, err := builder.Serialize()
	require.NoError(t, err)

	t.Logf("issued token=%s", token)

	return token
}

/*
Portions of this file copied from https://github.com/auth0/go-jwt-middleware/blob/b4b1b5f6d1b1eb3c7f4538a29f2caf2889693619/examples/http-jwks-example/main.go

Those portions are licensed under the MIT License (MIT) as follows:

The MIT License (MIT)

Copyright (c) 2015 Auth0, Inc. <support@auth0.com> (http://auth0.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
