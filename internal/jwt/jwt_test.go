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

	"github.com/justinas/alice"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

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
		buildToken     func() jwt.Token
		audienceCheck  string
		wantStatusCode int
		wantBodyText   string
		options        []jwtmiddleware.Option
	}{
		{
			name: "has subject",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{"audience"}, "subject", "issuer")
				tok = addCustomClaims(tok, custom(expectedOrganizationSlug, "test-pipeline"))
				return valid(tok)
			},
			audienceCheck:  "audience",
			wantStatusCode: http.StatusOK,
			wantBodyText:   "",
		},
		{
			name: "does not have subject",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{"audience"}, "", "issuer")
				tok = addCustomClaims(tok, custom(expectedOrganizationSlug, "test-pipeline"))
				return valid(tok)
			},
			audienceCheck:  "audience",
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "does not have an audience",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{}, "", "issuer")
				tok = addCustomClaims(tok, custom(expectedOrganizationSlug, "test-pipeline"))
				return valid(tok)
			},
			audienceCheck:  "an-actor-demands-an",
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "no validity period",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{"audience"}, "subject", "issuer")
				tok = addCustomClaims(tok, custom(expectedOrganizationSlug, "test-pipeline"))
				return tok
			},
			audienceCheck:  "audience",
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "mismatched organization",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{"audience"}, "subject", "issuer")
				tok = addCustomClaims(tok, custom("that dog ain't gonna hunt", "test-pipeline"))
				return valid(tok)
			},
			audienceCheck:  "audience",
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

			cfg := config.AuthorizationConfig{
				Audience:                  test.audienceCheck,
				IssuerURL:                 testServer.URL,
				BuildkiteOrganizationSlug: expectedOrganizationSlug,
			}

			token := createRequestJWT(t, jwk, testServer.URL, test.buildToken())
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

func valid(token jwt.Token) jwt.Token {
	now := time.Now().UTC()

	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.NotBeforeKey, now.Add(-1*time.Minute))
	_ = token.Set(jwt.ExpirationKey, now.Add(1*time.Minute))

	return token
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

// makeToken creates a new JWT token with standard claims
func makeToken(audience []string, subject, issuer string) jwt.Token {
	tok := jwt.New()
	if len(audience) > 0 {
		_ = tok.Set(jwt.AudienceKey, audience)
	}
	if subject != "" {
		_ = tok.Set(jwt.SubjectKey, subject)
	}
	if issuer != "" {
		_ = tok.Set(jwt.IssuerKey, issuer)
	}
	return tok
}

// addCustomClaims merges BuildkiteClaims into a token
func addCustomClaims(tok jwt.Token, claims BuildkiteClaims) jwt.Token {
	_ = tok.Set("organization_slug", claims.OrganizationSlug)
	_ = tok.Set("pipeline_slug", claims.PipelineSlug)
	_ = tok.Set("pipeline_id", claims.PipelineID)
	_ = tok.Set("build_number", claims.BuildNumber)
	_ = tok.Set("build_branch", claims.BuildBranch)
	_ = tok.Set("build_commit", claims.BuildCommit)
	_ = tok.Set("build_tag", claims.BuildTag)
	_ = tok.Set("step_key", claims.StepKey)
	_ = tok.Set("job_id", claims.JobID)
	_ = tok.Set("agent_id", claims.AgentID)
	_ = tok.Set("cluster_id", claims.ClusterID)
	_ = tok.Set("cluster_name", claims.ClusterName)
	_ = tok.Set("queue_id", claims.QueueID)
	_ = tok.Set("queue_key", claims.QueueKey)
	if claims.AgentTags != nil {
		for k, v := range claims.AgentTags {
			_ = tok.Set("agent_tag:"+k, v)
		}
	}
	return tok
}

func generateJWK(t *testing.T) jwk.Key {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate private key")

	key, err := jwk.Import(privateKey)
	require.NoError(t, err, "failed to import private key as JWK")

	_ = key.Set(jwk.KeyIDKey, "kid")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256())
	_ = key.Set(jwk.KeyUsageKey, "sig")

	return key
}

func setupTestServer(t *testing.T, key jwk.Key) (server *httptest.Server) {
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
			publicKey, err := jwk.PublicKeyOf(key)
			require.NoError(t, err, "failed to get public key")

			set := jwk.NewSet()
			err = set.AddKey(publicKey)
			require.NoError(t, err, "failed to add public key to set")

			if err := json.NewEncoder(w).Encode(set); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("was not expecting to handle the following url: %s", r.URL.String())
		}
	})

	return httptest.NewServer(handler)
}

func createRequestJWT(t *testing.T, key jwk.Key, issuer string, token jwt.Token) string {
	t.Helper()

	// Set issuer
	err := token.Set(jwt.IssuerKey, issuer)
	require.NoError(t, err, "failed to set issuer")

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err, "failed to sign JWT")

	tokenStr := string(signed)
	t.Logf("issued token=%s", tokenStr)

	return tokenStr
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
