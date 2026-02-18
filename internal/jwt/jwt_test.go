package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/lestrrat-go/jwx/v3/jwt"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/chinmina/chinmina-bridge/internal/jwt/jwxtest"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
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
				claims := custom(expectedOrganizationSlug, "test-pipeline")
				require.NoError(t, claims.SetOnToken(tok))
				return jwxtest.AddTimingClaims(tok)
			},
			audienceCheck:  "audience",
			wantStatusCode: http.StatusOK,
			wantBodyText:   "",
		},
		{
			name: "does not have subject",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{"audience"}, "", "issuer")
				claims := custom(expectedOrganizationSlug, "test-pipeline")
				require.NoError(t, claims.SetOnToken(tok))
				return jwxtest.AddTimingClaims(tok)
			},
			audienceCheck:  "audience",
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "does not have an audience",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{}, "", "issuer")
				claims := custom(expectedOrganizationSlug, "test-pipeline")
				require.NoError(t, claims.SetOnToken(tok))
				return jwxtest.AddTimingClaims(tok)
			},
			audienceCheck:  "an-actor-demands-an",
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
		{
			name: "no validity period",
			buildToken: func() jwt.Token {
				tok := makeToken([]string{"audience"}, "subject", "issuer")
				claims := custom(expectedOrganizationSlug, "test-pipeline")
				require.NoError(t, claims.SetOnToken(tok))
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
				claims := custom("that dog ain't gonna hunt", "test-pipeline")
				require.NoError(t, claims.SetOnToken(tok))
				return jwxtest.AddTimingClaims(tok)
			},
			audienceCheck:  "audience",
			wantStatusCode: http.StatusUnauthorized,
			wantBodyText:   "JWT is invalid",
		},
	}

	j := jwxtest.NewJWK(t)

	testServer := jwxtest.SetupJWKSServer(t, j)
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

			token := jwxtest.SignToken(t, j, testServer.URL, test.buildToken())
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
				// Verify Buildkite identity fields are populated from claims
				assert.Equal(t, expectedOrganizationSlug, auditEntry.OrganizationSlug)
				assert.Equal(t, "test-pipeline", auditEntry.PipelineSlug)
				assert.Equal(t, "default-jobid", auditEntry.JobID)
				assert.Equal(t, 0, auditEntry.BuildNumber)
				assert.Equal(t, "default-stepkey", auditEntry.StepKey)
				assert.Equal(t, "default-buildbranch", auditEntry.BuildBranch)
			} else {
				assert.False(t, auditEntry.Authorized)
				assert.NotEmpty(t, auditEntry.Error)
				assert.Empty(t, auditEntry.AuthIssuer)
				assert.Empty(t, auditEntry.AuthSubject)
				assert.Empty(t, auditEntry.AuthAudience)
				assert.Zero(t, auditEntry.AuthExpirySecs)
				// Verify Buildkite identity fields remain zero-valued on auth failure
				assert.Empty(t, auditEntry.OrganizationSlug)
				assert.Empty(t, auditEntry.PipelineSlug)
				assert.Empty(t, auditEntry.JobID)
				assert.Zero(t, auditEntry.BuildNumber)
				assert.Empty(t, auditEntry.StepKey)
				assert.Empty(t, auditEntry.BuildBranch)
			}
		})
	}
}

func TestAuditClaimsMiddleware_SpanAttributes(t *testing.T) {
	testhelpers.SetupLogger(t)

	// Set up span recorder to capture span attributes
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := trace.NewTracerProvider(trace.WithSpanProcessor(spanRecorder))
	otel.SetTracerProvider(tracerProvider)
	tracer := tracerProvider.Tracer("test")

	// Create test claims
	claims := &BuildkiteClaims{
		OrganizationSlug: "test-org",
		PipelineSlug:     "test-pipeline",
		JobID:            "test-job-123",
		BuildNumber:      42,
		StepKey:          "test-step",
		BuildBranch:      "test-branch",
	}

	// Set up context with claims and span
	ctx, span := tracer.Start(context.Background(), "test-span")
	ctx = ContextWithBuildkiteClaims(ctx, claims)
	ctx, _ = audit.Context(ctx)

	// Create test request and response
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Call middleware
	handler := auditClaimsMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(w, req)

	// End span explicitly to ensure it's recorded
	span.End()

	// Get recorded spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1, "expected exactly one span to be recorded")
	recordedSpan := spans[0]

	// Verify span attributes
	attrs := recordedSpan.Attributes()
	expectedAttrs := []attribute.KeyValue{
		attribute.String("buildkite.organization_slug", "test-org"),
		attribute.String("buildkite.pipeline_slug", "test-pipeline"),
		attribute.String("buildkite.job_id", "test-job-123"),
		attribute.Int("buildkite.build_number", 42),
		attribute.String("buildkite.step_key", "test-step"),
		attribute.String("buildkite.build_branch", "test-branch"),
	}

	for _, expectedAttr := range expectedAttrs {
		assert.Contains(t, attrs, expectedAttr, "span should contain attribute %s", expectedAttr.Key)
	}
}

// custom creates BuildkiteClaims with default test values for org and pipeline.
func custom(org, pipeline string) BuildkiteClaims {
	return BuildkiteClaims{
		OrganizationSlug: org,
		PipelineSlug:     pipeline,
		PipelineID:       pipeline + "--UUID",
		BuildNumber:      0,
		BuildBranch:      "default-buildbranch",
		BuildCommit:      "default-buildcommit",
		StepKey:          "default-stepkey",
		JobID:            "default-jobid",
		AgentID:          "default-agentid",
	}
}

// makeToken creates a new JWT token with standard claims.
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
