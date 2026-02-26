package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {

	t.Run("captures request info and configures context", func(t *testing.T) {
		testhelpers.SetupLogger(t)

		testAgent := "kettle/1.0"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			entry := audit.Log(ctx)
			assert.Equal(t, testAgent, entry.UserAgent)

			w.WriteHeader(http.StatusTeapot)
		})

		middleware := audit.Middleware()(handler)

		req, w := requestSetup()
		req.Header.Set("User-Agent", testAgent)

		middleware.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTeapot, w.Result().StatusCode)
	})

	t.Run("captures status code", func(t *testing.T) {
		testhelpers.SetupLogger(t)

		var capturedContext context.Context
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedContext = r.Context()
			w.WriteHeader(http.StatusTeapot)
		})

		req, w := requestSetup()

		middleware := audit.Middleware()(handler)

		middleware.ServeHTTP(w, req)

		entry := audit.Log(capturedContext)

		assert.Equal(t, http.StatusTeapot, w.Result().StatusCode)
		assert.Equal(t, http.StatusTeapot, entry.Status)
	})

	t.Run("log written", func(t *testing.T) {
		testhelpers.SetupLogger(t)

		auditWritten := false

		ctx := withLogHook(
			context.Background(),
			zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, msg string) {
				if level == audit.Level {
					auditWritten = true
				}
			}),
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})

		middleware := audit.Middleware()(handler)

		req, w := requestSetup()

		middleware.ServeHTTP(w, req.WithContext(ctx))

		assert.True(t, auditWritten, "audit log entry should be written")
	})

	t.Run("log written on panic", func(t *testing.T) {
		testhelpers.SetupLogger(t)

		auditWritten := false

		ctx := withLogHook(
			context.Background(),
			zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, msg string) {
				if level == audit.Level {
					auditWritten = true
				}
			}),
		)

		var entry *audit.Entry

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, entry = audit.Context(r.Context())
			entry.Error = "failure pre-panic"
			panic("not a teapot")
		})

		middleware := audit.Middleware()(handler)

		req, w := requestSetup()

		assert.PanicsWithValue(t, "not a teapot", func() {
			middleware.ServeHTTP(w, req.WithContext(ctx))
			// this will panic as it's expected that the middleware will re-panic
		})

		assert.Equal(t, "failure pre-panic; panic: not a teapot", entry.Error)
		assert.True(t, auditWritten, "audit log entry should be written")
	})
}

func TestAuditing(t *testing.T) {
	testhelpers.SetupLogger(t)

	ctx := context.Background()
	r, _ := requestSetup()

	_, e := audit.Context(ctx)
	e.Begin(r)
	e.End(ctx)()

	assert.NotEmpty(t, e.SourceIP)
	e.SourceIP = "" // clear IP as it will change between tests

	assert.Equal(t, &audit.Entry{Method: "GET", Path: "/foo", UserAgent: "kettle/1.0", Status: 200}, e)
}

func requestSetup() (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.Header.Set("User-Agent", "kettle/1.0")

	w := httptest.NewRecorder()

	return req, w
}

func withLogHook(ctx context.Context, hook zerolog.HookFunc) context.Context {
	testLog := log.Logger.With().Logger().Hook(hook)
	return testLog.WithContext(ctx)
}

func TestTokenFieldsSerialization(t *testing.T) {
	testhelpers.SetupLogger(t)

	serializeToken := func(t *testing.T, entry audit.Entry) map[string]any {
		t.Helper()
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		logger.Log().EmbedObject(&entry).Send()

		var result map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

		token, ok := result["token"].(map[string]any)
		require.True(t, ok, "expected 'token' dict in log output")
		return token
	}

	t.Run("successful matches serialized", func(t *testing.T) {
		token := serializeToken(t, audit.Entry{
			ClaimsMatched: []audit.ClaimMatch{
				{Claim: "pipeline_slug", Value: "silk-prod"},
				{Claim: "build_branch", Value: "main"},
			},
		})

		matches, ok := token["matches"].([]any)
		require.True(t, ok, "expected 'matches' array")
		require.Len(t, matches, 2)

		first := matches[0].(map[string]any)
		assert.Equal(t, "pipeline_slug", first["claim"])
		assert.Equal(t, "silk-prod", first["value"])

		second := matches[1].(map[string]any)
		assert.Equal(t, "build_branch", second["claim"])
		assert.Equal(t, "main", second["value"])
	})

	t.Run("failed matches serialized", func(t *testing.T) {
		token := serializeToken(t, audit.Entry{
			ClaimsFailed: []audit.ClaimFailure{
				{Claim: "pipeline_slug", Pattern: ".*-release", Value: "silk-staging"},
			},
		})

		patterns, ok := token["attemptedPatterns"].([]any)
		require.True(t, ok, "expected 'attemptedPatterns' array")
		require.Len(t, patterns, 1)

		first := patterns[0].(map[string]any)
		assert.Equal(t, "pipeline_slug", first["claim"])
		assert.Equal(t, ".*-release", first["pattern"])
		assert.Equal(t, "silk-staging", first["value"])
	})

	t.Run("empty matches array serialized", func(t *testing.T) {
		token := serializeToken(t, audit.Entry{
			ClaimsMatched: []audit.ClaimMatch{},
		})

		matches, ok := token["matches"].([]any)
		require.True(t, ok, "expected 'matches' array")
		assert.Empty(t, matches)
	})

	t.Run("nil matches omits token dict entirely", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		entry := audit.Entry{}
		logger.Log().EmbedObject(&entry).Send()

		var result map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
		assert.NotContains(t, result, "token")
	})

	t.Run("both matches and failures", func(t *testing.T) {
		token := serializeToken(t, audit.Entry{
			ClaimsMatched: []audit.ClaimMatch{
				{Claim: "pipeline_slug", Value: "silk-prod"},
			},
			ClaimsFailed: []audit.ClaimFailure{
				{Claim: "build_branch", Pattern: "main", Value: "feature"},
			},
		})
		assert.Contains(t, token, "matches")
		assert.Contains(t, token, "attemptedPatterns")
	})

	t.Run("repository fields", func(t *testing.T) {
		token := serializeToken(t, audit.Entry{
			RequestedRepository: "https://github.com/org/requested-repo",
			VendedRepository:    "https://github.com/org/vended-repo",
		})
		assert.Equal(t, "https://github.com/org/requested-repo", token["requestedRepository"])
		assert.Equal(t, "https://github.com/org/vended-repo", token["vendedRepository"])
	})
}

func TestNestedDictSerialization(t *testing.T) {
	testhelpers.SetupLogger(t)

	entry := audit.Entry{
		Method:           "POST",
		Path:             "/token",
		Status:           200,
		SourceIP:         "10.0.0.1",
		UserAgent:        "test/1.0",
		OrganizationSlug: "acme",
		PipelineSlug:     "main-pipeline",
		JobID:            "job-123",
		BuildNumber:      42,
		BuildBranch:      "main",
		Authorized:       true,
		AuthSubject:      "buildkite:org:acme",
	}

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	logger.Log().EmbedObject(&entry).Send()

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	t.Run("request fields nested", func(t *testing.T) {
		request, ok := result["request"].(map[string]any)
		require.True(t, ok, "expected 'request' dict in log output")
		assert.Equal(t, "POST", request["method"])
		assert.Equal(t, "/token", request["path"])
		assert.Equal(t, float64(200), request["status"])
		assert.Equal(t, "10.0.0.1", request["sourceIP"])
		assert.Equal(t, "test/1.0", request["userAgent"])
	})

	t.Run("pipeline fields nested", func(t *testing.T) {
		pipeline, ok := result["pipeline"].(map[string]any)
		require.True(t, ok, "expected 'pipeline' dict in log output")
		assert.Equal(t, "acme", pipeline["organizationSlug"])
		assert.Equal(t, "main-pipeline", pipeline["pipelineSlug"])
		assert.Equal(t, "job-123", pipeline["jobID"])
		assert.Equal(t, float64(42), pipeline["buildNumber"])
		assert.Equal(t, "main", pipeline["buildBranch"])
	})

	t.Run("authorization fields nested", func(t *testing.T) {
		auth, ok := result["authorization"].(map[string]any)
		require.True(t, ok, "expected 'authorization' dict in log output")
		assert.Equal(t, true, auth["authorized"])
		assert.Equal(t, "buildkite:org:acme", auth["subject"])
	})

	t.Run("error omitted when empty", func(t *testing.T) {
		assert.NotContains(t, result, "error")
	})

	t.Run("error present when set", func(t *testing.T) {
		errorEntry := audit.Entry{Error: "something broke"}
		var errBuf bytes.Buffer
		errLogger := zerolog.New(&errBuf)
		errLogger.Log().EmbedObject(&errorEntry).Send()

		var errResult map[string]any
		require.NoError(t, json.Unmarshal(errBuf.Bytes(), &errResult))
		assert.Equal(t, "something broke", errResult["error"])
	})
}

func TestOptionalDictElision(t *testing.T) {
	testhelpers.SetupLogger(t)

	serialize := func(t *testing.T, entry audit.Entry) map[string]any {
		t.Helper()
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		logger.Log().EmbedObject(&entry).Send()

		var result map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
		return result
	}

	t.Run("empty entry omits optional dicts without unconditional fields", func(t *testing.T) {
		result := serialize(t, audit.Entry{})
		assert.Contains(t, result, "request", "request dict is always present")
		assert.Contains(t, result, "authorization", "authorization dict is always present (contains authorized bool)")
		assert.NotContains(t, result, "pipeline")
		assert.NotContains(t, result, "token")
		assert.NotContains(t, result, "error")
	})

	t.Run("pipeline present when any pipeline field set", func(t *testing.T) {
		result := serialize(t, audit.Entry{PipelineSlug: "deploy"})
		pipeline, ok := result["pipeline"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "deploy", pipeline["pipelineSlug"])
	})

	t.Run("pipeline absent when all pipeline fields empty", func(t *testing.T) {
		result := serialize(t, audit.Entry{Method: "GET"})
		assert.NotContains(t, result, "pipeline")
	})

	t.Run("authorization present when auth subject set", func(t *testing.T) {
		result := serialize(t, audit.Entry{
			Authorized:  true,
			AuthSubject: "buildkite:org:acme",
		})
		auth, ok := result["authorization"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, true, auth["authorized"])
		assert.Equal(t, "buildkite:org:acme", auth["subject"])
	})

	t.Run("authorization always present due to authorized bool", func(t *testing.T) {
		result := serialize(t, audit.Entry{Authorized: true})
		auth, ok := result["authorization"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, true, auth["authorized"])
	})

	t.Run("authorization present via audience", func(t *testing.T) {
		result := serialize(t, audit.Entry{
			AuthAudience: []string{"https://buildkite.com"},
		})
		auth, ok := result["authorization"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, false, auth["authorized"])
		audiences, ok := auth["audience"].([]any)
		require.True(t, ok)
		assert.Equal(t, "https://buildkite.com", audiences[0])
	})

	t.Run("token present when repository requested", func(t *testing.T) {
		result := serialize(t, audit.Entry{
			RequestedRepository: "https://github.com/org/repo",
		})
		token, ok := result["token"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "https://github.com/org/repo", token["requestedRepository"])
	})

	t.Run("token absent when no token fields set", func(t *testing.T) {
		result := serialize(t, audit.Entry{AuthSubject: "sub"})
		assert.NotContains(t, result, "token")
	})
}

func TestFullyPopulatedEntry(t *testing.T) {
	testhelpers.SetupLogger(t)

	authExpiry := time.Now().Add(1 * time.Hour)
	tokenExpiry := time.Now().Add(45 * time.Minute)

	entry := audit.Entry{
		Method:              "POST",
		Path:                "/token",
		Status:              200,
		SourceIP:            "10.0.0.1",
		UserAgent:           "test/1.0",
		OrganizationSlug:    "acme",
		PipelineSlug:        "main-pipeline",
		JobID:               "job-123",
		BuildNumber:         42,
		BuildBranch:         "main",
		Authorized:          true,
		AuthSubject:         "buildkite:org:acme",
		AuthIssuer:          "https://agent.buildkite.com",
		AuthAudience:        []string{"https://buildkite.com"},
		AuthExpirySecs:      authExpiry.Unix(),
		RequestedProfile:    "org/repo",
		RequestedRepository: "https://github.com/org/repo",
		VendedRepository:    "https://github.com/org/vended-repo",
		Repositories:        []string{"org/repo"},
		Permissions:         []string{"contents:read"},
		ExpirySecs:          tokenExpiry.Unix(),
		ClaimsMatched:       []audit.ClaimMatch{{Claim: "pipeline_slug", Value: "main-pipeline"}},
		ClaimsFailed:        []audit.ClaimFailure{{Claim: "build_branch", Pattern: "release-.*", Value: "main"}},
		Error:               "partial failure",
	}

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	logger.Log().EmbedObject(&entry).Send()

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	t.Run("all top-level keys present", func(t *testing.T) {
		assert.Contains(t, result, "request")
		assert.Contains(t, result, "pipeline")
		assert.Contains(t, result, "authorization")
		assert.Contains(t, result, "token")
		assert.Equal(t, "partial failure", result["error"])
	})

	t.Run("authorization contains all fields", func(t *testing.T) {
		auth, ok := result["authorization"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, true, auth["authorized"])
		assert.Equal(t, "buildkite:org:acme", auth["subject"])
		assert.Equal(t, "https://agent.buildkite.com", auth["issuer"])

		audiences, ok := auth["audience"].([]any)
		require.True(t, ok)
		assert.Equal(t, []any{"https://buildkite.com"}, audiences)

		assert.Contains(t, auth, "expiry")
		assert.Contains(t, auth, "expiryRemaining")
	})

	t.Run("token contains all fields", func(t *testing.T) {
		token, ok := result["token"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "org/repo", token["requestedProfile"])
		assert.Equal(t, "https://github.com/org/repo", token["requestedRepository"])
		assert.Equal(t, "https://github.com/org/vended-repo", token["vendedRepository"])

		repos, ok := token["repositories"].([]any)
		require.True(t, ok)
		assert.Equal(t, []any{"org/repo"}, repos)

		perms, ok := token["permissions"].([]any)
		require.True(t, ok)
		assert.Equal(t, []any{"contents:read"}, perms)

		assert.Contains(t, token, "expiry")
		assert.Contains(t, token, "expiryRemaining")
		assert.Contains(t, token, "matches")
		assert.Contains(t, token, "attemptedPatterns")
	})
}

func TestExpiryFields(t *testing.T) {
	testhelpers.SetupLogger(t)

	serialize := func(t *testing.T, entry audit.Entry) map[string]any {
		t.Helper()
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		logger.Log().EmbedObject(&entry).Send()

		var result map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
		return result
	}

	t.Run("auth expiry present when AuthExpirySecs set", func(t *testing.T) {
		future := time.Now().Add(time.Hour).Unix()
		result := serialize(t, audit.Entry{AuthExpirySecs: future})
		auth, ok := result["authorization"].(map[string]any)
		require.True(t, ok)
		assert.Contains(t, auth, "expiry")
		assert.Contains(t, auth, "expiryRemaining")
	})

	t.Run("auth expiry absent when AuthExpirySecs zero", func(t *testing.T) {
		result := serialize(t, audit.Entry{})
		auth, ok := result["authorization"].(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, auth, "expiry")
		assert.NotContains(t, auth, "expiryRemaining")
	})

	t.Run("token expiry present when ExpirySecs set", func(t *testing.T) {
		future := time.Now().Add(time.Hour).Unix()
		result := serialize(t, audit.Entry{
			ExpirySecs:          future,
			RequestedRepository: "repo", // trigger token dict
		})
		token, ok := result["token"].(map[string]any)
		require.True(t, ok)
		assert.Contains(t, token, "expiry")
		assert.Contains(t, token, "expiryRemaining")
	})

	t.Run("token expiry absent when ExpirySecs zero", func(t *testing.T) {
		result := serialize(t, audit.Entry{
			RequestedRepository: "repo",
		})
		token, ok := result["token"].(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, token, "expiry")
		assert.NotContains(t, token, "expiryRemaining")
	})
}
