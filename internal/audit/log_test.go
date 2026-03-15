package audit_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/gkampitakis/go-snaps/match"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/assert"
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

		auditWritten := withSlogCapture(t)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})

		middleware := audit.Middleware()(handler)

		req, w := requestSetup()

		middleware.ServeHTTP(w, req)

		assert.True(t, *auditWritten, "audit log entry should be written")
	})

	t.Run("log written on panic", func(t *testing.T) {
		testhelpers.SetupLogger(t)

		auditWritten := withSlogCapture(t)

		var entry *audit.Entry

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, entry = audit.Context(r.Context())
			entry.Error = "failure pre-panic"
			panic("not a teapot")
		})

		middleware := audit.Middleware()(handler)

		req, w := requestSetup()

		assert.PanicsWithValue(t, "not a teapot", func() {
			middleware.ServeHTTP(w, req)
			// this will panic as it's expected that the middleware will re-panic
		})

		assert.Equal(t, "failure pre-panic; panic: not a teapot", entry.Error)
		assert.True(t, *auditWritten, "audit log entry should be written")
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

func TestAuditEndEventSnapshot(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.Level(-100),
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	original := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(original) })

	ctx, entry := audit.Context(context.Background())

	entry.Method = "POST"
	entry.Path = "/token"
	entry.Status = 200
	entry.SourceIP = "10.0.0.1"
	entry.UserAgent = "buildkite-agent/3.0"
	entry.Authorized = true
	entry.AuthSubject = "buildkite:org:acme"
	entry.AuthIssuer = "https://agent.buildkite.com"
	entry.AuthAudience = []string{"https://buildkite.com"}
	entry.AuthExpirySecs = fixedExpiry.Unix()
	entry.OrganizationSlug = "acme"
	entry.PipelineSlug = "main-pipeline"
	entry.JobID = "job-123"
	entry.BuildNumber = 42
	entry.BuildBranch = "main"
	entry.RequestedProfile = "org/repo"
	entry.RequestedRepository = "https://github.com/org/repo"
	entry.VendedRepository = "https://github.com/org/vended-repo"
	entry.Repositories = []string{"org/repo"}
	entry.Permissions = []string{"contents:read"}
	entry.ExpirySecs = fixedExpiry.Unix()
	entry.ClaimsMatched = []audit.ClaimMatch{{Claim: "pipeline_slug", Value: "main-pipeline"}}

	entry.End(ctx)()

	snaps.MatchJSON(t, buf.Bytes(),
		match.Any("authorization.expiryRemaining"),
		match.Any("token.expiryRemaining"),
	)
}

func requestSetup() (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.Header.Set("User-Agent", "kettle/1.0")

	w := httptest.NewRecorder()

	return req, w
}

type capturingHandler struct {
	auditWritten *bool
}

func (h *capturingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level == slog.LevelInfo {
		*h.auditWritten = true
	}
	return nil
}
func (h *capturingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(_ string) slog.Handler      { return h }

func withSlogCapture(t *testing.T) *bool {
	t.Helper()
	written := new(bool)
	original := slog.Default()
	slog.SetDefault(slog.New(&capturingHandler{auditWritten: written}))
	t.Cleanup(func() { slog.SetDefault(original) })
	return written
}
