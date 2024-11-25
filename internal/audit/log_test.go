package audit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
