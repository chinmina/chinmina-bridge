package cli_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// endpoint is a local health endpoint that counts the requests it receives.
type endpoint struct {
	*httptest.Server
	requests atomic.Int32
	paths    chan string
}

func newEndpoint(t *testing.T, handler http.HandlerFunc) *endpoint {
	t.Helper()

	e := &endpoint{paths: make(chan string, 10)}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		e.paths <- r.URL.Path
		handler(w, r)
	}))
	t.Cleanup(e.Close)

	return e
}

func (e *endpoint) port() string {
	return strconv.Itoa(e.Listener.Addr().(*net.TCPAddr).Port)
}

func healthy(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestHealthcheck_HealthyEndpointSucceedsSilently(t *testing.T) {
	e := newEndpoint(t, healthy)
	d := &dispatch{}

	err := d.run(t, "healthcheck", "--url", e.URL+"/healthcheck")

	require.NoError(t, err)
	assert.Equal(t, int32(1), e.requests.Load())
	assert.Equal(t, 0, d.serveCalls, "a probe must not start the service")
	assert.Empty(t, d.stdout.String())
	assert.Empty(t, d.stderr.String())
}

func TestHealthcheck_UnhealthyStatusFails(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{name: "service unavailable", status: http.StatusServiceUnavailable},
		{name: "server error", status: http.StatusInternalServerError},
		{name: "not found", status: http.StatusNotFound},
		{name: "success other than OK", status: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEndpoint(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte("response-body-detail"))
			})
			d := &dispatch{}

			err := d.run(t, "healthcheck", "--url", e.URL+"/healthcheck")

			require.Error(t, err)
			assert.Contains(t, err.Error(), strconv.Itoa(tt.status))
			assert.NotContains(t, err.Error(), "response-body-detail", "the diagnostic must not dump the response")
			assert.Equal(t, int32(1), e.requests.Load(), "the probe must not retry")

			_, isUnhealthy := errors.AsType[*cli.UnhealthyError](err)
			assert.True(t, isUnhealthy, "a failed probe is reported as unhealthy, not as a usage error")
		})
	}
}

func TestHealthcheck_RedirectIsNotFollowed(t *testing.T) {
	destination := newEndpoint(t, healthy)
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/healthcheck", http.StatusFound)
	})
	d := &dispatch{}

	err := d.run(t, "healthcheck", "--url", e.URL+"/healthcheck")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
	assert.Equal(t, int32(1), e.requests.Load())
	assert.Equal(t, int32(0), destination.requests.Load(), "the redirect destination must never be contacted")
}

func TestHealthcheck_SlowEndpointFailsWithinTimeout(t *testing.T) {
	release := make(chan struct{})
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	d := &dispatch{}

	start := time.Now()
	err := d.run(t, "healthcheck", "--url", e.URL+"/healthcheck", "--timeout", "100ms")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Less(t, elapsed, time.Second, "the probe must give up at its deadline")

	_, isUnhealthy := errors.AsType[*cli.UnhealthyError](err)
	assert.True(t, isUnhealthy)
}

func TestHealthcheck_ConnectionFailureFails(t *testing.T) {
	e := newEndpoint(t, healthy)
	e.Close()
	d := &dispatch{}

	err := d.run(t, "healthcheck", "--url", e.URL+"/healthcheck")

	require.Error(t, err)

	_, isUnhealthy := errors.AsType[*cli.UnhealthyError](err)
	assert.True(t, isUnhealthy)
}

func TestHealthcheck_CallerCancellationEndsProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	})

	cmd := cli.New(cli.Options{Writer: io.Discard, ErrWriter: io.Discard})

	start := time.Now()
	err := cmd.Run(ctx, []string{"chinmina-bridge", "healthcheck", "--url", e.URL + "/healthcheck", "--timeout", "1m"})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 10*time.Second, "cancellation, not the timeout, must end the probe")
}

func TestHealthcheck_InvalidInputFailsBeforeProbing(t *testing.T) {
	e := newEndpoint(t, healthy)
	valid := e.URL + "/healthcheck"

	tests := []struct {
		name string
		args []string
	}{
		{name: "relative URL", args: []string{"--url", "/healthcheck"}},
		{name: "URL without host", args: []string{"--url", "http:///healthcheck"}},
		{name: "non-HTTP scheme", args: []string{"--url", "ftp" + strings.TrimPrefix(valid, "http")}},
		{name: "unparseable URL", args: []string{"--url", "http://[::1"}},
		{name: "zero timeout", args: []string{"--url", valid, "--timeout", "0s"}},
		{name: "negative timeout", args: []string{"--url", valid, "--timeout", "-1s"}},
		{name: "malformed timeout", args: []string{"--url", valid, "--timeout", "soon"}},
		{name: "positional argument", args: []string{"--url", valid, "extra"}},
		{name: "unknown flag", args: []string{"--url", valid, "--bogus"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &dispatch{}

			err := d.run(t, append([]string{"healthcheck"}, tt.args...)...)

			require.Error(t, err)
			assert.Equal(t, int32(0), e.requests.Load(), "invalid input must fail before any request")

			_, isUnhealthy := errors.AsType[*cli.UnhealthyError](err)
			assert.False(t, isUnhealthy, "invalid input is a usage error, not an unhealthy service")

			assert.Empty(t, d.stdout.String(), "the entry point reports the error once")
			assert.Empty(t, d.stderr.String(), "the entry point reports the error once")
		})
	}
}

func TestHealthcheck_ResolvesTarget(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		args     func(e *endpoint) []string
		expected string
	}{
		{
			name:     "port flag",
			args:     func(e *endpoint) []string { return []string{"--port", e.port()} },
			expected: "/healthcheck",
		},
		{
			name:     "port from environment",
			env:      map[string]string{"SERVER_PORT": "{port}"},
			expected: "/healthcheck",
		},
		{
			name:     "port flag takes precedence over environment",
			env:      map[string]string{"SERVER_PORT": "1"},
			args:     func(e *endpoint) []string { return []string{"--port", e.port()} },
			expected: "/healthcheck",
		},
		{
			name:     "base path flag is normalized",
			args:     func(e *endpoint) []string { return []string{"--port", e.port(), "--base-path", " api/v1/ "} },
			expected: "/api/v1/healthcheck",
		},
		{
			name:     "base path from environment",
			env:      map[string]string{"SERVER_PORT": "{port}", "SERVER_BASE_PATH": "/api"},
			expected: "/api/healthcheck",
		},
		{
			name:     "base path flag takes precedence over environment",
			env:      map[string]string{"SERVER_PORT": "{port}", "SERVER_BASE_PATH": "/ignored"},
			args:     func(e *endpoint) []string { return []string{"--base-path", "/api"} },
			expected: "/api/healthcheck",
		},
		{
			name:     "root base path is no prefix",
			args:     func(e *endpoint) []string { return []string{"--port", e.port(), "--base-path", "/"} },
			expected: "/healthcheck",
		},
		{
			name: "explicit URL ignores invalid server settings",
			env:  map[string]string{"SERVER_PORT": "not-a-port", "SERVER_BASE_PATH": "a//b"},
			args: func(e *endpoint) []string {
				return []string{"--url", e.URL + "/custom/health", "--port", "0", "--base-path", "x//y"}
			},
			expected: "/custom/health",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEndpoint(t, healthy)
			for k, v := range tt.env {
				t.Setenv(k, strings.ReplaceAll(v, "{port}", e.port()))
			}

			var args []string
			if tt.args != nil {
				args = tt.args(e)
			}

			d := &dispatch{}

			err := d.run(t, append([]string{"healthcheck"}, args...)...)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, <-e.paths)
		})
	}
}

func TestHealthcheck_InvalidServerSettingsFail(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{name: "non-numeric port", args: []string{"--port", "http"}},
		{name: "port out of range", args: []string{"--port", "65536"}},
		{name: "zero port", args: []string{"--port", "0"}},
		{name: "invalid port from environment", env: map[string]string{"SERVER_PORT": "eighty"}},
		{name: "base path with double slash", args: []string{"--base-path", "/a//b"}},
		{name: "invalid base path from environment", env: map[string]string{"SERVER_BASE_PATH": "a//b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			d := &dispatch{}

			err := d.run(t, append([]string{"healthcheck"}, tt.args...)...)

			require.Error(t, err)

			_, isUnhealthy := errors.AsType[*cli.UnhealthyError](err)
			assert.False(t, isUnhealthy, "invalid settings are a usage error, not an unhealthy service")
		})
	}
}

// The service's own default port: probing it needs the port to be free, so
// the test is skipped where something else holds it.
func TestHealthcheck_DefaultsToServiceDefaultPort(t *testing.T) {
	t.Setenv("SERVER_PORT", "")
	t.Setenv("SERVER_BASE_PATH", "")

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("default port unavailable: %v", err)
	}

	e := &endpoint{paths: make(chan string, 10)}
	e.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		e.paths <- r.URL.Path
	}))
	e.Listener = listener
	e.Start()
	t.Cleanup(e.Close)

	d := &dispatch{}

	err = d.run(t, "healthcheck")

	require.NoError(t, err)
	assert.Equal(t, "/healthcheck", <-e.paths)
}
