package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var defaultExpiry = time.Date(2024, time.May, 7, 17, 59, 36, 0, time.UTC)

func TestHandlers_RequireClaims(t *testing.T) {
	cases := []struct {
		name    string
		handler http.Handler
	}{
		{
			name:    "postToken",
			handler: handlePostToken(nil),
		},
		{
			name:    "postGitCredentials",
			handler: handlePostGitCredentials(nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/not-applicable", nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()

			handler := handlePostToken(nil)

			assert.PanicsWithValue(t, "Buildkite claims not present in context, likely used outside of the JWT middleware", func() {
				handler.ServeHTTP(rr, req)
			})
		})
	}
}

func TestHandlePostToken_ReturnsTokenOnSuccess(t *testing.T) {
	tokenVendor := tv("expected-token-value")

	ctx := claimsContext()

	req, err := http.NewRequest("POST", "/token", nil)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	respBody := vendor.ProfileToken{}
	err = json.Unmarshal(rr.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:            "expected-token-value",
		Expiry:           defaultExpiry,
		OrganizationSlug: "organization-slug",
		Profile:          "default",
	}, &respBody)
}

func TestHandlePostToken_ReturnsFailureOnVendorFailure(t *testing.T) {
	tokenVendor := tvFails(errors.New("vendor failure"))

	ctx := claimsContext()

	req, err := http.NewRequest("POST", "/token", nil)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	// important to know that internal details aren't part of the error response
	assert.Equal(t, "Internal Server Error\n", rr.Body.String())
}

func TestHandlePostGitCredentials_ReturnsTokenOnSuccess(t *testing.T) {
	tokenVendor := tv("expected-token-value")

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	credentialhandler.WriteProperties(m, body)
	req, err := http.NewRequest("POST", "/git-credentials", body)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

	respBody := rr.Body.String()
	assert.Equal(t, "protocol=https\nhost=github.com\npath=org/repo\nusername=x-access-token\npassword=expected-token-value\npassword_expiry_utc=1715104776\n\n", respBody)
}

func TestHandlePostGitCredentials_ReturnsEmptySuccessWhenNoToken(t *testing.T) {
	tokenVendor := vendor.ProfileTokenVendor(func(_ context.Context, ref profile.ProfileRef, repoUrl string) (*vendor.ProfileToken, error) {
		return nil, nil
	})

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	credentialhandler.WriteProperties(m, body)
	req, err := http.NewRequest("POST", "/git-credentials", body)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor)
	handler.ServeHTTP(rr, req)

	// assert
	r := rr.Result()
	assert.Equal(t, http.StatusOK, r.StatusCode)
	assert.Equal(t, "text/plain", r.Header.Get("Content-Type"))
	assert.Equal(t, "0", r.Header.Get("Content-Length"))
	assert.Equal(t, int64(0), r.ContentLength)

	respBody := rr.Body.String()
	assert.Equal(t, "", respBody)
}

func TestHandlePostGitCredentials_ReturnsFailureOnInvalidRequest(t *testing.T) {
	tokenVendor := tv("expected-token-value")

	ctx := claimsContext()

	req, err := http.NewRequest("POST", "/git-credentials", nil)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	// important to know that internal details aren't part of the error response
	assert.Equal(t, "Bad Request\n", rr.Body.String())
}

func TestHandlePostGitCredentials_ReturnsFailureOnReadFailure(t *testing.T) {
	tokenVendor := tv("expected-token-value")

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	credentialhandler.WriteProperties(m, body)

	req, err := http.NewRequest("POST", "/git-credentials", body)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := maxRequestSize(1)(
		// use the request size limit to force an error in the credentials handler
		handlePostGitCredentials(tokenVendor),
	)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	// important to know that internal details aren't part of the error response
	assert.Equal(t, "Internal Server Error\n", rr.Body.String())
}

func TestHandlePostGitCredentials_ReturnsFailureOnVendorFailure(t *testing.T) {
	tokenVendor := tvFails(errors.New("vendor failure"))

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	credentialhandler.WriteProperties(m, body)
	req, err := http.NewRequest("POST", "/git-credentials", body)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	// important to know that internal details aren't part of the error response
	assert.Equal(t, "Internal Server Error\n", rr.Body.String())
}

func TestHandleHealthCheck_Success(t *testing.T) {
	ctx := context.Background()

	req, err := http.NewRequest("GET", "/healthcheck", nil)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handleHealthCheck()
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

	respBody := rr.Body.String()
	assert.Equal(t, "OK", respBody)
}

func tv(token string) vendor.ProfileTokenVendor {
	return vendor.ProfileTokenVendor(func(_ context.Context, ref profile.ProfileRef, repoUrl string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Token:                  token,
			Expiry:                 defaultExpiry,
			Profile:                ref.ShortString(),
			OrganizationSlug:       ref.Organization,
			RequestedRepositoryURL: repoUrl,
		}, nil
	})
}

func TestHandlePostGitCredentialsWithProfile_ReturnsTokenOnSuccess(t *testing.T) {
	tokenVendor := tv("expected-token-value")

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	credentialhandler.WriteProperties(m, body)
	req, err := http.NewRequest("POST", "/organization/git-credentials/test-profile", body)
	require.NoError(t, err)

	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

	respBody := rr.Body.String()
	assert.Equal(t, "protocol=https\nhost=github.com\npath=org/repo\nusername=x-access-token\npassword=expected-token-value\npassword_expiry_utc=1715104776\n\n", respBody)
}

func tvFails(err error) vendor.ProfileTokenVendor {
	return vendor.ProfileTokenVendor(func(_ context.Context, ref profile.ProfileRef, repoUrl string) (*vendor.ProfileToken, error) {
		return nil, err
	})
}

func claimsContext() context.Context {
	ctx := context.Background()

	ctx = jwt.ContextWithClaims(ctx, &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Issuer: "https://buildkite.com",
		},
		CustomClaims: &jwt.BuildkiteClaims{
			OrganizationSlug: "organization-slug",
			PipelineSlug:     "pipeline-slug",
			PipelineID:       "pipeline-id",
		},
	})

	return ctx
}

func TestMaxRequestSizeMiddleware(t *testing.T) {

	mw := maxRequestSize(10)

	var readError error
	var readBytes int64

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readBytes, readError = io.CopyN(io.Discard, r.Body, 5*1024*1024)

		status := http.StatusOK
		if readError != nil {
			status = http.StatusBadRequest
		}

		w.WriteHeader(status)
	})

	handler := mw(innerHandler)

	body := bytes.NewBufferString("0123456789n123456789")
	req, err := http.NewRequest("POST", "/git-credentials", body)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	// act
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.ErrorContains(t, readError, "http: request body too large")
	assert.Equal(t, int64(10), readBytes)

	respBody := rr.Body.String()
	assert.Equal(t, "", respBody)
}
