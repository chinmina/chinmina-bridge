package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var defaultExpiry = time.Date(2024, time.May, 7, 17, 59, 36, 0, time.UTC)

// testBuilder returns the default ProfileRefBuilder wired with a nil store
// (sufficient for tests that exercise handler plumbing without needing
// type-aware scope validation — that is covered in builder-unit tests).
func testBuilder(expectedType profile.ProfileType) ProfileRefBuilder {
	return NewProfileRefBuilder(nil, expectedType)
}

func TestHandlers_RequireClaims(t *testing.T) {
	// The builder's call to jwt.RequireBuildkiteClaimsFromContext panics when
	// claims are absent — a defence-in-depth signal that the JWT middleware
	// was bypassed. For /token the builder runs first; for /git-credentials
	// the body is read first, so we send a valid body to reach the builder.
	validGitCredsBody := func() *bytes.Buffer {
		m := credentialhandler.NewMap(3)
		m.Set("protocol", "https")
		m.Set("host", "github.com")
		m.Set("path", "org/repo")
		b := &bytes.Buffer{}
		require.NoError(t, credentialhandler.WriteProperties(m, b))
		return b
	}

	cases := []struct {
		name    string
		handler http.Handler
		body    io.Reader
	}{
		{
			name:    "postToken",
			handler: handlePostToken(nil, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo),
			body:    nil,
		},
		{
			name:    "postGitCredentials",
			handler: handlePostGitCredentials(nil, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo),
			body:    validGitCredsBody(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), "POST", "/not-applicable", tc.body)
			require.NoError(t, err)

			rr := httptest.NewRecorder()

			assert.PanicsWithValue(t, "Buildkite claims not present in context, likely used outside of the JWT middleware", func() {
				tc.handler.ServeHTTP(rr, req)
			})
		})
	}
}

func TestHandlePostToken_ReturnsTokenOnSuccess(t *testing.T) {
	tokenVendor := tv("expected-token-value")

	ctx := claimsContext()

	req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
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
		Profile:          "repo:default",
	}, &respBody)
}

func TestHandlePostToken_ReturnsFailureOnVendorFailure(t *testing.T) {
	tokenVendor := tvFails(errors.New("vendor failure"))

	ctx := claimsContext()

	req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var respBody ErrorResponse
	err = json.Unmarshal(rr.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, ErrorResponse{Error: "Internal Server Error"}, respBody)
}

func TestHandlePostTokenWithProfile_ReturnsTokenOnSuccess(t *testing.T) {
	cases := []struct {
		name            string
		profileParam    string
		expectedProfile string
	}{
		{
			name:            "repo profile without prefix",
			profileParam:    "my-profile",
			expectedProfile: "repo:my-profile",
		},
		{
			name:            "repo profile with prefix",
			profileParam:    "repo:my-profile",
			expectedProfile: "repo:my-profile",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenVendor := tv("expected-token-value")

			ctx := claimsContext()

			req, err := http.NewRequestWithContext(ctx, "POST", "/token/"+tc.profileParam, nil)
			require.NoError(t, err)

			req.SetPathValue("profile", tc.profileParam)
			rr := httptest.NewRecorder()

			// act
			handler := handlePostToken(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
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
				Profile:          tc.expectedProfile,
			}, &respBody)
		})
	}
}

func TestHandlePostGitCredentials_ReturnsTokenOnSuccess(t *testing.T) {
	tokenVendor := tv("expected-token-value")

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	require.NoError(t, credentialhandler.WriteProperties(m, body))
	req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials", body)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

	respBody := rr.Body.String()
	assert.Equal(t, "protocol=https\nhost=github.com\npath=org/repo\nusername=x-access-token\npassword=expected-token-value\npassword_expiry_utc=1715104776\n\n", respBody)
}

func TestHandlePostGitCredentials_ReturnsEmptySuccessWhenNoToken(t *testing.T) {
	tokenVendor := vendor.ProfileTokenVendor(func(_ context.Context, ref profile.ProfileRef, repoUrl string) vendor.VendorResult {
		return vendor.NewVendorUnmatched()
	})

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	require.NoError(t, credentialhandler.WriteProperties(m, body))
	req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials", body)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
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

	req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
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
	require.NoError(t, credentialhandler.WriteProperties(m, body))

	req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials", body)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := maxRequestSize(1)(
		// use the request size limit to force an error in the credentials handler
		handlePostGitCredentials(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo),
	)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	// important to know that internal details aren't part of the error response
	assert.Equal(t, "", rr.Body.String())
}

func TestHandlePostGitCredentials_ReturnsFailureOnVendorFailure(t *testing.T) {
	tokenVendor := tvFails(errors.New("vendor failure"))

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	require.NoError(t, credentialhandler.WriteProperties(m, body))
	req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials", body)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))
	assert.Equal(t, "Internal Server Error", rr.Header().Get("Chinmina-Denied"))
	assert.Empty(t, rr.Body.String())
}

func TestHandlePostGitCredentialsWithRepoProfile_ReturnsTokenOnSuccess(t *testing.T) {
	cases := []struct {
		name            string
		profileParam    string
		expectedProfile string
	}{
		{
			name:            "repo profile without prefix",
			profileParam:    "my-profile",
			expectedProfile: "repo:my-profile",
		},
		{
			name:            "repo profile with prefix",
			profileParam:    "repo:my-profile",
			expectedProfile: "repo:my-profile",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenVendor := tv("expected-token-value")

			ctx := claimsContext()

			m := credentialhandler.NewMap(10)
			m.Set("protocol", "https")
			m.Set("host", "github.com")
			m.Set("path", "org/repo")

			body := &bytes.Buffer{}
			require.NoError(t, credentialhandler.WriteProperties(m, body))
			req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials/"+tc.profileParam, body)
			require.NoError(t, err)

			req.SetPathValue("profile", tc.profileParam)
			rr := httptest.NewRecorder()

			// act
			handler := handlePostGitCredentials(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
			handler.ServeHTTP(rr, req)

			// assert
			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

			respBody := rr.Body.String()
			assert.Equal(t, "protocol=https\nhost=github.com\npath=org/repo\nusername=x-access-token\npassword=expected-token-value\npassword_expiry_utc=1715104776\n\n", respBody)
		})
	}
}

func TestHandleHealthCheck_Success(t *testing.T) {
	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, "GET", "/healthcheck", nil)
	require.NoError(t, err)
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
	return vendor.ProfileTokenVendor(func(_ context.Context, ref profile.ProfileRef, repoUrl string) vendor.VendorResult {
		return vendor.NewVendorSuccess(vendor.ProfileToken{
			Token:               token,
			Expiry:              defaultExpiry,
			Profile:             ref.ShortString(),
			OrganizationSlug:    ref.Organization,
			VendedRepositoryURL: repoUrl,
		})
	})
}

func TestHandlePostGitCredentialsWithProfile_ReturnsTokenOnSuccess(t *testing.T) {
	tokenVendor := tv("expected-token-value")
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()

	m := credentialhandler.NewMap(10)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", "org/repo")

	body := &bytes.Buffer{}
	require.NoError(t, credentialhandler.WriteProperties(m, body))
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/git-credentials/static-profile", body)
	require.NoError(t, err)

	req.SetPathValue("profile", "static-profile")
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor, builder, profile.ProfileTypeOrg)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

	respBody := rr.Body.String()
	assert.Equal(t, "protocol=https\nhost=github.com\npath=org/repo\nusername=x-access-token\npassword=expected-token-value\npassword_expiry_utc=1715104776\n\n", respBody)
}

func tvFails(err error) vendor.ProfileTokenVendor {
	return vendor.ProfileTokenVendor(func(_ context.Context, ref profile.ProfileRef, repoUrl string) vendor.VendorResult {
		return vendor.NewVendorFailed(err)
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
	req, err := http.NewRequestWithContext(t.Context(), "POST", "/git-credentials", body)
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

func TestHandlePostToken_ProfileErrors(t *testing.T) {
	cases := []struct {
		name           string
		vendorErr      error
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "ProfileMatchFailedError",
			vendorErr:      profile.ProfileMatchFailedError{Name: "test-profile"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Forbidden",
		},
		{
			name:           "ProfileNotFoundError",
			vendorErr:      profile.ProfileNotFoundError{Name: "test-profile"},
			expectedStatus: http.StatusNotFound,
			expectedError:  "profile not found",
		},
		{
			name:           "ProfileUnavailableError",
			vendorErr:      profile.ProfileUnavailableError{Name: "test-profile", Cause: errors.New("validation failed")},
			expectedStatus: http.StatusNotFound,
			expectedError:  "profile unavailable: validation failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenVendor := tvFails(tc.vendorErr)

			ctx := claimsContext()

			req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
			require.NoError(t, err)
			rr := httptest.NewRecorder()

			// act
			handler := handlePostToken(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
			handler.ServeHTTP(rr, req)

			// assert
			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

			var respBody ErrorResponse
			err = json.Unmarshal(rr.Body.Bytes(), &respBody)
			require.NoError(t, err)
			assert.Equal(t, ErrorResponse{Error: tc.expectedError}, respBody)
		})
	}
}

func TestHandlePostToken_ClaimValidationError(t *testing.T) {
	tokenVendor := tvFails(profile.ClaimValidationError{
		Claim: "build_branch",
		Value: "main\n",
		Err:   errors.New("contains control character or whitespace"),
	})

	ctx := claimsContext()

	req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var respBody ErrorResponse
	err = json.Unmarshal(rr.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, ErrorResponse{Error: "Forbidden"}, respBody)
}

func TestHandlePostGitCredentials_ClaimValidationError(t *testing.T) {
	tokenVendor := tvFails(profile.ClaimValidationError{
		Claim: "build_branch",
		Value: "main\n",
		Err:   errors.New("contains control character or whitespace"),
	})

	ctx := claimsContext()

	// request body in git-credentials format
	body := strings.NewReader("protocol=https\nhost=github.com\npath=org/repo\n\n")

	req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials", body)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor, testBuilder(profile.ProfileTypeRepo), profile.ProfileTypeRepo)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))
	assert.Equal(t, "Forbidden", rr.Header().Get("Chinmina-Denied"))
	assert.Empty(t, rr.Body.String())
}

func TestWriteJSONError_Success(t *testing.T) {
	rr := httptest.NewRecorder()

	// act
	writeJSONError(t.Context(), rr, statusError(http.StatusForbidden, "access denied: profile match conditions not met"))

	// assert
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var respBody ErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, ErrorResponse{Error: "access denied: profile match conditions not met"}, respBody)
}

func TestWriteJSONError_MultipleStatusCodes(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		message    string
	}{
		{
			name:       "400 Bad Request",
			statusCode: http.StatusBadRequest,
			message:    "invalid JWT claims",
		},
		{
			name:       "403 Forbidden",
			statusCode: http.StatusForbidden,
			message:    "access denied: profile match conditions not met",
		},
		{
			name:       "404 Not Found",
			statusCode: http.StatusNotFound,
			message:    "profile not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			// act
			writeJSONError(t.Context(), rr, statusError(tc.statusCode, tc.message))

			// assert
			assert.Equal(t, tc.statusCode, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

			var respBody ErrorResponse
			err := json.Unmarshal(rr.Body.Bytes(), &respBody)
			require.NoError(t, err)
			assert.Equal(t, ErrorResponse{Error: tc.message}, respBody)
		})
	}
}

func statusError(statusCode int, message string) error {
	return mockStatusError{
		statusCode: statusCode,
		message:    message,
	}
}

type mockStatusError struct {
	statusCode int
	message    string
}

func (e mockStatusError) Error() string {
	return e.message
}

func (e mockStatusError) Status() (int, string) {
	return e.statusCode, e.message
}

func TestAuditError(t *testing.T) {
	cases := []struct {
		name               string
		err                error
		existingAuditError string
		expectedAuditError string
	}{
		{
			name:               "nil error does nothing",
			err:                nil,
			existingAuditError: "",
			expectedAuditError: "",
		},
		{
			name:               "error written when audit log empty",
			err:                errors.New("token creation failed"),
			existingAuditError: "",
			expectedAuditError: "token creation failed",
		},
		{
			name:               "error not written when audit log already has error",
			err:                errors.New("second error"),
			existingAuditError: "first error",
			expectedAuditError: "first error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, auditLog := audit.Context(context.Background())
			auditLog.Error = tc.existingAuditError

			// act
			auditError(ctx, tc.err)

			// assert
			assert.Equal(t, tc.expectedAuditError, auditLog.Error)
		})
	}
}

// mapPathValuer is a minimal PathValuer for tests that do not need a real
// *http.Request.
type mapPathValuer map[string]string

func (m mapPathValuer) PathValue(name string) string { return m[name] }

func TestNewProfileRefBuilder_OrgProfile(t *testing.T) {
	// Non-caller-scoped org profile with no caller-supplied scope produces
	// an unscoped ref — status quo for static-list profiles.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "static-profile"}

	ref, err := builder(ctx, pv, "", "")
	require.NoError(t, err)

	assert.Equal(t, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "static-profile",
	}, ref)
}

func TestNewProfileRefBuilder_RepoProfileDefault(t *testing.T) {
	builder := NewProfileRefBuilder(nil, profile.ProfileTypeRepo)

	ctx := claimsContext()
	pv := mapPathValuer{} // no path parameter — repo profiles default to "default"

	ref, err := builder(ctx, pv, "", "")
	require.NoError(t, err)

	assert.Equal(t, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "default",
		PipelineID:   "pipeline-id",
		PipelineSlug: "pipeline-slug",
	}, ref)
}

const scopedProfilesYAML = `organization:
  profiles:
    - name: caller-scoped-profile
      repositories:
        - "{{caller-scoped-repository}}"
      permissions:
        - contents:write
      match:
        - claim: pipeline_slug
          valuePattern: ".*"
    - name: all-repos-profile
      repositories:
        - "{{all-repositories}}"
      permissions:
        - contents:read
    - name: static-profile
      repositories:
        - repo1
        - repo2
      permissions:
        - contents:read

pipeline:
  defaults:
    permissions:
      - contents:read
`

func TestNewProfileRefBuilder_OrgCallerScoped_MissingScopeReturnsRequiredError(t *testing.T) {
	// A caller-scoped profile without a caller-supplied scope must surface
	// RepositoryScopeRequiredError so the handler can respond with 400 and
	// a specific message. This is Req 2.3 enforced at the builder boundary.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "caller-scoped-profile"}

	_, err := builder(ctx, pv, "", "")

	var scopeErr profile.RepositoryScopeRequiredError
	require.ErrorAs(t, err, &scopeErr)
	assert.Equal(t, "caller-scoped-profile", scopeErr.ProfileName)
}

func TestNewProfileRefBuilder_OrgStaticList_RejectsScope(t *testing.T) {
	// A static-list profile must reject caller-supplied scope (Req 2.2).
	// RepositoryScopeUnexpectedError carries a 400 status, allowing the
	// handler to surface a specific message via writeJSONError/writeTextError.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "static-profile"}

	_, err := builder(ctx, pv, "unexpected-scope", "")

	var scopeErr profile.RepositoryScopeUnexpectedError
	require.ErrorAs(t, err, &scopeErr)
	assert.Equal(t, "static-profile", scopeErr.ProfileName)
}

func TestNewProfileRefBuilder_OrgCallerScoped_PopulatesScopedRepository(t *testing.T) {
	// When a caller supplies a repository scope to a caller-scoped profile,
	// the builder populates ref.ScopedRepository so downstream consumers
	// (URN, cache key, audit log) observe a single source of truth.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "caller-scoped-profile"}

	ref, err := builder(ctx, pv, "target-repo", "")
	require.NoError(t, err)

	assert.Equal(t, profile.ProfileRef{
		Organization:     "organization-slug",
		Type:             profile.ProfileTypeOrg,
		Name:             "caller-scoped-profile",
		ScopedRepository: "target-repo",
	}, ref)
}

func TestNewProfileRefBuilder_OrgCallerScoped_UsesImplicitScopeWhenExplicitEmpty(t *testing.T) {
	// The git-credentials endpoint derives the repository name from the
	// Git-supplied URL and passes it as implicitScope. For caller-scoped
	// profiles this fills ref.ScopedRepository when no explicit scope is
	// supplied.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "caller-scoped-profile"}

	ref, err := builder(ctx, pv, "", "url-derived-repo")
	require.NoError(t, err)

	assert.Equal(t, "url-derived-repo", ref.ScopedRepository)
}

func TestNewProfileRefBuilder_RepoProfile_IgnoresScopeArgs(t *testing.T) {
	// Pipeline profiles are never scoped. Any scope arguments are silently
	// ignored; the builder does not even touch the store.
	builder := NewProfileRefBuilder(nil, profile.ProfileTypeRepo)

	ctx := claimsContext()
	pv := mapPathValuer{}

	ref, err := builder(ctx, pv, "explicit-ignored", "implicit-ignored")
	require.NoError(t, err)
	assert.Empty(t, ref.ScopedRepository)
}

func TestNewProfileRefBuilder_OrgProfileNotFound_SurfacesLookupError(t *testing.T) {
	// Unknown profile surfaces ProfileNotFoundError from the store lookup.
	// The handler will route this through writeJSONError / writeTextError,
	// preserving the 404 status the error carries.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "no-such-profile"}

	_, err := builder(ctx, pv, "", "")

	var notFound profile.ProfileNotFoundError
	require.ErrorAs(t, err, &notFound)
}

func TestNewProfileRefBuilder_OrgNonCallerScoped_IgnoresImplicitScope(t *testing.T) {
	// Static-list and all-repositories profiles must not reject a
	// git-credentials request just because the URL yielded a repo name.
	// implicitScope is a structural artefact of the request format, not a
	// scope request.
	cases := []string{"static-profile", "all-repos-profile"}
	for _, profileName := range cases {
		t.Run(profileName, func(t *testing.T) {
			store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
			builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

			ctx := claimsContext()
			pv := mapPathValuer{"profile": profileName}

			ref, err := builder(ctx, pv, "", "url-derived-repo")
			require.NoError(t, err)

			assert.Empty(t, ref.ScopedRepository)
		})
	}
}

func TestHandlePostToken_OrgStaticList_RejectsScopeWithSpecificMessage(t *testing.T) {
	// Req 2.2 — the client must receive a message identifying *why* the
	// scope was rejected, not a generic "Bad Request". The handler routes
	// builder errors through writeJSONError so HTTPStatuser types carry
	// their declared message.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/static-profile?repository-scope=anything", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "static-profile")
	rr := httptest.NewRecorder()

	handler := handlePostToken(tv("unused"), builder, profile.ProfileTypeOrg)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "profile does not accept repository scoping", body.Error)
}

func TestHandlePostToken_OrgCallerScoped_MissingScopeReturnsSpecificMessage(t *testing.T) {
	// Req 2.3 — the caller must learn that the profile requires a scope.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	builder := NewProfileRefBuilder(store, profile.ProfileTypeOrg)

	ctx := claimsContext()
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/caller-scoped-profile", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "caller-scoped-profile")
	rr := httptest.NewRecorder()

	handler := handlePostToken(tv("unused"), builder, profile.ProfileTypeOrg)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "repository scope is required for this profile", body.Error)
}

func TestExtractRepositoryScope_Valid(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected string
	}{
		{"simple name", "repository-scope=my-repo", "my-repo"},
		{"hyphenated name", "repository-scope=my-cool-repo", "my-cool-repo"},
		{"mixed case preserved", "repository-scope=MyRepo", "MyRepo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), "POST", "/organization/token/test?"+tt.query, nil)
			require.NoError(t, err)
			scope, err := extractRepositoryScope(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, scope)
		})
	}
}

func TestExtractRepositoryScope_Absent(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), "POST", "/organization/token/test", nil)
	require.NoError(t, err)
	scope, err := extractRepositoryScope(req)
	require.NoError(t, err)
	assert.Equal(t, "", scope)
}

func TestExtractRepositoryScope_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"contains slash", "repository-scope=owner/repo"},
		{"empty value", "repository-scope="},
		{"whitespace only", "repository-scope=%20%20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), "POST", "/organization/token/test?"+tt.query, nil)
			require.NoError(t, err)
			_, err = extractRepositoryScope(req)
			require.Error(t, err)
		})
	}
}

func TestStripPrefix(t *testing.T) {
	echoPath := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.URL.Path))
	})

	t.Run("strips matching prefix", func(t *testing.T) {
		cases := []struct {
			name         string
			prefix       string
			requestPath  string
			expectedPath string
		}{
			{
				name:         "simple prefix",
				prefix:       "/test",
				requestPath:  "/test/token",
				expectedPath: "/token",
			},
			{
				name:         "nested prefix",
				prefix:       "/api/v1",
				requestPath:  "/api/v1/users/123",
				expectedPath: "/users/123",
			},
			{
				name:         "exact match becomes root",
				prefix:       "/test",
				requestPath:  "/test",
				expectedPath: "/",
			},
			{
				name:         "prefix with trailing slash on request",
				prefix:       "/test",
				requestPath:  "/test/",
				expectedPath: "/",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				handler := stripPrefix(tc.prefix, echoPath)
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.requestPath, nil)
				rr := httptest.NewRecorder()

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusOK, rr.Code)
				assert.Equal(t, tc.expectedPath, rr.Body.String())
			})
		}
	})

	t.Run("rejects non-matching requests", func(t *testing.T) {
		cases := []struct {
			name        string
			prefix      string
			requestPath string
		}{
			{
				name:        "partial segment match",
				prefix:      "/test",
				requestPath: "/testing",
			},
			{
				name:        "completely different path",
				prefix:      "/api",
				requestPath: "/other/path",
			},
			{
				name:        "prefix not present",
				prefix:      "/api/v1",
				requestPath: "/api/v2/users",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				handler := stripPrefix(tc.prefix, echoPath)
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.requestPath, nil)
				rr := httptest.NewRecorder()

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusNotFound, rr.Code)
			})
		}
	})

	t.Run("handles RawPath", func(t *testing.T) {
		echoRawPath := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(r.URL.RawPath))
		})

		handler := stripPrefix("/test", echoRawPath)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test/path%2Fwith%2Fencoding", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "/path%2Fwith%2Fencoding", rr.Body.String())
	})
}
