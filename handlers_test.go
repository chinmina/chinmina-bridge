package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var defaultExpiry = time.Date(2024, time.May, 7, 17, 59, 36, 0, time.UTC)

// pipelineAttr and orgAttr name the two profile attribute types the vendor
// chain is instantiated with, keeping generic call sites readable.
type (
	pipelineAttr = profile.PipelineProfileAttr
	orgAttr      = profile.OrganizationProfileAttr
)

// testApp is the identity every test profile resolves to.
var testApp = github.AppIdentity{Name: "default", ApplicationID: 111, InstallationID: 222}

// testAppResolver matches a deployment with no app registry: the default app
// resolves and nothing else does.
func testAppResolver(name string) (github.AppIdentity, bool) {
	if name != testApp.Name {
		return github.AppIdentity{}, false
	}
	return testApp, true
}

// testPipelineResolver returns a pipeline ProfileResolver whose lookup always
// yields an unconditionally-matching profile. It is sufficient for tests that
// exercise handler plumbing rather than configuration; profile lookup failure
// and scope validation are covered by the resolver unit tests below.
func testPipelineResolver() ProfileResolver[pipelineAttr] {
	return NewPipelineProfileResolver(func(string) (profile.AuthorizedProfile[pipelineAttr], string, error) {
		return profile.NewAuthorizedProfile(profile.CompositeMatcher(), pipelineAttr{App: testApp.Name}), "test-digest", nil
	}, testAppResolver)
}

func TestHandlers_RequireClaims(t *testing.T) {
	// The resolver's call to jwt.RequireBuildkiteClaimsFromContext panics when
	// claims are absent — a defence-in-depth signal that the JWT middleware
	// was bypassed. For /token the resolver runs first; for /git-credentials
	// the body is read first, so we send a valid body to reach the resolver.
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
			handler: handlePostToken(nil, testPipelineResolver(), withheld),
			body:    nil,
		},
		{
			name:    "postGitCredentials",
			handler: handlePostGitCredentials(nil, testPipelineResolver(), withheld),
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
	tokenVendor := tv[pipelineAttr]("expected-token-value")

	ctx := claimsContext()

	req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor, testPipelineResolver(), withheld)
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
	tokenVendor := tvFails[pipelineAttr](errors.New("vendor failure"))

	ctx := claimsContext()

	req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor, testPipelineResolver(), withheld)
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
			tokenVendor := tv[pipelineAttr]("expected-token-value")

			ctx := claimsContext()

			req, err := http.NewRequestWithContext(ctx, "POST", "/token/"+tc.profileParam, nil)
			require.NoError(t, err)

			req.SetPathValue("profile", tc.profileParam)
			rr := httptest.NewRecorder()

			// act
			handler := handlePostToken(tokenVendor, testPipelineResolver(), withheld)
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
	tokenVendor := tv[pipelineAttr]("expected-token-value")

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
	handler := handlePostGitCredentials(tokenVendor, testPipelineResolver(), withheld)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

	respBody := rr.Body.String()
	assert.Equal(t, "protocol=https\nhost=github.com\npath=org/repo\nusername=x-access-token\npassword=expected-token-value\npassword_expiry_utc=1715104776\n\n", respBody)
}

func TestHandlePostGitCredentials_ReturnsEmptySuccessWhenNoToken(t *testing.T) {
	tokenVendor := vendor.ProfileTokenVendor[pipelineAttr](func(_ context.Context, _ vendor.Resolved[pipelineAttr], _ string) vendor.VendorResult {
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
	handler := handlePostGitCredentials(tokenVendor, testPipelineResolver(), withheld)
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
	tokenVendor := tv[pipelineAttr]("expected-token-value")

	ctx := claimsContext()

	req, err := http.NewRequestWithContext(ctx, "POST", "/git-credentials", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostGitCredentials(tokenVendor, testPipelineResolver(), withheld)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	// important to know that internal details aren't part of the error response
	assert.Equal(t, "Bad Request\n", rr.Body.String())
}

func TestHandlePostGitCredentials_ReturnsFailureOnReadFailure(t *testing.T) {
	tokenVendor := tv[pipelineAttr]("expected-token-value")

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
		handlePostGitCredentials(tokenVendor, testPipelineResolver(), withheld),
	)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	// important to know that internal details aren't part of the error response
	assert.Equal(t, "", rr.Body.String())
}

func TestHandlePostGitCredentials_ReturnsFailureOnVendorFailure(t *testing.T) {
	tokenVendor := tvFails[pipelineAttr](errors.New("vendor failure"))

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
	handler := handlePostGitCredentials(tokenVendor, testPipelineResolver(), withheld)
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
			tokenVendor := tv[pipelineAttr]("expected-token-value")

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
			handler := handlePostGitCredentials(tokenVendor, testPipelineResolver(), withheld)
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

// tv returns a vendor that always succeeds, echoing the resolved profile back
// in the token so handler tests can assert what reached the chain.
func tv[T any](token string) vendor.ProfileTokenVendor[T] {
	return func(_ context.Context, r vendor.Resolved[T], repoUrl string) vendor.VendorResult {
		return vendor.NewVendorSuccess(vendor.ProfileToken{
			Token:               token,
			Expiry:              defaultExpiry,
			Profile:             r.Ref.ShortString(),
			OrganizationSlug:    r.Ref.Organization,
			VendedRepositoryURL: repoUrl,
		})
	}
}

func TestHandlePostGitCredentialsWithProfile_ReturnsTokenOnSuccess(t *testing.T) {
	tokenVendor := tv[orgAttr]("expected-token-value")
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

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
	handler := handlePostGitCredentials(tokenVendor, resolve, withheld)
	handler.ServeHTTP(rr, req)

	// assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))

	respBody := rr.Body.String()
	assert.Equal(t, "protocol=https\nhost=github.com\npath=org/repo\nusername=x-access-token\npassword=expected-token-value\npassword_expiry_utc=1715104776\n\n", respBody)
}

// tvFails returns a vendor that always fails with err.
func tvFails[T any](err error) vendor.ProfileTokenVendor[T] {
	return func(_ context.Context, _ vendor.Resolved[T], _ string) vendor.VendorResult {
		return vendor.NewVendorFailed(err)
	}
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
			tokenVendor := tvFails[pipelineAttr](tc.vendorErr)

			ctx := claimsContext()

			req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
			require.NoError(t, err)
			rr := httptest.NewRecorder()

			// act
			handler := handlePostToken(tokenVendor, testPipelineResolver(), withheld)
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
	tokenVendor := tvFails[pipelineAttr](profile.ClaimValidationError{
		Claim: "build_branch",
		Value: "main\n",
		Err:   errors.New("contains control character or whitespace"),
	})

	ctx := claimsContext()

	req, err := http.NewRequestWithContext(ctx, "POST", "/token", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()

	// act
	handler := handlePostToken(tokenVendor, testPipelineResolver(), withheld)
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
	tokenVendor := tvFails[pipelineAttr](profile.ClaimValidationError{
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
	handler := handlePostGitCredentials(tokenVendor, testPipelineResolver(), withheld)
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

func TestProfileResolver_OrgProfile(t *testing.T) {
	// Non-caller-scoped org profile with no caller-supplied scope produces
	// an unscoped ref — status quo for static-list profiles.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "static-profile"}

	resolved, err := resolve.Resolve(ctx, pv, "", "")
	require.NoError(t, err)

	assert.Equal(t, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "static-profile",
	}, resolved.Ref)
}

func TestProfileResolver_RepoProfileDefault(t *testing.T) {
	resolve := testPipelineResolver()

	ctx := claimsContext()
	pv := mapPathValuer{} // no path parameter — repo profiles default to "default"

	resolved, err := resolve.Resolve(ctx, pv, "", "")
	require.NoError(t, err)

	assert.Equal(t, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "default",
		PipelineID:   "pipeline-id",
		PipelineSlug: "pipeline-slug",
	}, resolved.Ref)
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

func TestProfileResolver_OrgCallerScoped_MissingScopeReturnsRequiredError(t *testing.T) {
	// A caller-scoped profile without a caller-supplied scope must surface
	// RepositoryScopeRequiredError so the handler can respond with 400 and
	// a specific message identifying the required scope.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "caller-scoped-profile"}

	_, err := resolve.Resolve(ctx, pv, "", "")

	var scopeErr profile.RepositoryScopeRequiredError
	require.ErrorAs(t, err, &scopeErr)
	assert.Equal(t, "caller-scoped-profile", scopeErr.ProfileName)
}

func TestProfileResolver_OrgStaticList_RejectsScope(t *testing.T) {
	// A static-list profile must reject caller-supplied scope.
	// RepositoryScopeUnexpectedError carries a 400 status, allowing the
	// handler to surface a specific message via writeJSONError/writeTextError.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "static-profile"}

	_, err := resolve.Resolve(ctx, pv, "unexpected-scope", "")

	var scopeErr profile.RepositoryScopeUnexpectedError
	require.ErrorAs(t, err, &scopeErr)
	assert.Equal(t, "static-profile", scopeErr.ProfileName)
}

func TestProfileResolver_OrgCallerScoped_PopulatesScopedRepository(t *testing.T) {
	// When a caller supplies a repository scope to a caller-scoped profile,
	// the resolver populates ref.ScopedRepository so downstream consumers
	// (URN, cache key, audit log) observe a single source of truth.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "caller-scoped-profile"}

	resolved, err := resolve.Resolve(ctx, pv, "target-repo", "")
	require.NoError(t, err)

	assert.Equal(t, profile.ProfileRef{
		Organization:     "organization-slug",
		Type:             profile.ProfileTypeOrg,
		Name:             "caller-scoped-profile",
		ScopedRepository: "target-repo",
	}, resolved.Ref)
}

func TestProfileResolver_OrgCallerScoped_UsesImplicitScopeWhenExplicitEmpty(t *testing.T) {
	// The git-credentials endpoint derives the repository name from the
	// Git-supplied URL and passes it as implicitScope. For caller-scoped
	// profiles this fills ref.ScopedRepository when no explicit scope is
	// supplied.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "caller-scoped-profile"}

	resolved, err := resolve.Resolve(ctx, pv, "", "url-derived-repo")
	require.NoError(t, err)

	assert.Equal(t, "url-derived-repo", resolved.Ref.ScopedRepository)
}

func TestProfileResolver_RepoProfile_IgnoresScopeArgs(t *testing.T) {
	// Pipeline profiles are never scoped. Any scope arguments are silently
	// ignored; the resolver never consults organization configuration.
	resolve := testPipelineResolver()

	ctx := claimsContext()
	pv := mapPathValuer{}

	resolved, err := resolve.Resolve(ctx, pv, "explicit-ignored", "implicit-ignored")
	require.NoError(t, err)
	assert.Empty(t, resolved.Ref.ScopedRepository)
}

func TestProfileResolver_OrgProfileNotFound_SurfacesLookupError(t *testing.T) {
	// Unknown profile surfaces ProfileNotFoundError from the store lookup.
	// The handler will route this through writeJSONError / writeTextError,
	// preserving the 404 status the error carries.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	pv := mapPathValuer{"profile": "no-such-profile"}

	_, err := resolve.Resolve(ctx, pv, "", "")

	var notFound profile.ProfileNotFoundError
	require.ErrorAs(t, err, &notFound)
}

// TestHandlePostToken_PipelineProfileNotFoundAnswers404 covers the pipeline
// half of profile-not-found: an unloaded or incomplete configuration must be
// caught at the resolver boundary, before anything is vended.
func TestHandlePostToken_PipelineProfileNotFoundAnswers404(t *testing.T) {
	vended := false
	tokenVendor := vendor.ProfileTokenVendor[pipelineAttr](func(context.Context, vendor.Resolved[pipelineAttr], string) vendor.VendorResult {
		vended = true
		return vendor.NewVendorFailed(errors.New("must not be reached"))
	})

	// An unloaded store answers ProfileNotFoundError for every name.
	resolve := NewPipelineProfileResolver(profile.NewProfileStore().GetPipelineProfile, testAppResolver)

	req, err := http.NewRequestWithContext(claimsContext(), "POST", "/token", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	handlePostToken(tokenVendor, resolve, withheld).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.False(t, vended, "no token may be vended for a profile that does not exist")
}

func TestProfileResolver_OrgNonCallerScoped_IgnoresImplicitScope(t *testing.T) {
	// Static-list and all-repositories profiles must not reject a
	// git-credentials request just because the URL yielded a repo name.
	// implicitScope is a structural artefact of the request format, not a
	// scope request.
	cases := []string{"static-profile", "all-repos-profile"}
	for _, profileName := range cases {
		t.Run(profileName, func(t *testing.T) {
			store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
			resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

			ctx := claimsContext()
			pv := mapPathValuer{"profile": profileName}

			resolved, err := resolve.Resolve(ctx, pv, "", "url-derived-repo")
			require.NoError(t, err)

			assert.Empty(t, resolved.Ref.ScopedRepository)
		})
	}
}

func TestHandlePostToken_OrgStaticList_RejectsScopeWithSpecificMessage(t *testing.T) {
	// The client must receive a message identifying *why* the scope was
	// rejected, not a generic "Bad Request". The handler routes resolver
	// errors through writeJSONError so HTTPStatuser types carry their
	// declared message.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/static-profile?repository-scope=anything", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "static-profile")
	rr := httptest.NewRecorder()

	handler := handlePostToken(tv[orgAttr]("unused"), resolve, withheld)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "profile does not accept repository scoping", body.Error)
}

func TestHandlePostToken_OrgCallerScoped_MissingScopeReturnsSpecificMessage(t *testing.T) {
	// The caller must learn that the profile requires a scope.
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx := claimsContext()
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/caller-scoped-profile", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "caller-scoped-profile")
	rr := httptest.NewRecorder()

	handler := handlePostToken(tv[orgAttr]("unused"), resolve, withheld)
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
		{"leading whitespace", "repository-scope=%20repo"},
		{"trailing whitespace", "repository-scope=repo%20"},
		{"internal tab", "repository-scope=re%09po"},
		{"newline", "repository-scope=re%0Apo"},
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

// TestHandlePostToken_PipelineRouteIgnoresRepositoryScope pins the one
// load-bearing use of AcceptsRepositoryScope. A pipeline profile cannot be
// narrowed by the caller, so ?repository-scope= is not a request the route
// understands — it is ignored rather than validated. The value below would be
// a 400 on an organization route; here it must not be read at all, because
// rejecting it would break every existing caller that passes the parameter
// indiscriminately.
func TestHandlePostToken_PipelineRouteIgnoresRepositoryScope(t *testing.T) {
	tokenVendor := vendor.ProfileTokenVendor[pipelineAttr](func(context.Context, vendor.Resolved[pipelineAttr], string) vendor.VendorResult {
		return vendor.NewVendorSuccess(vendor.ProfileToken{Token: "pipeline-token"})
	})

	req, err := http.NewRequestWithContext(claimsContext(), "POST", "/token?repository-scope=owner/repo", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "default")

	rr := httptest.NewRecorder()
	handlePostToken(tokenVendor, testPipelineResolver(), withheld).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "a scope parameter the route ignores must not fail the request")
}

func TestDeriveScopeFromRepoURL(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected string
	}{
		{"github single-segment repo", "https://github.com/acme/widget", "widget"},
		{"github repo with .git suffix", "https://github.com/acme/widget.git", "widget"},
		// A multi-segment path leaves a '/' in the derived repo name, which the
		// shared validateRepositoryScope rejects (F-02): same rule as the query
		// param channel, so it falls back to "" (unscoped → 400 for caller-scoped).
		{"multi-segment path rejected", "https://github.com/acme/sub/widget", ""},
		{"non-github host yields empty", "https://example.com/acme/widget", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, deriveScopeFromRepoURL(tt.repoURL))
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

// TestHandlers_RecordRequestedProfileWhenResolutionFails: a request that
// fails before the vendor chain runs must still say which profile was
// asked for. Without it, an operator seeing a 404 in the audit log cannot tell
// which profile name was rejected — the only record of the request's intent is
// lost precisely on the failure path where it matters most.
func TestHandlers_RecordRequestedProfileWhenResolutionFails(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)

	cases := []struct {
		name    string
		handler func(ProfileResolver[orgAttr]) http.Handler
		body    io.Reader
	}{
		{
			name: "postToken",
			handler: func(r ProfileResolver[orgAttr]) http.Handler {
				return handlePostToken(tv[orgAttr]("unused"), r, withheld)
			},
		},
		{
			name: "postGitCredentials",
			handler: func(r ProfileResolver[orgAttr]) http.Handler {
				return handlePostGitCredentials(tv[orgAttr]("unused"), r, withheld)
			},
			body: gitCredentialsBody(t, "org", "repo1"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, entry := audit.Context(claimsContext())
			req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/no-such-profile", tc.body)
			require.NoError(t, err)
			req.SetPathValue("profile", "no-such-profile")

			rr := httptest.NewRecorder()
			tc.handler(NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)).ServeHTTP(rr, req)

			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.Equal(t, "no-such-profile", entry.RequestedProfile)
		})
	}
}

// TestHandlers_UnresolvedProfileIsNotAuditedAsCanonicalURN guards the audit
// record against forgery: net/http unescapes %2F after routing, so a caller
// can put '/' in the profile path parameter. If an unresolved name were
// rendered as a canonical URN, a 404 could be made to produce a record
// byte-identical to a successful caller-scoped request for a private
// repository.
func TestHandlers_UnresolvedProfileIsNotAuditedAsCanonicalURN(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	forged := "caller-scoped-profile/repository/secret-repo"

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/"+url.PathEscape(forged), nil)
	require.NoError(t, err)
	req.SetPathValue("profile", forged)

	rr := httptest.NewRecorder()
	handlePostToken(tv[orgAttr]("unused"), NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver), withheld).ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, forged, entry.RequestedProfile, "an unresolved name must be recorded verbatim, never as a URN")
	assert.NotContains(t, entry.RequestedProfile, "profile://")
}

// invalidProfileYAML compiles to one valid profile and one that fails
// validation, so a request against the invalid profile carries a reason
// produced by the real compilation path rather than a synthesised error.
const invalidProfileYAML = `organization:
  profiles:
    - name: valid-profile
      repositories:
        - repo1
      permissions:
        - contents:read
    - name: broken-profile
      repositories:
        - repo1
      permissions:
        - contents:read
      match:
        - claim: not_a_real_claim
          value: anything

pipeline:
  defaults:
    permissions:
      - contents:read
`

// TestHandlePostToken_RecordsInvalidProfileReason: the caller of an
// unavailable profile is told only that it is unavailable, so the audit
// entry's error is the sole durable record of why. Without the reason, an
// operator seeing a 404 has no way to tell a misconfigured profile from a
// mistyped name.
func TestHandlePostToken_RecordsInvalidProfileReason(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, invalidProfileYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/broken-profile", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "broken-profile")

	rr := httptest.NewRecorder()
	handlePostToken(tv[orgAttr]("unused"), resolve, withheld).ServeHTTP(rr, req)

	// caller-facing behaviour is unchanged: 404, and a message that says
	// nothing about the cause
	require.Equal(t, http.StatusNotFound, rr.Code)
	var respBody ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &respBody))
	assert.Equal(t, ErrorResponse{Error: "profile unavailable: validation failed"}, respBody)

	assert.Equal(t,
		`profile resolution failed: profile "broken-profile" unavailable: invalid match rule for claim "not_a_real_claim": claim "not_a_real_claim" is not allowed for matching`,
		entry.Error)
}

// TestHandlePostToken_RecordsScopedRepositoryInAuditedProfile:
// the caller-supplied repository scope must be visible in the audited profile
// URN, so an audit reader can tell which repository a caller-scoped profile
// was actually exercised against.
func TestHandlePostToken_RecordsScopedRepositoryInAuditedProfile(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/caller-scoped-profile?repository-scope=target-repo", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "caller-scoped-profile")

	rr := httptest.NewRecorder()
	handlePostToken(tv[orgAttr]("token-value"), resolve, withheld).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "profile://organization/organization-slug/profile/caller-scoped-profile/repository/target-repo", entry.RequestedProfile)
}

// TestHandlePostToken_RecordsRequestedProfileWhenScopeRejected covers the
// audit gap before resolution: a request rejected for a malformed
// repository-scope never reaches the resolver, but an operator still needs to
// know which profile the caller was aiming at.
func TestHandlePostToken_RecordsRequestedProfileWhenScopeRejected(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, scopedProfilesYAML)
	resolve := NewOrgProfileResolver(store.GetOrganizationProfile, testAppResolver)

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/static-profile?repository-scope=bad/scope", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "static-profile")

	rr := httptest.NewRecorder()
	handlePostToken(tv[orgAttr]("unused"), resolve, withheld).ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "static-profile", entry.RequestedProfile)
}

// TestRoutes_ReadTheProfileStoreExactlyOncePerRequest is the acceptance
// observable for resolving once per request. A request that reads the store
// twice can be authorized against one configuration generation and vended from
// another, because profiles are replaced wholesale every five minutes. The
// count must hold on a cache miss and on a cache hit alike: the authorization
// gate runs outside the cache, so a warm entry does not skip a resolution.
func TestRoutes_ReadTheProfileStoreExactlyOncePerRequest(t *testing.T) {
	const profilesYAML = `organization:
  profiles:
    - name: static-profile
      repositories:
        - repo1
      permissions:
        - contents:read

pipeline:
  defaults:
    permissions:
      - contents:read
`

	repoLookup := vendor.RepositoryLookup(func(context.Context, string, string) (string, error) {
		return "https://github.com/organization-slug/repo1", nil
	})

	cases := []struct {
		name    string
		handler func(*profile.ProfileStore, *int, vendor.TokenVendor) http.Handler
		target  string
		profile string
		body    func() io.Reader
	}{
		{
			name: "organization token",
			handler: func(store *profile.ProfileStore, reads *int, tokenVendor vendor.TokenVendor) http.Handler {
				return handlePostToken(orgChain(t, tokenVendor), countingOrgResolver(store, reads), withheld)
			},
			target:  "/organization/token/static-profile",
			profile: "static-profile",
		},
		{
			name: "organization git-credentials",
			handler: func(store *profile.ProfileStore, reads *int, tokenVendor vendor.TokenVendor) http.Handler {
				return handlePostGitCredentials(orgChain(t, tokenVendor), countingOrgResolver(store, reads), withheld)
			},
			target:  "/organization/git-credentials/static-profile",
			profile: "static-profile",
			body:    func() io.Reader { return gitCredentialsBody(t, "organization-slug", "repo1") },
		},
		{
			name: "pipeline token",
			handler: func(store *profile.ProfileStore, reads *int, tokenVendor vendor.TokenVendor) http.Handler {
				return handlePostToken(pipelineChain(t, repoLookup, tokenVendor), countingPipelineResolver(store, reads), withheld)
			},
			target: "/token",
		},
		{
			name: "pipeline git-credentials",
			handler: func(store *profile.ProfileStore, reads *int, tokenVendor vendor.TokenVendor) http.Handler {
				return handlePostGitCredentials(pipelineChain(t, repoLookup, tokenVendor), countingPipelineResolver(store, reads), withheld)
			},
			target: "/git-credentials",
			body:   func() io.Reader { return gitCredentialsBody(t, "organization-slug", "repo1") },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := profiletest.CreateTestProfileStore(t, profilesYAML)
			reads, vends := 0, 0
			tokenVendor := vendor.TokenVendor(func(context.Context, []string, []string) (string, time.Time, error) {
				vends++
				return "minted-token", defaultExpiry, nil
			})
			handler := tc.handler(store, &reads, tokenVendor)

			serve := func() int {
				var body io.Reader
				if tc.body != nil {
					body = tc.body()
				}
				ctx, _ := audit.Context(claimsContext())
				req, err := http.NewRequestWithContext(ctx, "POST", tc.target, body)
				require.NoError(t, err)
				if tc.profile != "" {
					req.SetPathValue("profile", tc.profile)
				}
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				return rr.Code
			}

			require.Equal(t, http.StatusOK, serve(), "cache miss")
			assert.Equal(t, 1, reads, "a cache miss must read the profile store exactly once")
			require.Equal(t, 1, vends, "a cache miss must mint a token")

			require.Equal(t, http.StatusOK, serve(), "cache hit")
			assert.Equal(t, 2, reads, "a cache hit must still resolve, and still only once")
			require.Equal(t, 1, vends, "the second request must be served from the cache, not re-minted")
		})
	}
}

// orgChain builds the production organization vendor chain over a shared cache.
func orgChain(t *testing.T, tokenVendor vendor.TokenVendor) vendor.ProfileTokenVendor[orgAttr] {
	t.Helper()

	return vendor.Auditor(vendor.Authorized(vendor.Cached[orgAttr](testTokenCache(t))(
		vendor.Vending(vendor.OrgRepositories, mintingThrough(tokenVendor)),
	)))
}

// pipelineChain builds the production pipeline vendor chain over a shared cache.
func pipelineChain(t *testing.T, repoLookup vendor.RepositoryLookup, tokenVendor vendor.TokenVendor) vendor.ProfileTokenVendor[pipelineAttr] {
	t.Helper()

	return vendor.Auditor(vendor.Authorized(vendor.Cached[pipelineAttr](testTokenCache(t))(
		vendor.Vending(vendor.PipelineRepositories(repoLookup), mintingThrough(tokenVendor)),
	)))
}

// testTokenCache builds the in-memory token cache with production TTL.
func testTokenCache(t *testing.T) cache.TokenCache[vendor.ProfileToken] {
	t.Helper()

	tokenCache, err := cache.NewMemory[vendor.ProfileToken](45*time.Minute, 10_000)
	require.NoError(t, err)

	return tokenCache
}

// countingOrgResolver counts the store reads a request performs.
func countingOrgResolver(store *profile.ProfileStore, reads *int) ProfileResolver[orgAttr] {
	return NewOrgProfileResolver(func(name string) (profile.AuthorizedProfile[orgAttr], string, error) {
		*reads++
		return store.GetOrganizationProfile(name)
	}, testAppResolver)
}

// countingPipelineResolver counts the store reads a request performs.
func countingPipelineResolver(store *profile.ProfileStore, reads *int) ProfileResolver[pipelineAttr] {
	return NewPipelineProfileResolver(func(name string) (profile.AuthorizedProfile[pipelineAttr], string, error) {
		*reads++
		return store.GetPipelineProfile(name)
	}, testAppResolver)
}

// gitCredentialsBody renders a minimal git-credentials request body for the
// given org/repo.
func gitCredentialsBody(t *testing.T, org, repo string) io.Reader {
	t.Helper()

	m := credentialhandler.NewMap(3)
	m.Set("protocol", "https")
	m.Set("host", "github.com")
	m.Set("path", org+"/"+repo)

	b := &bytes.Buffer{}
	require.NoError(t, credentialhandler.WriteProperties(m, b))
	return b
}

// mintingThrough adapts a plain token vendor to the app-aware signature,
// discarding the app.
func mintingThrough(mint vendor.TokenVendor) vendor.AppTokenVendor {
	return func(ctx context.Context, _ github.AppIdentity, repoNames []string, scopes []string) (string, time.Time, error) {
		return mint(ctx, repoNames, scopes)
	}
}
