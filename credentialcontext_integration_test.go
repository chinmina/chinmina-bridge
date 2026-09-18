//go:build integration

package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type credentialContextCase struct {
	name, body, repository string
	status                 int
}

// The completeness table is independent of profile and cache state. Zero marks
// the supported pair, whose profile-specific outcomes are exercised separately.
func unfulfillableCredentialContexts() []credentialContextCase {
	protocols := []string{"", "protocol=\n", "protocol=https\n", "protocol=http\n"}
	hosts := []string{"", "host=\n", "host=github.com\n", "host=gitlab.com\n"}
	paths := []string{"", "path=\n", "path=/\n", "path=test-org/test-repo\n"}
	requiredNames := []string{"omitted", "empty", "supported", "unsupported"}
	pathNames := []string{"omitted", "empty", "root", "repository"}
	statuses := [4][4]int{
		{-1, -1, 400, 400},
		{-1, -1, 400, 400},
		{400, 400, 0, 200},
		{400, 400, 200, 200},
	}
	prefixes := [4][4]string{
		{}, {},
		{"", "", "", "https://gitlab.com"},
		{"", "", "http://github.com", "http://gitlab.com"},
	}
	suffixes := []string{"", "", "/", "/test-org/test-repo"}
	var cases []credentialContextCase
	for p, protocol := range protocols {
		for h, host := range hosts {
			if statuses[p][h] == 0 {
				continue
			}
			for s, path := range paths {
				status := statuses[p][h]
				if status == -1 {
					status = http.StatusOK
					if s >= 2 {
						status = http.StatusBadRequest
					}
				}
				repository := prefixes[p][h]
				if repository != "" {
					repository += suffixes[s]
				}
				cases = append(cases, credentialContextCase{
					name: fmt.Sprintf("protocol-%s/host-%s/path-%s", requiredNames[p], requiredNames[h], pathNames[s]),
					body: protocol + host + path, repository: repository, status: status,
				})
			}
		}
	}
	return append(cases,
		credentialContextCase{name: "unrelated-properties", body: "username=someone\npassword=ignored\n", status: http.StatusOK},
		credentialContextCase{name: "protocol-case", body: "protocol=HTTPS\nhost=github.com\n", repository: "HTTPS://github.com", status: http.StatusOK},
		credentialContextCase{name: "host-case", body: "protocol=https\nhost=GitHub.com\n", repository: "https://GitHub.com", status: http.StatusOK},
		credentialContextCase{name: "explicit-port", body: "protocol=https\nhost=github.com:443\n", repository: "https://github.com:443", status: http.StatusOK},
		credentialContextCase{name: "trailing-dot", body: "protocol=https\nhost=github.com.\n", repository: "https://github.com.", status: http.StatusOK},
		credentialContextCase{name: "protocol-whitespace", body: "protocol= \nhost=github.com\n", repository: " ://github.com", status: http.StatusOK},
		credentialContextCase{name: "host-whitespace", body: "protocol=https\nhost= \n", repository: "https://%20", status: http.StatusOK},
		credentialContextCase{name: "both-whitespace", body: "protocol= \nhost= \n", repository: " ://%20", status: http.StatusOK},
	)
}

// A single table crosses every early outcome with every route family and cache
// warming source. Each warm run must still serve its original token afterwards;
// an empty organization-token URL must never leak into Git serialization.
func TestIntegrationGitCredentials_ContextCacheIndependence(t *testing.T) {
	profiles := []struct {
		name, endpoint, tokenEndpoint, requestedName, path string
	}{
		{"default-pipeline", "/git-credentials", "/token", "", "test-org/test-repo"},
		{"named-pipeline", "/git-credentials/default", "/token/default", "default", "test-org/test-repo"},
		{"static", "/organization/git-credentials/static-profile", "/organization/token/static-profile", "static-profile", "test-org/repo1"},
		{"caller-scoped", "/organization/git-credentials/caller-scoped-profile", "/organization/token/caller-scoped-profile?repository-scope=test-repo", "caller-scoped-profile", "test-org/test-repo"},
		{"wildcard", "/organization/git-credentials/all-repos-profile", "/organization/token/all-repos-profile", "all-repos-profile", "test-org/test-repo"},
	}
	cases := unfulfillableCredentialContexts()
	for _, prof := range profiles {
		for _, cacheState := range []string{"cold", "credentials", "token"} {
			t.Run(prof.name+"/"+cacheState, func(t *testing.T) {
				harness := newCredentialPathHarness(t)
				request := auditedGitCredentialRequest(t, harness)
				token := harness.PipelineToken()
				validBody := "protocol=https\nhost=github.com\npath=" + prof.path + "\n"
				switch cacheState {
				case "credentials":
					response, _ := request(t, prof.endpoint, token, validBody)
					require.Equal(t, http.StatusOK, response.StatusCode)
					require.Contains(t, string(response.Body), "\npassword=ghs_path_presence\n")
				case "token":
					response, status, err := harness.Client().RequestJSON(http.MethodPost, prof.tokenEndpoint, token, nil)
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, status)
					require.Equal(t, "ghs_path_presence", response["token"])
				}
				mints := harness.GitHubMock.TokenRequestCount()
				lookups := harness.BuildkiteMock.RequestCount()
				if cacheState != "cold" {
					require.Equal(t, 1, mints)
					harness.GitHubMock.Token = "ghs_must_not_replace_cached_token"
				}

				for _, tc := range cases {
					t.Run(tc.name, func(t *testing.T) {
						response, entry := request(t, prof.endpoint, token, tc.body)
						assert.Equal(t, tc.status, response.StatusCode)
						assert.Equal(t, credentialAudit{RequestedProfile: prof.requestedName, RequestedRepository: tc.repository}, credentialAuditFields(entry), "early outcomes must not claim profile authorization or vending")
						assert.True(t, entry.Authorized, "OIDC authentication still precedes classification")
						assert.Equal(t, "test-org", entry.OrganizationSlug)
						assert.Equal(t, "test-pipeline", entry.PipelineSlug)
						if tc.status == http.StatusOK {
							assert.Equal(t, credentialResponseHeaders{Status: http.StatusOK, ContentType: "text/plain"}, credentialHeaders(response))
							assert.Equal(t, "0", response.Headers.Get("Content-Length"))
							assert.NotContains(t, response.Headers, "Chinmina-Denied")
							assert.Empty(t, response.Body)
							assert.Equal(t, audit.SkippedSuccessMessage, entry.Error)
						} else {
							assert.Equal(t, "Bad Request\n", string(response.Body))
							assert.NotEmpty(t, entry.Error)
							assert.NotEqual(t, audit.SkippedSuccessMessage, entry.Error)
						}
						assert.Equal(t, mints, harness.GitHubMock.TokenRequestCount(), "early outcomes must not mint")
						assert.Equal(t, lookups, harness.BuildkiteMock.RequestCount(), "early outcomes must not look up repositories")
					})
				}

				// Prove preservation before exercising supported mismatches: pipeline
				// mismatches intentionally invalidate cache entries, outside this change.

				response, _ := request(t, prof.endpoint, token, validBody)
				require.Equal(t, http.StatusOK, response.StatusCode)
				assert.Contains(t, string(response.Body), "\npassword=ghs_path_presence\n", "early contexts must leave valid credentials usable")
				assert.Equal(t, 1, harness.GitHubMock.TokenRequestCount())
				jsonResponse, status, err := harness.Client().RequestJSON(http.MethodPost, prof.tokenEndpoint, token, nil)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
				assert.Equal(t, "ghs_path_presence", jsonResponse["token"], "token endpoints retain their cache and JSON response")
				assert.Equal(t, 1, harness.GitHubMock.TokenRequestCount())

				// Both host-only spellings retain their profile-specific outcomes,
				// even when a token-endpoint response was cached without a URL.
				for _, path := range hostCredentialPaths {
					t.Run("supported/"+path.name, func(t *testing.T) {
						response, entry := request(t, prof.endpoint, token, "protocol=https\nhost=github.com\n"+path.property)
						switch prof.name {
						case "caller-scoped":
							assert.Equal(t, http.StatusBadRequest, response.StatusCode)
							assert.Empty(t, response.Body)
							assert.NotEmpty(t, response.Headers.Get("Chinmina-Denied"))
						case "wildcard":
							assert.Equal(t, http.StatusOK, response.StatusCode)
							assert.Contains(t, string(response.Body), "\npassword=ghs_path_presence\n")
							assert.Empty(t, entry.Error)
						default:
							assert.Equal(t, http.StatusOK, response.StatusCode)
							assert.Empty(t, response.Body)
							assert.Equal(t, audit.SkippedSuccessMessage, entry.Error)
						}
					})
				}
			})
		}
	}
}

func TestIntegrationGitCredentials_ContextAuthenticationPrecedence(t *testing.T) {
	harness := newCredentialPathHarness(t)
	for _, endpoint := range []string{"/git-credentials", "/git-credentials/default", "/organization/git-credentials/all-repos-profile"} {
		for _, body := range []string{"", "protocol=http\nhost=github.com\n"} {
			for _, token := range []string{"", "invalid-jwt"} {
				t.Run(endpoint+"/"+body+"/"+token, func(t *testing.T) {
					response, err := harness.Client().Request(http.MethodPost, endpoint, token, strings.NewReader(body))
					require.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
				})
			}
		}
	}
	assert.Zero(t, harness.GitHubMock.TokenRequestCount())
	assert.Zero(t, harness.BuildkiteMock.RequestCount())
}

func TestIntegrationGitCredentials_ContextProfilePrecedence(t *testing.T) {
	harness := newCredentialPathHarness(t)
	contents, err := os.ReadFile("testdata/org-profiles-matched.yaml")
	require.NoError(t, err)
	harness.UpdateProfiles(t, string(contents))
	request := auditedGitCredentialRequest(t, harness)
	token := harness.PipelineToken()
	for _, prof := range []struct {
		endpoint, name string
		status         int
	}{
		{"/git-credentials/unknown", "unknown", http.StatusNotFound},
		{"/organization/git-credentials/unknown", "unknown", http.StatusNotFound},
		{"/organization/git-credentials/release-only-profile", "release-only-profile", http.StatusForbidden},
	} {
		t.Run(prof.endpoint, func(t *testing.T) {
			for _, tc := range []credentialContextCase{
				{name: "empty", status: http.StatusOK},
				{name: "unsupported", body: "protocol=http\nhost=github.com\n", repository: "http://github.com", status: http.StatusOK},
			} {
				t.Run(tc.name, func(t *testing.T) {
					response, entry := request(t, prof.endpoint, token, tc.body)
					assert.Equal(t, credentialResponseHeaders{Status: http.StatusOK, ContentType: "text/plain"}, credentialHeaders(response))
					assert.Empty(t, response.Body)
					assert.Equal(t, "0", response.Headers.Get("Content-Length"))
					assert.Equal(t, credentialAudit{RequestedProfile: prof.name, RequestedRepository: tc.repository}, credentialAuditFields(entry))
					assert.Equal(t, audit.SkippedSuccessMessage, entry.Error)
				})
			}
			response, entry := request(t, prof.endpoint, token, "protocol=https\nhost=github.com\n")
			assert.Equal(t, prof.status, response.StatusCode)
			assert.NotEmpty(t, response.Headers.Get("Chinmina-Denied"))
			assert.Empty(t, response.Body)
			assert.NotEqual(t, audit.SkippedSuccessMessage, entry.Error)
		})
	}
	assert.Zero(t, harness.GitHubMock.TokenRequestCount())
	assert.Zero(t, harness.BuildkiteMock.RequestCount())
}
