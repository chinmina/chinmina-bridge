//go:build integration

package main

import (
	"net/http"
	"sync"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/jwt/jwxtest"
	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	packagesAppID          = int64(333)
	packagesInstallationID = int64(444)

	// defaultAccountID matches the mock's default installation account, which
	// the default app resolves to. Registry apps sharing it are enabled.
	defaultAccountID = int64(1)
	otherAccountID   = int64(99)
)

const multiAppProfiles = `organization:
  profiles:
    - name: publish-packages
      app: packages
      repositories:
        - test-repo
      permissions:
        - contents:read
    - name: read-source
      repositories:
        - test-repo
      permissions:
        - contents:read
`

// packagesApp is a registry entry pointed at the harness's mock. Its key is
// any valid RSA key: the mock does not verify the App JWT, and what is under
// test is which installation was contacted, not how it was authenticated.
func packagesApp(t *testing.T) GitHubAppEntry {
	t.Helper()

	return GitHubAppEntry{
		Name:           "packages",
		ApplicationID:  packagesAppID,
		InstallationID: packagesInstallationID,
		PrivateKey:     jwxtest.NewJWK(t).PrivateKeyPEM(),
	}
}

// enabledPackagesInstallation puts the packages app on the default app's
// account, so verification enables it, and gives it its own token so a
// response can be attributed to it.
func enabledPackagesInstallation() testhelpers.MockInstallation {
	return testhelpers.MockInstallation{
		AccountID:    defaultAccountID,
		AccountLogin: "test-org",
		Token:        "packages-installation-token",
	}
}

// A profile bound to a second app must mint through that app's installation,
// and say so: the response body is how an operator attributes a credential to
// the app that issued it.
func TestIntegrationMultiApp_VendsThroughTheProfilesApp(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, enabledPackagesInstallation()),
		WithGitHubApps(packagesApp(t)),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	token, err := harness.Client().OrganizationToken(harness.PipelineToken(), "publish-packages")
	require.NoError(t, err)

	assert.Equal(t, "packages-installation-token", token.Token,
		"the token must come from the named app's installation")
	assert.Equal(t, "packages", token.App)
	assert.Positive(t, harness.GitHubMock.CallsForInstallation(packagesInstallationID))
}

// A profile with no app property mints through the default app, unchanged from
// how the service behaved before an app could be named at all.
func TestIntegrationMultiApp_ProfileWithoutAnAppUsesTheDefault(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, enabledPackagesInstallation()),
		WithGitHubApps(packagesApp(t)),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	token, err := harness.Client().OrganizationToken(harness.PipelineToken(), "read-source")
	require.NoError(t, err)

	assert.Equal(t, "test-github-token", token.Token)
	assert.Equal(t, "default", token.App)
}

// An app on a different account is disabled at startup, so a profile naming it
// is invalid and the request is refused. Falling back to a different
// credential is the hazard this feature exists to avoid, so "unavailable" is
// the correct answer even though a working default app is right there.
func TestIntegrationMultiApp_ProfileNamingADisabledAppIsUnavailable(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, testhelpers.MockInstallation{
			AccountID:    otherAccountID,
			AccountLogin: "someone-else",
		}),
		WithGitHubApps(packagesApp(t)),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	_, err := harness.Client().OrganizationToken(harness.PipelineToken(), "publish-packages")

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)

	// Isolation: one disabled app must not withdraw every other profile.
	_, err = harness.Client().OrganizationToken(harness.PipelineToken(), "read-source")
	assert.NoError(t, err)
}

// An app whose installation cannot be queried is disabled rather than fatal,
// so the service starts and every other profile keeps working.
func TestIntegrationMultiApp_UnreachableInstallationDisablesOnlyThatApp(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, testhelpers.MockInstallation{
			StatusCode: http.StatusInternalServerError,
		}),
		WithGitHubApps(packagesApp(t)),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	_, err := harness.Client().OrganizationToken(harness.PipelineToken(), "publish-packages")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)

	token, err := harness.Client().OrganizationToken(harness.PipelineToken(), "read-source")
	require.NoError(t, err)
	assert.Equal(t, "default", token.App)
}

// Two profiles resolving through different apps must not share cache entries:
// each response has to carry the token its own app minted, however many times
// the pair is requested.
func TestIntegrationMultiApp_AppsDoNotShareCacheEntries(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, enabledPackagesInstallation()),
		WithGitHubApps(packagesApp(t)),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	for range 3 {
		packages, err := harness.Client().OrganizationToken(harness.PipelineToken(), "publish-packages")
		require.NoError(t, err)
		assert.Equal(t, "packages-installation-token", packages.Token)

		source, err := harness.Client().OrganizationToken(harness.PipelineToken(), "read-source")
		require.NoError(t, err)
		assert.Equal(t, "test-github-token", source.Token)
	}
}

// The registry is built once and never written afterwards, so parallel
// requests across apps need no synchronisation. Under -race this fails if a
// future change introduces lazily-populated registry state.
func TestIntegrationMultiApp_ParallelRequestsAcrossApps(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, enabledPackagesInstallation()),
		WithGitHubApps(packagesApp(t)),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	expected := map[string]string{
		"publish-packages": "packages-installation-token",
		"read-source":      "test-github-token",
	}

	var wg sync.WaitGroup
	for range 10 {
		for profileName, expectedToken := range expected {
			wg.Go(func() {
				token, err := harness.Client().OrganizationToken(harness.PipelineToken(), profileName)
				if assert.NoError(t, err) {
					assert.Equal(t, expectedToken, token.Token)
				}
			})
		}
	}
	wg.Wait()
}

// A deployment not using the feature must pay nothing for its existence: no
// GITHUB_APPS means no installation is queried at startup.
func TestIntegrationMultiApp_NoRegistryQueriesNoInstallation(t *testing.T) {
	harness := NewAPITestHarness(t)

	assert.Equal(t, 0, harness.GitHubMock.InstallationQueryCount())

	token, err := harness.Client().Token(harness.PipelineToken(), "")
	require.NoError(t, err)
	assert.Equal(t, "default", token.App)
}
