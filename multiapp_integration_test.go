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

	// defaultAccountID matches the mock's default installation account.
	// Registry apps sharing it are enabled by verification.
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

// packagesApp is a registry entry pointed at the harness's mock. Any valid RSA
// key will do: the mock does not verify the App JWT.
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
// account, which is what verification requires to enable it.
func enabledPackagesInstallation() testhelpers.MockInstallation {
	return testhelpers.MockInstallation{
		AccountID:    defaultAccountID,
		AccountLogin: "test-org",
		Token:        "packages-installation-token",
	}
}

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

// A profile naming a disabled app is refused rather than falling back to the
// default app: silently vending a different credential is the hazard this
// feature exists to avoid.
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

	// One disabled app must not withdraw every other profile.
	_, err = harness.Client().OrganizationToken(harness.PipelineToken(), "read-source")
	assert.NoError(t, err)
}

// A failed installation query disables that app rather than failing startup.
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

// Repeated interleaved requests: a cache key that ignored the app would return
// one app's token for the other.
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

// The registry is built once and never written afterwards. Under -race this
// fails if a change introduces lazily-populated registry state.
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

// No GITHUB_APPS means no installation is queried at startup.
func TestIntegrationMultiApp_NoRegistryQueriesNoInstallation(t *testing.T) {
	harness := NewAPITestHarness(t)

	assert.Equal(t, 0, harness.GitHubMock.InstallationQueryCount())

	token, err := harness.Client().Token(harness.PipelineToken(), "")
	require.NoError(t, err)
	assert.Equal(t, "default", token.App)
}

// Nothing here hands a flag to the handlers: the shape is whatever
// configureServerRoutes builds from an unset environment.
func TestIntegrationMultiApp_ProductionDefaultWithholdsAppIdentifiers(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, enabledPackagesInstallation()),
		WithGitHubApps(packagesApp(t)),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	response, status, err := harness.Client().RequestJSON(
		"POST", "/organization/token/publish-packages", harness.PipelineToken(), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	assert.Equal(t, "packages", response["app"], "the app name has always been part of the response")
	assert.NotContains(t, response, "appId")
	assert.NotContains(t, response, "installationId")

	props, err := harness.Client().OrganizationGitCredentials(harness.PipelineToken(), "publish-packages",
		GitCredentialRequest{Protocol: "https", Host: "github.com", Path: "test-org/test-repo"})
	require.NoError(t, err)

	for i := props.Iter(); i.HasNext(); {
		k, _ := i.Next()
		assert.NotContains(t, k, "chinmina_", "git must receive only the properties it consumes")
	}
}

// The default-off tests cannot tell a working gate from one wired to a
// constant, so this drives the flag through configureServerRoutes.
func TestIntegrationMultiApp_ConfiguredDisclosureReachesBothFormats(t *testing.T) {
	harness := NewAPITestHarness(t,
		WithInstallation(packagesInstallationID, enabledPackagesInstallation()),
		WithGitHubApps(packagesApp(t)),
		WithDisclosedAppIdentifiers(),
	)
	harness.UpdateProfiles(t, multiAppProfiles)

	response, status, err := harness.Client().RequestJSON(
		"POST", "/organization/token/publish-packages", harness.PipelineToken(), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	assert.Equal(t, float64(packagesAppID), response["appId"])
	assert.Equal(t, float64(packagesInstallationID), response["installationId"])

	props, err := harness.Client().OrganizationGitCredentials(harness.PipelineToken(), "publish-packages",
		GitCredentialRequest{Protocol: "https", Host: "github.com", Path: "test-org/test-repo"})
	require.NoError(t, err)

	assert.Equal(t, "packages", props.Get("chinmina_app_name"))
	assert.Equal(t, "333", props.Get("chinmina_app_id"))
	assert.Equal(t, "444", props.Get("chinmina_installation_id"))
}
