package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/credentialhandler"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const appProfilesYAML = `organization:
  profiles:
    - name: publish-packages
      app: packages
      repositories:
        - repo1
      permissions:
        - contents:read
    - name: default-app-profile
      repositories:
        - repo1
      permissions:
        - contents:read

pipeline:
  defaults:
    permissions:
      - contents:read
`

var (
	defaultAppIdentity  = github.AppIdentity{Name: "default", ApplicationID: 111, InstallationID: 222}
	packagesAppIdentity = github.AppIdentity{Name: "packages", ApplicationID: 333, InstallationID: 444}
)

// registryResolver stands in for the app registry. Its identities are mutable
// between requests, so a test can withdraw one mid-test.
type registryResolver struct {
	apps map[string]github.AppIdentity
}

func (r *registryResolver) Resolve(name string) (github.AppIdentity, bool) {
	app, found := r.apps[name]
	return app, found
}

func (r *registryResolver) withdraw(name string) {
	delete(r.apps, name)
}

func newRegistryResolver(apps ...github.AppIdentity) *registryResolver {
	byName := make(map[string]github.AppIdentity, len(apps))
	for _, app := range apps {
		byName[app.Name] = app
	}
	return &registryResolver{apps: byName}
}

// Cached short-circuits on a hit before Vending runs, so a registry check
// placed inside the vendor chain would be skipped on exactly the requests that
// need it: those warmed while the profile was valid, whose app has since been
// disabled. Resolution therefore belongs at the handler boundary.
func TestRoutes_WarmCacheEntryDoesNotBypassAppResolution(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, appProfilesYAML, usableApps("packages"))
	registry := newRegistryResolver(defaultAppIdentity, packagesAppIdentity)

	vends := 0
	chain := orgChain(t, func(context.Context, []string, []string) (string, time.Time, error) {
		vends++
		return "minted-token", defaultExpiry, nil
	})

	handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve), withheld)

	serve := func() *httptest.ResponseRecorder {
		ctx, _ := audit.Context(claimsContext())
		req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/publish-packages", nil)
		require.NoError(t, err)
		req.SetPathValue("profile", "publish-packages")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	warm := serve()
	require.Equal(t, http.StatusOK, warm.Code, "the entry must be warm before the app is withdrawn")
	require.Equal(t, 1, vends)

	// In production this is a restart that disables the app at verification.
	registry.withdraw("packages")

	after := serve()

	assert.Equal(t, http.StatusInternalServerError, after.Code,
		"an unresolvable app is our defect, not GitHub's denial")
	assert.NotContains(t, after.Body.String(), "minted-token",
		"the cached token must not be served once its app cannot be resolved")
	assert.Equal(t, 1, vends, "no new token may be minted either")
}

func TestRoutes_MintThroughTheResolvedApp(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		expectedApp github.AppIdentity
	}{
		{
			name:        "a profile naming a registry app",
			profileName: "publish-packages",
			expectedApp: packagesAppIdentity,
		},
		{
			name:        "a profile with no app property",
			profileName: "default-app-profile",
			expectedApp: defaultAppIdentity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := profiletest.CreateTestProfileStore(t, appProfilesYAML, usableApps("packages"))
			registry := newRegistryResolver(defaultAppIdentity, packagesAppIdentity)

			var mintedThrough github.AppIdentity
			chain := vendor.Auditor(vendor.Authorized(vendor.Cached[orgAttr](testTokenCache(t))(
				vendor.Vending(vendor.OrgRepositories,
					func(_ context.Context, app github.AppIdentity, _ []string, _ []string) (string, time.Time, error) {
						mintedThrough = app
						return "minted-token", defaultExpiry, nil
					}),
			)))

			handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve), disclosed)

			ctx, entry := audit.Context(claimsContext())
			req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/"+tt.profileName, nil)
			require.NoError(t, err)
			req.SetPathValue("profile", tt.profileName)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)

			assert.Equal(t, tt.expectedApp, mintedThrough,
				"the token must be minted through the installation the profile named")

			var response vendor.ProfileToken
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
			assert.Equal(t, tt.expectedApp, github.AppIdentity{
				Name:           response.App,
				ApplicationID:  response.ApplicationID,
				InstallationID: response.InstallationID,
			}, "the disclosed response must name the installation the mint went through")

			assert.Equal(t, tt.expectedApp, auditedApp(entry),
				"the audit entry must identify the installation, not just its repointable name")
		})
	}
}

// The app is stamped at resolution rather than at vend, so a failed mint is
// still attributed to the app it was attempted through.
func TestRoutes_AuditEntryNamesTheAppWhenMintingFails(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, appProfilesYAML, usableApps("packages"))
	registry := newRegistryResolver(defaultAppIdentity, packagesAppIdentity)

	chain := orgChain(t, func(context.Context, []string, []string) (string, time.Time, error) {
		return "", time.Time{}, assert.AnError
	})

	handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve), withheld)

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/publish-packages", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "publish-packages")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, packagesAppIdentity, auditedApp(entry))
	assert.NotEmpty(t, entry.Error)
}

// A profile invalid because its app is disabled fails before any app is
// resolved: the audit entry carries the reason, not an app name.
func TestRoutes_DisabledAppMakesTheProfileUnavailable(t *testing.T) {
	// Compiled with no registry: `app: packages` names nothing usable.
	store := profiletest.CreateTestProfileStore(t, appProfilesYAML)
	registry := newRegistryResolver(defaultAppIdentity)

	chain := orgChain(t, func(context.Context, []string, []string) (string, time.Time, error) {
		t.Fatal("an unavailable profile must not reach the vendor")
		return "", time.Time{}, nil
	})

	handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve), withheld)

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/publish-packages", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "publish-packages")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, github.AppIdentity{}, auditedApp(entry),
		"no app was resolved, so none may be attributed")
	assert.Contains(t, entry.Error, "packages", "the audit entry must record why the profile is unavailable")
}

func auditedApp(entry *audit.Entry) github.AppIdentity {
	return github.AppIdentity{
		Name:           entry.App,
		ApplicationID:  entry.ApplicationID,
		InstallationID: entry.InstallationID,
	}
}

// usableApps builds the compilation-time lookup over a set of enabled names.
func usableApps(names ...string) profile.AppLookup {
	usable := map[string]struct{}{"default": {}}
	for _, name := range names {
		usable[name] = struct{}{}
	}

	return func(name string) bool {
		_, found := usable[name]
		return found
	}
}

var (
	withheld  = newTokenResponseMarshaler(false)
	disclosed = newTokenResponseMarshaler(true)
)

func packagesOrgChain(t *testing.T) (vendor.ProfileTokenVendor[orgAttr], ProfileResolver[orgAttr]) {
	t.Helper()

	store := profiletest.CreateTestProfileStore(t, appProfilesYAML, usableApps("packages"))
	registry := newRegistryResolver(defaultAppIdentity, packagesAppIdentity)
	chain := orgChain(t, func(context.Context, []string, []string) (string, time.Time, error) {
		return "minted-token", defaultExpiry, nil
	})

	return chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve)
}

func serveOrgToken(t *testing.T, marshaler TokenResponseMarshaler, profileName string) (*httptest.ResponseRecorder, *audit.Entry) {
	t.Helper()

	chain, resolve := packagesOrgChain(t)
	handler := handlePostToken(chain, resolve, marshaler)

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/"+profileName, nil)
	require.NoError(t, err)
	req.SetPathValue("profile", profileName)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	return rr, entry
}

// Substring-matching the body would also hit the hashed token, so assertions
// run on the decoded object.
func TestRoutes_TokenResponseDisclosesIdentifiersOnlyWhenConfigured(t *testing.T) {
	tests := []struct {
		name      string
		marshaler TokenResponseMarshaler
		expected  map[string]any
		absent    []string
	}{
		{
			name:      "withholding is the production default",
			marshaler: withheld,
			expected:  map[string]any{"app": "packages"},
			absent:    []string{"appId", "installationId"},
		},
		{
			name:      "disclosing carries both identifiers",
			marshaler: disclosed,
			expected: map[string]any{
				"app":            "packages",
				"appId":          float64(packagesAppIdentity.ApplicationID),
				"installationId": float64(packagesAppIdentity.InstallationID),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, _ := serveOrgToken(t, tt.marshaler, "publish-packages")

			var response map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))

			for key, want := range tt.expected {
				assert.Equal(t, want, response[key])
			}
			for _, key := range tt.absent {
				assert.NotContains(t, response, key)
			}
		})
	}
}

// Both halves read from the same request, so neither can be satisfied by a
// fixture that only looks right in isolation.
func TestRoutes_AuditRecordsIdentifiersTheResponseWithholds(t *testing.T) {
	rr, entry := serveOrgToken(t, withheld, "publish-packages")

	var response map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.NotContains(t, response, "appId", "a CI pipeline has no use for the deployment's app topology")
	assert.Equal(t, packagesAppIdentity, auditedApp(entry), "the operator-facing record must still attribute the vend")
}

func TestRoutes_GitCredentialsDiscloseIdentifiersOnlyWhenConfigured(t *testing.T) {
	tests := []struct {
		name      string
		marshaler TokenResponseMarshaler
		expected  string
	}{
		{
			name:      "withholding leaves git's properties untouched",
			marshaler: withheld,
			expected: "protocol=https\nhost=github.com\npath=acme/repo1\n" +
				"username=x-access-token\npassword=minted-token\npassword_expiry_utc=1715104776\n\n",
		},
		{
			name:      "disclosing appends the chinmina properties",
			marshaler: disclosed,
			expected: "protocol=https\nhost=github.com\npath=acme/repo1\n" +
				"username=x-access-token\npassword=minted-token\npassword_expiry_utc=1715104776\n" +
				"chinmina_app_name=packages\nchinmina_app_id=333\nchinmina_installation_id=444\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, resolve := packagesOrgChain(t)
			handler := handlePostGitCredentials(chain, resolve, tt.marshaler)

			props := credentialhandler.NewMap(3)
			props.Set("protocol", "https")
			props.Set("host", "github.com")
			props.Set("path", "acme/repo1")
			body := &bytes.Buffer{}
			require.NoError(t, credentialhandler.WriteProperties(props, body))

			ctx, _ := audit.Context(claimsContext())
			req, err := http.NewRequestWithContext(ctx, "POST", "/organization/git-credentials/publish-packages", body)
			require.NoError(t, err)
			req.SetPathValue("profile", "publish-packages")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tt.expected, rr.Body.String())
		})
	}
}
