package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
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

// registryResolver stands in for the app registry: a set of resolvable
// identities, mutable between requests so a test can withdraw one the way
// a restart with different configuration would.
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

// TestRoutes_WarmCacheEntryDoesNotBypassAppResolution is the acceptance
// observable for resolving the app at the handler boundary rather than inside
// the vendor chain.
//
// The chain is Audit -> Authorized -> Cached -> Vending, and Cached
// short-circuits on a hit before Vending runs. A registry check placed inside
// the chain would therefore be absent on exactly the requests that need it:
// those whose profile was valid long enough to warm an entry and has since had
// its app disabled. This test fails if resolution is ever moved into the
// vendor chain, which is the reason it exists.
func TestRoutes_WarmCacheEntryDoesNotBypassAppResolution(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, appProfilesYAML, usableApps("packages"))
	registry := newRegistryResolver(defaultAppIdentity, packagesAppIdentity)

	vends := 0
	chain := orgChain(t, func(context.Context, []string, []string) (string, time.Time, error) {
		vends++
		return "minted-token", defaultExpiry, nil
	})

	handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve))

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

	// The app becomes unresolvable — an operator removed it, or this instance
	// restarted and disabled it at verification.
	registry.withdraw("packages")

	after := serve()

	assert.Equal(t, http.StatusInternalServerError, after.Code,
		"an unresolvable app is our defect, not GitHub's denial")
	assert.NotContains(t, after.Body.String(), "minted-token",
		"the cached token must not be served once its app cannot be resolved")
	assert.Equal(t, 1, vends, "no new token may be minted either")
}

// A request against a profile bound to a non-default app mints through that
// app and is attributed to it in both the response and the audit entry.
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
			// An omitted app property compiles to the default app, so this is
			// indistinguishable from an explicit `app: default`.
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

			handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve))

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
			assert.Equal(t, tt.expectedApp.Name, response.App)

			assert.Equal(t, tt.expectedApp.Name, entry.App)
		})
	}
}

// The app is stamped at resolution rather than at vend, so an outcome reached
// after resolution still names the app it was attempted through. Without this
// a failed mint would be the one case with no attribution — exactly the case
// an operator is looking at.
func TestRoutes_AuditEntryNamesTheAppWhenMintingFails(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, appProfilesYAML, usableApps("packages"))
	registry := newRegistryResolver(defaultAppIdentity, packagesAppIdentity)

	chain := orgChain(t, func(context.Context, []string, []string) (string, time.Time, error) {
		return "", time.Time{}, assert.AnError
	})

	handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve))

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/publish-packages", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "publish-packages")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "packages", entry.App)
	assert.NotEmpty(t, entry.Error)
}

// A profile invalid because its app is disabled fails before an app is
// resolved, so the audit entry carries the reason rather than an app name.
func TestRoutes_DisabledAppMakesTheProfileUnavailable(t *testing.T) {
	// Compiled with no registry: `app: packages` names nothing usable.
	store := profiletest.CreateTestProfileStore(t, appProfilesYAML)
	registry := newRegistryResolver(defaultAppIdentity)

	chain := orgChain(t, func(context.Context, []string, []string) (string, time.Time, error) {
		t.Fatal("an unavailable profile must not reach the vendor")
		return "", time.Time{}, nil
	})

	handler := handlePostToken(chain, NewOrgProfileResolver(store.GetOrganizationProfile, registry.Resolve))

	ctx, entry := audit.Context(claimsContext())
	req, err := http.NewRequestWithContext(ctx, "POST", "/organization/token/publish-packages", nil)
	require.NoError(t, err)
	req.SetPathValue("profile", "publish-packages")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Empty(t, entry.App, "no app was resolved, so none may be attributed")
	assert.Contains(t, entry.Error, "packages", "the audit entry must record why the profile is unavailable")
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
