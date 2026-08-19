package vendor_test

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cacheAttr is the profile attribute type the cache tests instantiate the
// chain with. Cached is agnostic to it — the organization/pipeline branch
// reads Resolved.Ref.Type, not T — so a single instantiation covers every
// path.
type cacheAttr = profile.OrganizationProfileAttr

// newTestCached creates a Cached vendor with the specified TTL. The
// configuration generation comes from each request's Resolved value, so it is
// chosen per call by cacheRequest / cacheRequestAt, not here.
func newTestCached(t *testing.T, ttl time.Duration) func(vendor.ProfileTokenVendor[cacheAttr]) vendor.ProfileTokenVendor[cacheAttr] {
	t.Helper()
	tokenCache, err := cache.NewMemory[vendor.ProfileToken](ttl, 10_000)
	require.NoError(t, err)
	return vendor.Cached[cacheAttr](tokenCache)
}

// testGeneration stands in for the configuration digest the boundary resolver
// stamps. Tests that do not care which generation they resolved from share it,
// so they all address one namespace.
const testGeneration = "test-generation"

// testApp stands in for the app identity the boundary resolver stamps. Cached
// refuses a zero identity, so every helper here supplies one.
var testApp = github.AppIdentity{Name: "default", ApplicationID: 111, InstallationID: 222}

// cacheRequest wraps a ref the way the handler boundary would, for tests that
// exercise the cache without depending on the resolved profile value.
func cacheRequest(ref profile.ProfileRef) vendor.Resolved[cacheAttr] {
	return cacheRequestAt(ref, testGeneration)
}

// cacheRequestAt wraps a ref as cacheRequest does, pinning the configuration
// generation the request was resolved from.
func cacheRequestAt(ref profile.ProfileRef, digest string) vendor.Resolved[cacheAttr] {
	return vendor.Resolved[cacheAttr]{Ref: ref, Digest: digest, App: testApp}
}

// resolvedOrg builds the Resolved value the organization boundary resolver
// would produce for ref, reading the profile and digest from store.
func resolvedOrg(t *testing.T, store *profile.ProfileStore, ref profile.ProfileRef) vendor.Resolved[profile.OrganizationProfileAttr] {
	t.Helper()
	authProfile, digest, err := store.GetOrganizationProfile(ref.Name)
	require.NoError(t, err)
	return vendor.Resolved[profile.OrganizationProfileAttr]{Ref: ref, Profile: authProfile, Digest: digest, App: testApp}
}

// resolvedPipeline builds the Resolved value the pipeline boundary resolver
// would produce for ref, reading the profile and digest from store.
func resolvedPipeline(t *testing.T, store *profile.ProfileStore, ref profile.ProfileRef) vendor.Resolved[profile.PipelineProfileAttr] {
	t.Helper()
	authProfile, digest, err := store.GetPipelineProfile(ref.Name)
	require.NoError(t, err)
	return vendor.Resolved[profile.PipelineProfileAttr]{Ref: ref, Profile: authProfile, Digest: digest, App: testApp}
}

// mintingThrough adapts a plain token vendor to the app-aware signature.
func mintingThrough(mint vendor.TokenVendor) vendor.AppTokenVendor {
	return func(ctx context.Context, _ github.AppIdentity, repoNames []string, scopes []string) (string, time.Time, error) {
		return mint(ctx, repoNames, scopes)
	}
}

// assertVendorSuccess verifies that vending succeeded and returns the expected token
func assertVendorSuccess(t *testing.T, result vendor.VendorResult, expected vendor.ProfileToken) {
	t.Helper()
	require.Equal(t, vendor.VendStatusSuccess, result.Status(), "expected vendor to succeed")
	assert.Equal(t, expected, result.Token())
}

func assertVendorTokenValue(t *testing.T, result vendor.VendorResult, expected string) {
	t.Helper()
	require.Equal(t, vendor.VendStatusSuccess, result.Status(), "expected vendor to succeed")
	assert.Equal(t, expected, result.Token().Token)
}

// assertVendorUnmatched verifies that vending succeeded but no token was returned (unmatched case)
func assertVendorUnmatched(t *testing.T, result vendor.VendorResult) {
	t.Helper()
	require.Equal(t, vendor.VendStatusSuccessUnmatched, result.Status(), "expected vendor to succeed with no match")
}

// assertVendorFailure verifies that vending failed with the expected error
func assertVendorFailure(t *testing.T, result vendor.VendorResult, expectedErrorSubstring string) {
	t.Helper()
	require.Equal(t, vendor.VendStatusFailed, result.Status(), "expected vendor to fail")
	require.ErrorContains(t, result.Err(), expectedErrorSubstring)
}

// createTestClaimsContextWithPipeline creates a context with JWT claims for testing,
// allowing specification of the pipeline slug.
func createTestClaimsContextWithPipeline(pipelineSlug string) context.Context {
	claims := &jwt.BuildkiteClaims{
		OrganizationSlug: "organization-slug",
		PipelineSlug:     pipelineSlug,
		PipelineID:       "pipeline-id",
		BuildBranch:      "main",
	}

	return jwt.ContextWithBuildkiteClaims(context.Background(), claims)
}
