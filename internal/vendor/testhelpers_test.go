package vendor_test

import (
	"context"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDigester returns a fixed digest for testing
type mockDigester struct {
	digest string
}

func (m mockDigester) Digest() string {
	return m.digest
}

// cacheAttr is the profile attribute type the cache tests instantiate the
// chain with. Cached is agnostic to it — the organization/pipeline branch
// reads Resolved.Ref.Type, not T — so a single instantiation covers every
// path.
type cacheAttr = profile.OrganizationProfileAttr

// newTestCached creates a Cached vendor with the specified TTL and digest
func newTestCached(t *testing.T, ttl time.Duration, digest string) func(vendor.ProfileTokenVendor[cacheAttr]) vendor.ProfileTokenVendor[cacheAttr] {
	t.Helper()
	tokenCache, err := cache.NewMemory[vendor.ProfileToken](ttl, 10_000)
	require.NoError(t, err)
	digester := mockDigester{digest: digest}
	return vendor.Cached[cacheAttr](tokenCache, digester)
}

// cacheRequest wraps a ref the way the handler boundary would, for tests that
// exercise the cache without depending on the resolved profile value.
func cacheRequest(ref profile.ProfileRef) vendor.Resolved[cacheAttr] {
	return vendor.Resolved[cacheAttr]{Ref: ref}
}

// resolvedOrg builds the Resolved value the organization boundary resolver
// would produce for ref, reading the profile and digest from store.
func resolvedOrg(t *testing.T, store *profile.ProfileStore, ref profile.ProfileRef) vendor.Resolved[profile.OrganizationProfileAttr] {
	t.Helper()
	authProfile, digest, err := store.GetOrganizationProfile(ref.Name)
	require.NoError(t, err)
	return vendor.Resolved[profile.OrganizationProfileAttr]{Ref: ref, Profile: authProfile, Digest: digest}
}

// resolvedPipeline builds the Resolved value the pipeline boundary resolver
// would produce for ref, reading the profile and digest from store.
func resolvedPipeline(t *testing.T, store *profile.ProfileStore, ref profile.ProfileRef) vendor.Resolved[profile.PipelineProfileAttr] {
	t.Helper()
	authProfile, digest, err := store.GetPipelineProfile(ref.Name)
	require.NoError(t, err)
	return vendor.Resolved[profile.PipelineProfileAttr]{Ref: ref, Profile: authProfile, Digest: digest}
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
