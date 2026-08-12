package vendor_test

import (
	"context"
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/profile/profiletest"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const orgMatchYAML = `
organization:
  profiles:
    - name: prod-deploy
      match:
        - claim: pipeline_slug
          value: prod-pipeline
      repositories:
        - widget
      permissions:
        - contents:write
`

func recordingOrgVendor() (vendor.ProfileTokenVendor[profile.OrganizationProfileAttr], *int) {
	calls := 0
	v := vendor.ProfileTokenVendor[profile.OrganizationProfileAttr](
		func(ctx context.Context, r vendor.Resolved[profile.OrganizationProfileAttr], repo string) vendor.VendorResult {
			calls++
			return vendor.NewVendorSuccess(vendor.ProfileToken{Token: "delegated-token"})
		})
	return v, &calls
}

func recordingPipelineVendor() (vendor.ProfileTokenVendor[profile.PipelineProfileAttr], *int) {
	calls := 0
	v := vendor.ProfileTokenVendor[profile.PipelineProfileAttr](
		func(ctx context.Context, r vendor.Resolved[profile.PipelineProfileAttr], repo string) vendor.VendorResult {
			calls++
			return vendor.NewVendorSuccess(vendor.ProfileToken{Token: "delegated-token"})
		})
	return v, &calls
}

func TestAuthorized_OrgProfile_MatchSuccess(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
	inner, calls := recordingOrgVendor()
	v := vendor.Authorized(inner)

	r := resolvedOrg(t, store, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	})

	result := v(createTestClaimsContextWithPipeline("prod-pipeline"), r, "")
	assertVendorTokenValue(t, result, "delegated-token")
	assert.Equal(t, 1, *calls)
}

func TestAuthorized_OrgProfile_MatchDenied(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
	inner, calls := recordingOrgVendor()
	v := vendor.Authorized(inner)

	r := resolvedOrg(t, store, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	})

	result := v(createTestClaimsContextWithPipeline("attacker-pipeline"), r, "")
	assertVendorFailure(t, result, "match conditions not met")
	assert.Equal(t, 0, *calls, "wrapped vendor must not be called on a denied match")
}

func TestAuthorized_RepoProfile_MatchSuccess(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingPipelineVendor()
	v := vendor.Authorized(inner)

	r := resolvedPipeline(t, store, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "with-match-rules",
		PipelineID:   "pipeline-id",
		PipelineSlug: "security-scanner", // matches "^security-.*"
	})

	result := v(createTestClaimsContextWithPipeline("security-scanner"), r, "")
	assertVendorTokenValue(t, result, "delegated-token")
	assert.Equal(t, 1, *calls)
}

func TestAuthorized_RepoProfile_MatchDenied(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingPipelineVendor()
	v := vendor.Authorized(inner)

	r := resolvedPipeline(t, store, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "with-match-rules",
		PipelineID:   "pipeline-id",
		PipelineSlug: "normal-pipeline", // does not match "^security-.*"
	})

	result := v(createTestClaimsContextWithPipeline("normal-pipeline"), r, "")
	assertVendorFailure(t, result, "match conditions not met")
	assert.Equal(t, 0, *calls, "wrapped vendor must not be called on a denied match")
}

// TestAuthorized_EmptyMatchRules covers the most common production path: the
// built-in "default" pipeline profile has no match rules and must always
// delegate.
func TestAuthorized_EmptyMatchRules(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingPipelineVendor()
	v := vendor.Authorized(inner)

	r := resolvedPipeline(t, store, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "default",
		PipelineID:   "pipeline-id",
		PipelineSlug: "any-pipeline",
	})

	result := v(createTestClaimsContextWithPipeline("any-pipeline"), r, "")
	assertVendorTokenValue(t, result, "delegated-token")
	assert.Equal(t, 1, *calls)
}

func TestAuthorized_ValidationError(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingPipelineVendor()
	v := vendor.Authorized(inner)

	r := resolvedPipeline(t, store, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "with-match-rules",
		PipelineID:   "pipeline-id",
		PipelineSlug: "security scanner", // contains a space: fails claim validation
	})

	// "with-match-rules" matches on pipeline_slug, so the invalid value is
	// looked up and rejected before any pattern comparison happens.
	result := v(createTestClaimsContextWithPipeline("security scanner"), r, "")
	assertVendorFailure(t, result, "profile match evaluation failed")
	assert.Equal(t, 0, *calls)
}

// TestAuthorized_DeniesOnWarmCacheEntry is the regression guard for the
// cache-hit authorization bypass: an unauthorized caller must be refused even
// when the profile's token is already cached, because Authorized is composed
// outside Cached and evaluates the rules on every call.
func TestAuthorized_DeniesOnWarmCacheEntry(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
	inner, calls := recordingOrgVendor()
	chain := vendor.Authorized(newTestCached(t, defaultTTL, "test-digest")(inner))

	r := resolvedOrg(t, store, profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	})

	// warm the cache as the authorized caller
	assertVendorTokenValue(t, chain(createTestClaimsContextWithPipeline("prod-pipeline"), r, ""), "delegated-token")
	assert.Equal(t, 1, *calls)

	// the same profile, requested by a caller the rules exclude
	result := chain(createTestClaimsContextWithPipeline("attacker-pipeline"), r, "")
	assertVendorFailure(t, result, "match conditions not met")
	assert.Equal(t, vendor.VendStatusFailed, result.Status())
	assert.Empty(t, result.Token().Token, "no token may be returned from the cache to an unauthorized caller")
	assert.Equal(t, 1, *calls, "the cached entry must not be served")
}

func TestAuthorized_AuditLogging(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
	inner, _ := recordingOrgVendor()
	v := vendor.Authorized(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	}

	t.Run("success populates ClaimsMatched", func(t *testing.T) {
		auditCtx, entry := audit.Context(context.Background())
		ctx := jwt.ContextWithBuildkiteClaims(auditCtx, &jwt.BuildkiteClaims{
			OrganizationSlug: "organization-slug",
			PipelineSlug:     "prod-pipeline",
		})

		result := v(ctx, resolvedOrg(t, store, ref), "")
		assertVendorTokenValue(t, result, "delegated-token")
		assert.Equal(t, []audit.ClaimMatch{{Claim: "pipeline_slug", Value: "prod-pipeline"}}, entry.ClaimsMatched)
		assert.Nil(t, entry.ClaimsFailed)
	})

	t.Run("failure populates ClaimsFailed", func(t *testing.T) {
		auditCtx, entry := audit.Context(context.Background())
		ctx := jwt.ContextWithBuildkiteClaims(auditCtx, &jwt.BuildkiteClaims{
			OrganizationSlug: "organization-slug",
			PipelineSlug:     "attacker-pipeline",
		})

		result := v(ctx, resolvedOrg(t, store, ref), "")
		assertVendorFailure(t, result, "match conditions not met")
		assert.NotEmpty(t, entry.ClaimsFailed)
		assert.Nil(t, entry.ClaimsMatched)
	})
}

// TestAuthorized_JudgesTheResolvedGeneration proves the authorization decision
// comes from the profile generation the request was resolved from, not from
// whatever the store holds when the chain runs. Re-reading the store here
// would let a mid-flight profile refresh combine one generation's match rules
// with another's permissions.
func TestAuthorized_JudgesTheResolvedGeneration(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
	inner, calls := recordingOrgVendor()
	v := vendor.Authorized(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	}

	// resolved while the rules exclude this caller
	r := resolvedOrg(t, store, ref)

	// the configuration is then replaced by one that would admit the caller
	permissive, err := profiletest.CompileFromYAML(`
organization:
  profiles:
    - name: prod-deploy
      match:
        - claim: pipeline_slug
          valuePattern: ".*"
      repositories:
        - widget
      permissions:
        - contents:write
`)
	require.NoError(t, err)
	store.Update(t.Context(), permissive)

	result := v(createTestClaimsContextWithPipeline("attacker-pipeline"), r, "")
	assertVendorFailure(t, result, "match conditions not met")
	assert.Equal(t, 0, *calls, "authorization must not consult the store a second time")

	// the replacement generation really would admit the caller: without this,
	// the failure above could pass for the wrong reason.
	assertVendorTokenValue(t, v(createTestClaimsContextWithPipeline("attacker-pipeline"), resolvedOrg(t, store, ref), ""), "delegated-token")
}
