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

func recordingVendor() (vendor.ProfileTokenVendor, *int) {
	calls := 0
	v := vendor.ProfileTokenVendor(func(ctx context.Context, ref profile.ProfileRef, repo string) vendor.VendorResult {
		calls++
		return vendor.NewVendorSuccess(vendor.ProfileToken{Token: "delegated-token"})
	})
	return v, &calls
}

func TestMatched_OrgProfile_MatchSuccess(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
	inner, calls := recordingVendor()
	m := vendor.Matched(vendor.OrgMatcherLookup(store))(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	}

	result := m(createTestClaimsContextWithPipeline("prod-pipeline"), ref, "")
	assertVendorTokenValue(t, result, "delegated-token")
	assert.Equal(t, 1, *calls)
}

func TestMatched_OrgProfile_MatchDenied(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
	inner, calls := recordingVendor()
	m := vendor.Matched(vendor.OrgMatcherLookup(store))(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeOrg,
		Name:         "prod-deploy",
	}

	result := m(createTestClaimsContextWithPipeline("attacker-pipeline"), ref, "")
	assertVendorFailure(t, result, "match conditions not met")
	assert.Equal(t, 0, *calls, "wrapped vendor must not be called on a denied match")
}

func TestMatched_RepoProfile_MatchSuccess(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingVendor()
	m := vendor.Matched(vendor.RepoMatcherLookup(store))(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "with-match-rules",
		PipelineID:   "pipeline-id",
		PipelineSlug: "security-scanner", // matches "^security-.*"
	}

	result := m(createTestClaimsContextWithPipeline("security-scanner"), ref, "")
	assertVendorTokenValue(t, result, "delegated-token")
	assert.Equal(t, 1, *calls)
}

func TestMatched_RepoProfile_MatchDenied(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingVendor()
	m := vendor.Matched(vendor.RepoMatcherLookup(store))(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "with-match-rules",
		PipelineID:   "pipeline-id",
		PipelineSlug: "normal-pipeline", // does not match "^security-.*"
	}

	result := m(createTestClaimsContextWithPipeline("normal-pipeline"), ref, "")
	assertVendorFailure(t, result, "match conditions not met")
	assert.Equal(t, 0, *calls, "wrapped vendor must not be called on a denied match")
}

// TestMatched_EmptyMatchRules covers the most common production path: the
// built-in "default" pipeline profile has no match rules and must always
// delegate.
func TestMatched_EmptyMatchRules(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingVendor()
	m := vendor.Matched(vendor.RepoMatcherLookup(store))(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "default",
		PipelineID:   "pipeline-id",
		PipelineSlug: "any-pipeline",
	}

	result := m(createTestClaimsContextWithPipeline("any-pipeline"), ref, "")
	assertVendorTokenValue(t, result, "delegated-token")
	assert.Equal(t, 1, *calls)
}

func TestMatched_ProfileNotFound(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingVendor()
	m := vendor.Matched(vendor.RepoMatcherLookup(store))(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "nonexistent-profile",
		PipelineID:   "pipeline-id",
		PipelineSlug: "any-pipeline",
	}

	result := m(createTestClaimsContextWithPipeline("any-pipeline"), ref, "")
	assertVendorFailure(t, result, "could not find profile")
	assert.Equal(t, 0, *calls)
}

// TestMatched_ProfileTypeMismatch covers a misassembled vendor chain: the gate
// must fail rather than resolve the name in the other profile namespace, where
// an unrelated profile of the same name could supply the match rules.
func TestMatched_ProfileTypeMismatch(t *testing.T) {
	tests := []struct {
		name    string
		lookup  vendor.MatcherLookup
		refType profile.ProfileType
	}{
		{
			name:    "org gate rejects repo ref",
			lookup:  vendor.OrgMatcherLookup(profiletest.CreateTestProfileStore(t, orgMatchYAML)),
			refType: profile.ProfileTypeRepo,
		},
		{
			name:    "repo gate rejects org ref",
			lookup:  vendor.RepoMatcherLookup(profiletest.CreateTestProfileStore(t, orgMatchYAML)),
			refType: profile.ProfileTypeOrg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner, calls := recordingVendor()
			m := vendor.Matched(tt.lookup)(inner)

			ref := profile.ProfileRef{
				Organization: "organization-slug",
				Type:         tt.refType,
				Name:         "prod-deploy",
				PipelineSlug: "prod-pipeline",
			}

			result := m(createTestClaimsContextWithPipeline("prod-pipeline"), ref, "")
			assertVendorFailure(t, result, "profile type mismatch")
			assert.Equal(t, 0, *calls, "wrapped vendor must not be called on a type mismatch")
		})
	}
}

func TestMatched_ValidationError(t *testing.T) {
	store := profiletest.CreateTestProfileStore(t, pipelineProfilesYAML)
	inner, calls := recordingVendor()
	m := vendor.Matched(vendor.RepoMatcherLookup(store))(inner)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Type:         profile.ProfileTypeRepo,
		Name:         "with-match-rules",
		PipelineID:   "pipeline-id",
		PipelineSlug: "security scanner", // contains a space: fails claim validation
	}

	// "with-match-rules" matches on pipeline_slug, so the invalid value is
	// looked up and rejected before any pattern comparison happens.
	result := m(createTestClaimsContextWithPipeline("security scanner"), ref, "")
	assertVendorFailure(t, result, "profile match evaluation failed")
	assert.Equal(t, 0, *calls)
}

func TestMatched_AuditLogging(t *testing.T) {
	inner, _ := recordingVendor()

	t.Run("success populates ClaimsMatched", func(t *testing.T) {
		store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
		m := vendor.Matched(vendor.OrgMatcherLookup(store))(inner)

		auditCtx, entry := audit.Context(context.Background())
		claims := &jwt.BuildkiteClaims{
			OrganizationSlug: "organization-slug",
			PipelineSlug:     "prod-pipeline",
		}
		ctx := jwt.ContextWithBuildkiteClaims(auditCtx, claims)

		ref := profile.ProfileRef{
			Organization: "organization-slug",
			Type:         profile.ProfileTypeOrg,
			Name:         "prod-deploy",
		}

		result := m(ctx, ref, "")
		assertVendorTokenValue(t, result, "delegated-token")
		assert.Equal(t, []audit.ClaimMatch{{Claim: "pipeline_slug", Value: "prod-pipeline"}}, entry.ClaimsMatched)
		assert.Nil(t, entry.ClaimsFailed)
	})

	t.Run("failure populates ClaimsFailed", func(t *testing.T) {
		store := profiletest.CreateTestProfileStore(t, orgMatchYAML)
		m := vendor.Matched(vendor.OrgMatcherLookup(store))(inner)

		auditCtx, entry := audit.Context(context.Background())
		claims := &jwt.BuildkiteClaims{
			OrganizationSlug: "organization-slug",
			PipelineSlug:     "attacker-pipeline",
		}
		ctx := jwt.ContextWithBuildkiteClaims(auditCtx, claims)

		ref := profile.ProfileRef{
			Organization: "organization-slug",
			Type:         profile.ProfileTypeOrg,
			Name:         "prod-deploy",
		}

		result := m(ctx, ref, "")
		assertVendorFailure(t, result, "match conditions not met")
		assert.NotEmpty(t, entry.ClaimsFailed)
		assert.Nil(t, entry.ClaimsMatched)
	})
}
