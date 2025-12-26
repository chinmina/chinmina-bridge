package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
)

func TestAuditor_Success(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)
	successfulVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) vendor.VendorResult {
		return vendor.NewVendorSuccess(vendor.ProfileToken{
			Repositories:        []string{"https://example.com/repo"},
			Permissions:         []string{"contents:read"},
			VendedRepositoryURL: "https://example.com/repo",
			Expiry:              vendedDate,
		})
	}
	auditedVendor := vendor.Auditor(successfulVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref1 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	result := auditedVendor(ctx, ref1, repo)

	expectedToken := vendor.ProfileToken{
		Repositories:        []string{"https://example.com/repo"},
		Permissions:         []string{"contents:read"},
		VendedRepositoryURL: "https://example.com/repo",
		Expiry:              vendedDate,
	}
	assertVendorSuccess(t, result, expectedToken)

	entry := audit.Log(ctx)
	expected := audit.Entry{
		Error:            "",
		VendedRepository: "https://example.com/repo",
		Repositories:     []string{"https://example.com/repo"},
		Permissions:      []string{"contents:read"},
	}
	// ExpirySecs is dynamic based on current time, so check separately
	assert.Equal(t, expected.Error, entry.Error)
	assert.Equal(t, expected.VendedRepository, entry.VendedRepository)
	assert.Equal(t, expected.Repositories, entry.Repositories)
	assert.Equal(t, expected.Permissions, entry.Permissions)
	assert.NotZero(t, entry.ExpirySecs)

	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "test-profile",
		Type:         profile.ProfileTypeOrg,
		PipelineSlug: "",
	}
	result = auditedVendor(ctx, ref2, repo)

	assertVendorSuccess(t, result, expectedToken)

	entry = audit.Log(ctx)
	expected = audit.Entry{
		Error:            "",
		VendedRepository: "https://example.com/repo",
		Repositories:     []string{"https://example.com/repo"},
		Permissions:      []string{"contents:read"},
	}
	// ExpirySecs is dynamic based on current time, so check separately
	assert.Equal(t, expected.Error, entry.Error)
	assert.Equal(t, expected.VendedRepository, entry.VendedRepository)
	assert.Equal(t, expected.Repositories, entry.Repositories)
	assert.Equal(t, expected.Permissions, entry.Permissions)
	assert.NotZero(t, entry.ExpirySecs)

}

func TestAuditor_Mismatch(t *testing.T) {
	unmatchedVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) vendor.VendorResult {
		return vendor.NewVendorUnmatched()
	}
	auditedVendor := vendor.Auditor(unmatchedVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	result := auditedVendor(ctx, ref, repo)

	assertVendorUnmatched(t, result)

	entry := audit.Log(ctx)
	expected := audit.Entry{
		Error:               "skipped(success): profile has no credentials for requested repository",
		Repositories:        nil,
		Permissions:         nil,
		ExpirySecs:          0,
		RequestedProfile:    "profile://organization/org/pipeline/pipeline-id/my-pipeline/profile/default",
		RequestedRepository: "example-repo",
		VendedRepository:    "",
	}
	assert.Equal(t, expected, *entry)
}

func TestAuditor_Failure(t *testing.T) {
	failingVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) vendor.VendorResult {
		return vendor.NewVendorFailed(errors.New("vendor error"))
	}
	auditedVendor := vendor.Auditor(failingVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	result := auditedVendor(ctx, ref, repo)
	assertVendorFailure(t, result, "vendor error")

	entry := audit.Log(ctx)
	expected := audit.Entry{
		Error:               "vendor failure: vendor error",
		Repositories:        nil,
		Permissions:         nil,
		ExpirySecs:          0,
		RequestedProfile:    "profile://organization/org/pipeline/pipeline-id/my-pipeline/profile/default",
		RequestedRepository: "example-repo",
		VendedRepository:    "",
	}
	assert.Equal(t, expected, *entry)
}
func TestAuditor_ProfileAuditing(t *testing.T) {
	profileVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) vendor.VendorResult {
		return vendor.NewVendorSuccess(vendor.ProfileToken{
			Repositories:        []string{"https://example.com/repo"},
			Permissions:         []string{"contents:read"},
			VendedRepositoryURL: "https://example.com/repo",
			Profile:             ref.ShortString(),
			Expiry:              time.Now().Add(1 * time.Hour),
		})
	}
	// Testing auditing over the cache layer as there
	// are resultant changes to audit objects.
	vendorCache, err := vendor.Cached(45 * time.Minute)
	assert.NoError(t, err)

	auditedVendor := vendor.Auditor(vendorCache(profileVendor))

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref1 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	// Case 1: Test with default profile - audit log should contain full URN
	result := auditedVendor(ctx, ref1, repo)

	_, failed := result.Failed()
	assert.False(t, failed)

	entry := audit.Log(ctx)
	expected := audit.Entry{
		Error:            "",
		RequestedProfile: "profile://organization/org/pipeline/pipeline-id/my-pipeline/profile/default",
	}
	assert.Equal(t, expected.Error, entry.Error)
	assert.Equal(t, expected.RequestedProfile, entry.RequestedProfile)

	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "test-profile",
		Type:         profile.ProfileTypeOrg,
		PipelineSlug: "",
	}
	// Case 2: Test with specified profile - audit log should contain full URN
	result = auditedVendor(ctx, ref2, repo)

	_, failed = result.Failed()
	assert.False(t, failed)

	entry = audit.Log(ctx)
	expected = audit.Entry{
		Error:            "",
		RequestedProfile: "profile://organization/org/profile/test-profile",
	}
	assert.Equal(t, expected.Error, entry.Error)
	assert.Equal(t, expected.RequestedProfile, entry.RequestedProfile)
}

func TestAuditingMatcher_SuccessfulMatch(t *testing.T) {
	ctx, _ := audit.Context(context.Background())

	// Create a mock matcher that returns a successful match
	mockMatcher := func(claims profile.ClaimValueLookup) profile.MatchResult {
		return profile.MatchResult{
			Matched: true,
			Matches: []profile.ClaimMatch{
				{Claim: "pipeline_slug", Value: "my-pipeline"},
				{Claim: "build_branch", Value: "main"},
			},
		}
	}

	// Wrap with AuditingMatcher
	auditingMatcher := vendor.AuditingMatcher(ctx, mockMatcher)

	// Call the matcher (claims value doesn't matter since mock ignores it)
	result := auditingMatcher(nil)

	// Verify the result is returned unchanged
	assert.True(t, result.Matched)
	assert.Len(t, result.Matches, 2)

	// Verify audit log was populated
	entry := audit.Log(ctx)
	expected := []audit.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
		{Claim: "build_branch", Value: "main"},
	}
	assert.Equal(t, expected, entry.ClaimsMatched)
	assert.Nil(t, entry.ClaimsFailed)
}

func TestAuditingMatcher_FailedMatch(t *testing.T) {
	ctx, _ := audit.Context(context.Background())

	// Create a mock matcher that returns a failed match
	mockMatcher := func(claims profile.ClaimValueLookup) profile.MatchResult {
		return profile.MatchResult{
			Matched: false,
			Attempt: &profile.MatchAttempt{
				Claim:       "pipeline_slug",
				Pattern:     ".*-release",
				ActualValue: "my-pipeline",
			},
		}
	}

	// Wrap with AuditingMatcher
	auditingMatcher := vendor.AuditingMatcher(ctx, mockMatcher)

	// Call the matcher
	result := auditingMatcher(nil)

	// Verify the result is returned unchanged
	assert.False(t, result.Matched)
	assert.NotNil(t, result.Attempt)

	// Verify audit log was populated
	entry := audit.Log(ctx)
	expected := []audit.ClaimFailure{
		{
			Claim:   "pipeline_slug",
			Pattern: ".*-release",
			Value:   "my-pipeline",
		},
	}
	assert.Equal(t, expected, entry.ClaimsFailed)
	assert.Nil(t, entry.ClaimsMatched)
}

func TestAuditingMatcher_EmptyMatchRules(t *testing.T) {
	ctx, _ := audit.Context(context.Background())

	// Create a mock matcher that returns success with empty match rules
	mockMatcher := func(claims profile.ClaimValueLookup) profile.MatchResult {
		return profile.MatchResult{
			Matched: true,
			Matches: []profile.ClaimMatch{},
		}
	}

	// Wrap with AuditingMatcher
	auditingMatcher := vendor.AuditingMatcher(ctx, mockMatcher)

	// Call the matcher
	result := auditingMatcher(nil)

	// Verify the result is returned unchanged
	assert.True(t, result.Matched)
	assert.Empty(t, result.Matches)

	// Verify audit log was populated with empty slice (not nil)
	entry := audit.Log(ctx)
	assert.NotNil(t, entry.ClaimsMatched)
	assert.Empty(t, entry.ClaimsMatched)
	assert.Nil(t, entry.ClaimsFailed)
}

func TestAuditingMatcher_ValidationError(t *testing.T) {
	ctx, _ := audit.Context(context.Background())

	// Create a mock matcher that returns a validation error
	mockMatcher := func(claims profile.ClaimValueLookup) profile.MatchResult {
		return profile.MatchResult{
			Matched: false,
			Err:     errors.New("claim validation failed: claim value contains invalid characters"),
			Attempt: &profile.MatchAttempt{
				Claim:       "pipeline_slug",
				Pattern:     ".*-release",
				ActualValue: "my-pipeline\x00",
			},
		}
	}

	// Wrap with AuditingMatcher
	auditingMatcher := vendor.AuditingMatcher(ctx, mockMatcher)

	// Call the matcher
	result := auditingMatcher(nil)

	// Verify the result is returned unchanged
	assert.False(t, result.Matched)
	assert.NotNil(t, result.Err)
	assert.NotNil(t, result.Attempt)

	// Verify audit log was populated with failure details
	entry := audit.Log(ctx)
	expected := []audit.ClaimFailure{
		{
			Claim:   "pipeline_slug",
			Pattern: ".*-release",
			Value:   "my-pipeline\x00",
		},
	}
	assert.Equal(t, expected, entry.ClaimsFailed)
	assert.Nil(t, entry.ClaimsMatched)
}
