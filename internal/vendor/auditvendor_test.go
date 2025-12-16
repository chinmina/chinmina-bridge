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
	successfulVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Expiry:                 time.Now().Add(1 * time.Hour),
		}, nil
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
	token, err := auditedVendor(ctx, ref1, repo)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "https://example.com/repo", token.RequestedRepositoryURL)

	entry := audit.Log(ctx)
	expected := audit.Entry{
		Error:       "",
		Repositories: []string{"https://example.com/repo"},
		Permissions: []string{"contents:read"},
	}
	// ExpirySecs is dynamic based on current time, so check separately
	assert.Equal(t, expected.Error, entry.Error)
	assert.Equal(t, expected.Repositories, entry.Repositories)
	assert.Equal(t, expected.Permissions, entry.Permissions)
	assert.NotZero(t, entry.ExpirySecs)

	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "test-profile",
		Type:         profile.ProfileTypeOrg,
		PipelineSlug: "",
	}
	token, err = auditedVendor(ctx, ref2, repo)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "https://example.com/repo", token.RequestedRepositoryURL)

	entry = audit.Log(ctx)
	expected = audit.Entry{
		Error:       "",
		Repositories: []string{"https://example.com/repo"},
		Permissions: []string{"contents:read"},
	}
	// ExpirySecs is dynamic based on current time, so check separately
	assert.Equal(t, expected.Error, entry.Error)
	assert.Equal(t, expected.Repositories, entry.Repositories)
	assert.Equal(t, expected.Permissions, entry.Permissions)
	assert.NotZero(t, entry.ExpirySecs)

}

func TestAuditor_Mismatch(t *testing.T) {
	successfulVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return nil, nil
	}
	auditedVendor := vendor.Auditor(successfulVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref, repo)

	assert.NoError(t, err)
	assert.Nil(t, token)

	entry := audit.Log(ctx)
	expected := audit.Entry{
		Error:       "repository mismatch, no token vended",
		Repositories: nil,
		Permissions: nil,
		ExpirySecs:  0,
	}
	assert.Equal(t, expected, *entry)
}

func TestAuditor_Failure(t *testing.T) {
	failingVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return nil, errors.New("vendor error")
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
	token, err := auditedVendor(ctx, ref, repo)
	assert.Error(t, err)
	assert.Nil(t, token)

	entry := audit.Log(ctx)
	expected := audit.Entry{
		Error:       "vendor failure: vendor error",
		Repositories: nil,
		Permissions: nil,
		ExpirySecs:  0,
	}
	assert.Equal(t, expected, *entry)
}
func TestAuditor_ProfileAuditing(t *testing.T) {
	profileVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Profile:                ref.ShortString(),
			Expiry:                 time.Now().Add(1 * time.Hour),
		}, nil
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
	_, err = auditedVendor(ctx, ref1, repo)

	assert.NoError(t, err)

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
	_, err = auditedVendor(ctx, ref2, repo)

	assert.NoError(t, err)

	entry = audit.Log(ctx)
	expected = audit.Entry{
		Error:            "",
		RequestedProfile: "profile://organization/org/profile/test-profile",
	}
	assert.Equal(t, expected.Error, entry.Error)
	assert.Equal(t, expected.RequestedProfile, entry.RequestedProfile)
}

func TestAuditor_SuccessfulMatch(t *testing.T) {
	successfulVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Expiry:                 time.Now().Add(1 * time.Hour),
			MatchResult: profile.MatchResult{
				Matched: true,
				Matches: []profile.ClaimMatch{
					{Claim: "pipeline_slug", Value: "my-pipeline"},
					{Claim: "build_branch", Value: "main"},
				},
			},
		}, nil
	}
	auditedVendor := vendor.Auditor(successfulVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref, repo)

	assert.NoError(t, err)
	assert.NotNil(t, token)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
	expected := []audit.ClaimMatch{
		{Claim: "pipeline_slug", Value: "my-pipeline"},
		{Claim: "build_branch", Value: "main"},
	}
	assert.Equal(t, expected, entry.ClaimsMatched)
	assert.Nil(t, entry.ClaimsFailed)
}

func TestAuditor_FailedMatch(t *testing.T) {
	failedVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Expiry:                 time.Now().Add(1 * time.Hour),
			MatchResult: profile.MatchResult{
				Matched: false,
				Attempt: &profile.MatchAttempt{
					Claim:       "pipeline_slug",
					Pattern:     ".*-release",
					ActualValue: "my-pipeline",
				},
			},
		}, nil
	}
	auditedVendor := vendor.Auditor(failedVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref, repo)

	assert.NoError(t, err)
	assert.NotNil(t, token)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
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

func TestAuditor_EmptyMatchRules(t *testing.T) {
	emptyRulesVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Expiry:                 time.Now().Add(1 * time.Hour),
			MatchResult: profile.MatchResult{
				Matched: true,
				Matches: []profile.ClaimMatch{},
			},
		}, nil
	}
	auditedVendor := vendor.Auditor(emptyRulesVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref, repo)

	assert.NoError(t, err)
	assert.NotNil(t, token)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
	assert.NotNil(t, entry.ClaimsMatched)
	assert.Empty(t, entry.ClaimsMatched)
	assert.Nil(t, entry.ClaimsFailed)
}

func TestAuditor_ValidationError(t *testing.T) {
	validationErrorVendor := func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		return &vendor.ProfileToken{
			Repositories:           []string{"https://example.com/repo"},
			Permissions:            []string{"contents:read"},
			RequestedRepositoryURL: "https://example.com/repo",
			Expiry:                 time.Now().Add(1 * time.Hour),
			MatchResult: profile.MatchResult{
				Matched: false,
				Err:     errors.New("claim validation failed: claim value contains invalid characters"),
				Attempt: &profile.MatchAttempt{
					Claim:       "pipeline_slug",
					Pattern:     ".*-release",
					ActualValue: "my-pipeline\x00",
				},
			},
		}, nil
	}
	auditedVendor := vendor.Auditor(validationErrorVendor)

	ctx, _ := audit.Context(context.Background())
	repo := "example-repo"

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}
	token, err := auditedVendor(ctx, ref, repo)

	assert.NoError(t, err)
	assert.NotNil(t, token)

	entry := audit.Log(ctx)
	assert.Empty(t, entry.Error)
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
