package profile_test

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/stretchr/testify/assert"
)

// TestNewAuthorizedProfile_OrganizationProfile creates an authorized profile with organization attributes.
func TestNewAuthorizedProfile_OrganizationProfile(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}

	authProfile := profile.NewAuthorizedProfile(matcher, attrs)

	assert.Equal(t, attrs, authProfile.Attrs)
}

// TestNewAuthorizedProfile_PipelineProfile creates an authorized profile with pipeline attributes.
func TestNewAuthorizedProfile_PipelineProfile(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.PipelineProfileAttr{}

	authProfile := profile.NewAuthorizedProfile(matcher, attrs)

	assert.Equal(t, attrs, authProfile.Attrs)
}

// TestAuthorizedProfile_Match_Success verifies Match delegates to underlying matcher on success.
func TestAuthorizedProfile_Match_Success(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)

	lookup := mockClaimLookup{
		claims: map[string]string{
			"pipeline_slug": "my-pipeline",
		},
	}

	result := authProfile.Match(lookup)

	expected := profile.MatchResult{
		Matched: true,
		Matches: []profile.ClaimMatch{
			{Claim: "pipeline_slug", Value: "my-pipeline"},
		},
	}
	assert.Equal(t, expected, result)
}

// TestAuthorizedProfile_Match_Failure verifies Match delegates to underlying matcher on failure.
func TestAuthorizedProfile_Match_Failure(t *testing.T) {
	tests := []struct {
		name     string
		matcher  profile.Matcher
		lookup   profile.ClaimValueLookup
		expected profile.MatchResult
	}{
		{
			name:    "claim value mismatch",
			matcher: profile.ExactMatcher("pipeline_slug", "my-pipeline"),
			lookup: mockClaimLookup{
				claims: map[string]string{
					"pipeline_slug": "other-pipeline",
				},
			},
			expected: profile.MatchResult{
				Matched: false,
				Attempt: &profile.MatchAttempt{
					Claim:       "pipeline_slug",
					Pattern:     "my-pipeline",
					ActualValue: "other-pipeline",
				},
			},
		},
		{
			name:    "claim not found",
			matcher: profile.ExactMatcher("pipeline_slug", "my-pipeline"),
			lookup: mockClaimLookup{
				claims: map[string]string{},
			},
			expected: profile.MatchResult{
				Matched: false,
				Attempt: &profile.MatchAttempt{
					Claim:       "pipeline_slug",
					Pattern:     "my-pipeline",
					ActualValue: "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := profile.OrganizationProfileAttr{
				Repositories: []string{"chinmina/chinmina-bridge"},
				Permissions:  []string{"contents:read"},
			}
			authProfile := profile.NewAuthorizedProfile(tt.matcher, attrs)

			result := authProfile.Match(tt.lookup)

			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthorizedProfile_Match_ValidationError verifies Match handles validation errors.
func TestAuthorizedProfile_Match_ValidationError(t *testing.T) {
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)

	// Mock lookup that returns a validation error
	lookup := mockErrorLookup{
		err: profile.ClaimValidationError{
			Claim: "pipeline_slug",
			Value: "invalid\x00value",
		},
	}

	result := authProfile.Match(lookup)

	assert.False(t, result.Matched)
	assert.NotNil(t, result.Err)
	var validationErr profile.ClaimValidationError
	assert.ErrorAs(t, result.Err, &validationErr)
}

// mockErrorLookup is a ClaimValueLookup that returns an error.
type mockErrorLookup struct {
	err error
}

func (m mockErrorLookup) Lookup(claim string) (string, error) {
	return "", m.err
}
