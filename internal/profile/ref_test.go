package profile

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProfileRef_WithTypePrefix_Success(t *testing.T) {
	tests := []struct {
		name       string
		profileStr string
		expected   ProfileRef
	}{
		{
			name:       "repo:default",
			profileStr: "repo:default",
			expected: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "pipeline-id",
				PipelineSlug: "pipeline-slug",
			},
		},
		{
			name:       "org:write-packages",
			profileStr: "org:write-packages",
			expected: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeOrg,
				Name:         "write-packages",
			},
		},
		{
			name:       "org:write-packages-v2",
			profileStr: "org:write-packages-v2",
			expected: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeOrg,
				Name:         "write-packages-v2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineID:       "pipeline-id",
				PipelineSlug:     "pipeline-slug",
			}

			ref, err := NewProfileRef(claims, tt.expected.Type, tt.profileStr)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ref)
		})
	}
}

func TestNewProfileRef_WithoutTypePrefix_Success(t *testing.T) {
	tests := []struct {
		name       string
		profileStr string
		expected   ProfileRef
	}{
		{
			name:       "custom-profile defaults to repo",
			profileStr: "custom-profile",
			expected: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeRepo,
				Name:         "custom-profile",
				PipelineID:   "pipeline-id",
				PipelineSlug: "pipeline-slug",
			},
		},
		{
			name:       "write-packages with explicit org type",
			profileStr: "write-packages",
			expected: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeOrg,
				Name:         "write-packages",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineID:       "pipeline-id",
				PipelineSlug:     "pipeline-slug",
			}

			ref, err := NewProfileRef(claims, tt.expected.Type, tt.profileStr)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ref)
		})
	}
}

func TestNewProfileRef_EmptyString_DefaultBehavior(t *testing.T) {
	claims := jwt.BuildkiteClaims{
		OrganizationSlug: "acme",
		PipelineID:       "pipeline-id",
		PipelineSlug:     "pipeline-slug",
	}

	ref, err := NewProfileRef(claims, ProfileTypeRepo, "")
	require.NoError(t, err)
	assert.Equal(t, ProfileTypeRepo, ref.Type)
	assert.Equal(t, "default", ref.Name)
}

func TestNewProfileRef_EmptyOrgSlug_Accepted(t *testing.T) {
	claims := jwt.BuildkiteClaims{
		OrganizationSlug: "",
		PipelineID:       "pipeline-id",
		PipelineSlug:     "pipeline-slug",
	}

	ref, err := NewProfileRef(claims, ProfileTypeRepo, "default")
	require.NoError(t, err)
	assert.Equal(t, "", ref.Organization)
}

func TestNewProfileRef_Failure(t *testing.T) {
	tests := []struct {
		name         string
		profileStr   string
		expectedType ProfileType
		errorMsg     string
	}{
		{
			name:         "empty org profile",
			profileStr:   "",
			expectedType: ProfileTypeOrg,
			errorMsg:     "organization profiles have no default",
		},
		{
			name:         "missing type",
			profileStr:   ":profile-name",
			expectedType: ProfileTypeRepo,
			errorMsg:     "invalid profile format",
		},
		{
			name:         "missing name",
			profileStr:   "repo:",
			expectedType: ProfileTypeRepo,
			errorMsg:     "invalid profile format",
		},
		{
			name:         "invalid profile type",
			profileStr:   "invalid:profile",
			expectedType: ProfileTypeRepo,
			errorMsg:     "invalid profile type",
		},
		{
			name:         "type mismatch - repo expected org given",
			profileStr:   "org:profile-name",
			expectedType: ProfileTypeRepo,
			errorMsg:     "profile type mismatch",
		},
		{
			name:         "type mismatch - org expected repo given",
			profileStr:   "repo:profile-name",
			expectedType: ProfileTypeOrg,
			errorMsg:     "profile type mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.BuildkiteClaims{
				OrganizationSlug: "acme",
				PipelineID:       "pipeline-id",
				PipelineSlug:     "pipeline-slug",
			}

			_, err := NewProfileRef(claims, tt.expectedType, tt.profileStr)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestProfileRef_String_CanonicalFormat(t *testing.T) {
	tests := []struct {
		name     string
		ref      ProfileRef
		expected string
	}{
		{
			name: "repo profile",
			ref: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
			expected: "profile://organization/acme/pipeline/abc123/my-pipeline/profile/default",
		},
		{
			name: "org profile",
			ref: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeOrg,
				Name:         "write-packages",
			},
			expected: "profile://organization/acme/profile/write-packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ref.String())
		})
	}
}

func TestProfileRef_ShortString(t *testing.T) {
	tests := []struct {
		name     string
		ref      ProfileRef
		expected string
	}{
		{
			name: "repo profile",
			ref: ProfileRef{
				Type: ProfileTypeRepo,
				Name: "default",
			},
			expected: "repo:default",
		},
		{
			name: "org profile",
			ref: ProfileRef{
				Type: ProfileTypeOrg,
				Name: "write-packages",
			},
			expected: "org:write-packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ref.ShortString())
		})
	}
}

func TestParseProfileRef_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		ref  ProfileRef
	}{
		{
			name: "repo profile",
			ref: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeRepo,
				Name:         "custom-profile",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
		},
		{
			name: "org profile",
			ref: ProfileRef{
				Organization: "acme",
				Type:         ProfileTypeOrg,
				Name:         "write-packages",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.ref.String()
			parsed, err := ParseProfileRef(s)
			require.NoError(t, err)
			assert.Equal(t, tt.ref, parsed)
		})
	}
}

func TestParseProfileRef_ComplexNames(t *testing.T) {
	tests := []struct {
		name string
		urn  string
		ref  ProfileRef
	}{
		{
			name: "hyphens and numbers in names",
			urn:  "profile://organization/acme-org-123/pipeline/pipeline-id-456/pipeline-slug-789/profile/profile-name-v2",
			ref: ProfileRef{
				Organization: "acme-org-123",
				Type:         ProfileTypeRepo,
				Name:         "profile-name-v2",
				PipelineID:   "pipeline-id-456",
				PipelineSlug: "pipeline-slug-789",
			},
		},
		{
			name: "underscores in names",
			urn:  "profile://organization/acme_org/profile/write_packages_v2",
			ref: ProfileRef{
				Organization: "acme_org",
				Type:         ProfileTypeOrg,
				Name:         "write_packages_v2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseProfileRef(tt.urn)
			require.NoError(t, err)
			assert.Equal(t, tt.ref, parsed)
		})
	}
}

func TestParseProfileRef_ExtraSlashesIgnored(t *testing.T) {
	// Extra slashes in path should be handled - parsing first valid structure
	urn := "profile://organization/acme/pipeline/id/slug/profile/name/extra/slashes"
	parsed, err := ParseProfileRef(urn)
	require.NoError(t, err)
	assert.Equal(t, ProfileRef{
		Organization: "acme",
		Type:         ProfileTypeRepo,
		Name:         "name",
		PipelineID:   "id",
		PipelineSlug: "slug",
	}, parsed)
}

func TestParseProfileRef_BackwardCompatibility_OldFormat(t *testing.T) {
	// Old format without pipeline slug: profile://organization/org/pipeline/id/name
	urn := "profile://organization/acme/pipeline/pipeline-id/profile-name"
	parsed, err := ParseProfileRef(urn)
	require.NoError(t, err)
	assert.Equal(t, ProfileRef{
		Organization: "acme",
		Type:         ProfileTypeRepo,
		Name:         "profile-name",
		PipelineID:   "pipeline-id",
		PipelineSlug: "",
	}, parsed)
}

func TestParseProfileRef_Failure(t *testing.T) {
	tests := []struct {
		name     string
		urn      string
		errorMsg string
	}{
		{
			name:     "no profile prefix",
			urn:      "invalid://organization/acme/profile/name",
			errorMsg: "expected to start with 'profile://organization/'",
		},
		{
			name:     "too few components",
			urn:      "profile://organization/acme",
			errorMsg: "expected at least 3 components",
		},
		{
			name:     "unknown type",
			urn:      "profile://organization/acme/unknown/value/name",
			errorMsg: "could not determine profile type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProfileRef(tt.urn)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestProfileType_String(t *testing.T) {
	tests := []struct {
		name     string
		pt       ProfileType
		expected string
	}{
		{
			name:     "ProfileTypeRepo",
			pt:       ProfileTypeRepo,
			expected: "repo",
		},
		{
			name:     "ProfileTypeOrg",
			pt:       ProfileTypeOrg,
			expected: "org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pt.String())
		})
	}
}

func TestNewProfileRef_PipelineFieldsOnlySetForRepo(t *testing.T) {
	claims := jwt.BuildkiteClaims{
		OrganizationSlug: "acme",
		PipelineID:       "pipeline-id",
		PipelineSlug:     "pipeline-slug",
	}

	// Repo profile should have pipeline fields set
	repoRef, err := NewProfileRef(claims, ProfileTypeRepo, "default")
	require.NoError(t, err)
	assert.Equal(t, "pipeline-id", repoRef.PipelineID)
	assert.Equal(t, "pipeline-slug", repoRef.PipelineSlug)

	// Org profile should NOT have pipeline fields set
	orgRef, err := NewProfileRef(claims, ProfileTypeOrg, "write-packages")
	require.NoError(t, err)
	assert.Empty(t, orgRef.PipelineID)
	assert.Empty(t, orgRef.PipelineSlug)
}

func TestProfileRef_Consistency(t *testing.T) {
	// Test that all methods work together consistently
	claims := jwt.BuildkiteClaims{
		OrganizationSlug: "test-org",
		PipelineID:       "test-id",
		PipelineSlug:     "test-slug",
	}

	// Create a repo profile ref
	repoRef, err := NewProfileRef(claims, ProfileTypeRepo, "custom-profile")
	require.NoError(t, err)

	// Verify complete struct matches expected
	expectedRepo := ProfileRef{
		Organization: "test-org",
		Type:         ProfileTypeRepo,
		Name:         "custom-profile",
		PipelineID:   "test-id",
		PipelineSlug: "test-slug",
	}
	assert.Equal(t, expectedRepo, repoRef)

	// Verify String() produces canonical format
	assert.Equal(t, "profile://organization/test-org/pipeline/test-id/test-slug/profile/custom-profile", repoRef.String())

	// Verify ShortString() produces short format
	assert.Equal(t, "repo:custom-profile", repoRef.ShortString())

	// Verify Type.String() works
	assert.Equal(t, "repo", repoRef.Type.String())

	// Verify ParseProfileRef can parse the canonical format
	parsed, err := ParseProfileRef(repoRef.String())
	require.NoError(t, err)
	assert.Equal(t, repoRef, parsed)

	// Create an org profile ref
	orgRef, err := NewProfileRef(claims, ProfileTypeOrg, "org-profile")
	require.NoError(t, err)

	// Verify complete struct matches expected
	expectedOrg := ProfileRef{
		Organization: "test-org",
		Type:         ProfileTypeOrg,
		Name:         "org-profile",
		PipelineID:   "",
		PipelineSlug: "",
	}
	assert.Equal(t, expectedOrg, orgRef)

	// Verify org profile formats
	assert.Equal(t, "profile://organization/test-org/profile/org-profile", orgRef.String())
	assert.Equal(t, "org:org-profile", orgRef.ShortString())
	assert.Equal(t, "org", orgRef.Type.String())
}
