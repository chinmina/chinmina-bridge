package profile_test

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProfileRef_Success(t *testing.T) {
	tests := []struct {
		name          string
		claims        jwt.BuildkiteClaims
		expectedType  profile.ProfileType
		profileString string
		expected      profile.ProfileRef
	}{
		{
			name: "RepoProfileWithTypePrefix",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			expectedType:  profile.ProfileTypeRepo,
			profileString: "repo:default",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
		},
		{
			name: "RepoProfileWithoutTypePrefix",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			expectedType:  profile.ProfileTypeRepo,
			profileString: "custom-profile",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "custom-profile",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
		},
		{
			name: "OrgProfileWithTypePrefix",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			expectedType:  profile.ProfileTypeOrg,
			profileString: "org:write-packages",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
				PipelineSlug: "",
			},
		},
		{
			name: "OrgProfileWithoutTypePrefix",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			expectedType:  profile.ProfileTypeOrg,
			profileString: "write-packages",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
				PipelineSlug: "",
			},
		},
		{
			name: "EmptyProfileDefaultsToRepoDefault",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			expectedType:  profile.ProfileTypeRepo,
			profileString: "",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
		},
		{
			name: "MultiComponentProfileName",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			expectedType:  profile.ProfileTypeOrg,
			profileString: "org:write-packages-v2",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages-v2",
				PipelineID:   "",
				PipelineSlug: "",
			},
		},
		{
			name: "EmptyOrganizationSlug",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			expectedType:  profile.ProfileTypeRepo,
			profileString: "repo:default",
			expected: profile.ProfileRef{
				Organization: "",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := profile.NewProfileRef(tt.claims, tt.expectedType, tt.profileString)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, ref)
		})
	}
}

func TestNewProfileRef_InvalidFormats(t *testing.T) {
	tests := []struct {
		name           string
		expectedType   profile.ProfileType
		profileString  string
		expectedErrMsg string
	}{
		{
			name:           "EmptyOrgProfile",
			expectedType:   profile.ProfileTypeOrg,
			profileString:  "",
			expectedErrMsg: "organization profiles have no default",
		},
		{
			name:           "MissingType",
			expectedType:   profile.ProfileTypeRepo,
			profileString:  ":profile-name",
			expectedErrMsg: "invalid profile format",
		},
		{
			name:           "MissingName",
			expectedType:   profile.ProfileTypeRepo,
			profileString:  "repo:",
			expectedErrMsg: "invalid profile format",
		},
		{
			name:           "InvalidProfileType",
			expectedType:   profile.ProfileTypeRepo,
			profileString:  "invalid:profile",
			expectedErrMsg: "invalid profile type",
		},
		{
			name:           "TypeMismatchRepoExpectedOrgGiven",
			expectedType:   profile.ProfileTypeRepo,
			profileString:  "org:profile-name",
			expectedErrMsg: "profile type mismatch",
		},
		{
			name:           "TypeMismatchOrgExpectedRepoGiven",
			expectedType:   profile.ProfileTypeOrg,
			profileString:  "repo:profile-name",
			expectedErrMsg: "profile type mismatch",
		},
	}

	claims := jwt.BuildkiteClaims{
		OrganizationSlug: "acme-corp",
		PipelineID:       "abc123",
		PipelineSlug:     "my-pipeline",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := profile.NewProfileRef(claims, tt.expectedType, tt.profileString)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.expectedErrMsg)
		})
	}
}

func TestProfileRef_String(t *testing.T) {
	tests := []struct {
		name     string
		ref      profile.ProfileRef
		expected string
	}{
		{
			name: "RepoFormat",
			ref: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
			expected: "profile://organization/acme-corp/pipeline/abc123/my-pipeline/profile/default",
		},
		{
			name: "OrgFormat",
			ref: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
				PipelineSlug: "",
			},
			expected: "profile://organization/acme-corp/profile/write-packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ref.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProfileRef_ShortString(t *testing.T) {
	tests := []struct {
		name     string
		ref      profile.ProfileRef
		expected string
	}{
		{
			name: "Repo",
			ref: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
			expected: "repo:default",
		},
		{
			name: "Org",
			ref: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
				PipelineSlug: "",
			},
			expected: "org:write-packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ref.ShortString()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseProfileRef_Roundtrip(t *testing.T) {
	tests := []struct {
		name     string
		original profile.ProfileRef
	}{
		{
			name: "RepoProfile",
			original: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
		},
		{
			name: "OrgProfile",
			original: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
				PipelineSlug: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to string
			refStr := tt.original.String()

			// Parse back
			parsed, err := profile.ParseProfileRef(refStr)

			require.NoError(t, err)
			assert.Equal(t, tt.original, parsed)
		})
	}
}

func TestParseProfileRef_ComplexNames(t *testing.T) {
	tests := []struct {
		name     string
		refStr   string
		expected profile.ProfileRef
	}{
		{
			name:   "RepoProfileComplexNames",
			refStr: "profile://organization/my-org-123/pipeline/pipe-id-456/my-slug-789/profile/profile-name-v2",
			expected: profile.ProfileRef{
				Organization: "my-org-123",
				Type:         profile.ProfileTypeRepo,
				Name:         "profile-name-v2",
				PipelineID:   "pipe-id-456",
				PipelineSlug: "my-slug-789",
			},
		},
		{
			name:   "OrgProfileComplexNames",
			refStr: "profile://organization/my-org-123/profile/profile-name-v2",
			expected: profile.ProfileRef{
				Organization: "my-org-123",
				Type:         profile.ProfileTypeOrg,
				Name:         "profile-name-v2",
				PipelineID:   "",
				PipelineSlug: "",
			},
		},
		{
			name:   "ExtraSlashesInPath",
			refStr: "profile://organization/acme-corp/pipeline/abc123/my-pipeline/profile/default/extra/path",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "my-pipeline",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := profile.ParseProfileRef(tt.refStr)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, parsed)
		})
	}
}

func TestParseProfileRef_InvalidFormats(t *testing.T) {
	tests := []struct {
		name           string
		refStr         string
		expectedErrMsg string
	}{
		{
			name:           "NoPrefix",
			refStr:         "invalid-string",
			expectedErrMsg: "expected to start with 'profile://organization/'",
		},
		{
			name:           "TooFewComponents",
			refStr:         "profile://organization/acme-corp",
			expectedErrMsg: "expected at least 3 components",
		},
		{
			name:           "UnknownType",
			refStr:         "profile://organization/acme-corp/unknown/profile-name",
			expectedErrMsg: "could not determine profile type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := profile.ParseProfileRef(tt.refStr)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.expectedErrMsg)
		})
	}
}

func TestProfileType_String(t *testing.T) {
	tests := []struct {
		name        string
		profileType profile.ProfileType
		expected    string
	}{
		{
			name:        "Repo",
			profileType: profile.ProfileTypeRepo,
			expected:    "repo",
		},
		{
			name:        "Org",
			profileType: profile.ProfileTypeOrg,
			expected:    "org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.profileType.String())
		})
	}
}

func TestParseProfileRef_OldFormat_BackwardCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		refStr   string
		expected profile.ProfileRef
	}{
		{
			name:   "OldRepoFormat",
			refStr: "profile://organization/acme-corp/pipeline/abc123/default",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
				PipelineSlug: "", // Empty in old format
			},
		},
		{
			name:   "OldRepoFormatComplexNames",
			refStr: "profile://organization/my-org-123/pipeline/pipe-id-456/profile-name-v2",
			expected: profile.ProfileRef{
				Organization: "my-org-123",
				Type:         profile.ProfileTypeRepo,
				Name:         "profile-name-v2",
				PipelineID:   "pipe-id-456",
				PipelineSlug: "", // Empty in old format
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := profile.ParseProfileRef(tt.refStr)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, parsed)
		})
	}
}
