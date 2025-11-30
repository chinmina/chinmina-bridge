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
		profileString string
		expected      profile.ProfileRef
	}{
		{
			name: "RepoProfile",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			profileString: "repo:default",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
			},
		},
		{
			name: "OrgProfile",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			profileString: "org:write-packages",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
			},
		},
		{
			name: "EmptyProfileDefaultsToRepoDefault",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			profileString: "",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
			},
		},
		{
			name: "MultiComponentProfileName",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "acme-corp",
				PipelineID:       "abc123",
				PipelineSlug:     "my-pipeline",
			},
			profileString: "org:write-packages-v2",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages-v2",
				PipelineID:   "",
			},
		},
		{
			name: "EmptyOrganizationSlug",
			claims: jwt.BuildkiteClaims{
				OrganizationSlug: "",
				PipelineID:       "abc123",
			},
			profileString: "repo:default",
			expected: profile.ProfileRef{
				Organization: "",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := profile.NewProfileRef(tt.claims, tt.profileString)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, ref)
		})
	}
}

func TestNewProfileRef_InvalidFormats(t *testing.T) {
	tests := []struct {
		name           string
		profileString  string
		expectedErrMsg string
	}{
		{
			name:           "MissingColon",
			profileString:  "invalid-no-colon",
			expectedErrMsg: "invalid profile format",
		},
		{
			name:           "MissingType",
			profileString:  ":profile-name",
			expectedErrMsg: "invalid profile format",
		},
		{
			name:           "MissingName",
			profileString:  "repo:",
			expectedErrMsg: "invalid profile format",
		},
		{
			name:           "InvalidProfileType",
			profileString:  "invalid:profile",
			expectedErrMsg: "invalid profile type",
		},
	}

	claims := jwt.BuildkiteClaims{
		OrganizationSlug: "acme-corp",
		PipelineID:       "abc123",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := profile.NewProfileRef(claims, tt.profileString)

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
			},
			expected: "profile://organization/acme-corp/pipeline/abc123/default",
		},
		{
			name: "OrgFormat",
			ref: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
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
			},
		},
		{
			name: "OrgProfile",
			original: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeOrg,
				Name:         "write-packages",
				PipelineID:   "",
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
			refStr: "profile://organization/my-org-123/pipeline/pipe-id-456/profile-name-v2",
			expected: profile.ProfileRef{
				Organization: "my-org-123",
				Type:         profile.ProfileTypeRepo,
				Name:         "profile-name-v2",
				PipelineID:   "pipe-id-456",
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
			},
		},
		{
			name:   "ExtraSlashesInPath",
			refStr: "profile://organization/acme-corp/pipeline/abc123/default/extra/path",
			expected: profile.ProfileRef{
				Organization: "acme-corp",
				Type:         profile.ProfileTypeRepo,
				Name:         "default",
				PipelineID:   "abc123",
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
