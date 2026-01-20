package github

import (
	"testing"

	api "github.com/google/go-github/v81/github"
	"github.com/stretchr/testify/assert"
)

func TestScopesToPermissions(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected *api.InstallationPermissions
	}{
		{
			name:   "valid scopes",
			scopes: []string{"contents:read", "packages:write"},
			expected: &api.InstallationPermissions{
				Contents: api.Ptr("read"),
				Packages: api.Ptr("write"),
			},
		},
		{
			name:   "multiple scopes",
			scopes: []string{"pull_requests:write", "actions:read", "metadata:read"},
			expected: &api.InstallationPermissions{
				PullRequests: api.Ptr("write"),
				Actions:      api.Ptr("read"),
				Metadata:     api.Ptr("read"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPermissions, err := scopesToPermissions(tt.scopes)
			assert.Equal(t, tt.expected, actualPermissions)
			assert.NoError(t, err)
		})
	}
}
