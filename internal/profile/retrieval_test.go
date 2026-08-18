package profile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecomposePath_Success(t *testing.T) {
	owner, repo, path, err := decomposePath("acme:silk:docs/profile.yaml")

	assert.NoError(t, err)
	assert.Equal(t, "acme", owner)
	assert.Equal(t, "silk", repo)
	assert.Equal(t, "docs/profile.yaml", path)
}

func TestDecomposePath_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		location string
	}{
		{name: "too few components", location: "owner:path"},
		{name: "no separators at all", location: "profile.yaml"},
		{name: "empty owner", location: ":silk:docs/profile.yaml"},
		{name: "empty repo", location: "acme::docs/profile.yaml"},
		{name: "empty path", location: "acme:silk:"},
		{name: "entirely empty components", location: "::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, path, err := decomposePath(tt.location)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid profile location format")
			assert.Equal(t, "", owner)
			assert.Equal(t, "", repo)
			assert.Equal(t, "", path)

			assert.Error(t, ValidateLocation(tt.location),
				"ValidateLocation must reject whatever decomposePath rejects")
		})
	}
}
