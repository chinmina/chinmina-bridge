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

func TestDecomposePath_InvalidTriplet(t *testing.T) {
	owner, repo, path, err := decomposePath("owner:path")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid profile location format")
	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
	assert.Equal(t, "", path)
}
