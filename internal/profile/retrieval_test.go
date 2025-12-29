package profile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecomposePath_Success(t *testing.T) {
	owner, repo, path := decomposePath("acme:silk:docs/profile.yaml")

	assert.Equal(t, "acme", owner)
	assert.Equal(t, "silk", repo)
	assert.Equal(t, "docs/profile.yaml", path)
}

func TestDecomposePath_InvalidTriplet(t *testing.T) {
	owner, repo, path := decomposePath("owner:path")

	assert.Equal(t, "", owner)
	assert.Equal(t, "", repo)
	assert.Equal(t, "", path)
}
