package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheMissOnFirstRequest(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, "first-call", token.Token)
}

func TestCacheMissWithNilResponse(t *testing.T) {
	wrapped := sequenceVendor("first-call", nil)

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// second call misses and returns nil
	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id-not-recognized",
	}
	token, err = v(context.Background(), ref2, "any-repo")
	require.NoError(t, err)
	assert.Nil(t, token)
}

func TestCacheHitWithOrgProfileAndDifferentRepo(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "read-plugins",
		Type:         profile.ProfileTypeOrg,
	}
	// first call misses cache
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "org:read-plugins",
		Repositories:           []string{"any-repo", "another-secret-repo"},
		Permissions:            []string{"contents:read", "packages:read"},
	}, token)

	// second call hits (even though it's for a different pipeline), return first value
	token, err = v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "org:read-plugins",
		Repositories:           []string{"any-repo", "another-secret-repo"},
		Permissions:            []string{"contents:read", "packages:read"},
	}, token)
}

func TestCacheHitOnSecondRequest(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// second call hits, return first value
	token, err = v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)
}

var defaultTTL = 60 * time.Minute

func TestCacheMissWithRepoChange(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// second call hits, but repo changes so causes a miss
	token, err = v(context.Background(), ref, "different-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "different-repo",
		Profile:                "repo:default",
	}, token)

	// third call hits, returns second result after cache reset
	token, err = v(context.Background(), ref, "different-repo")
	require.NoError(t, err)

	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "different-repo",
		Profile:                "repo:default",
	}, token)
}

func TestCacheMissWithPipelineIDChange(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref1 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	token, err := v(context.Background(), ref1, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "second-pipeline-id",
	}
	// second call misses as it's for a different pipeline (cache key)
	token, err = v(context.Background(), ref2, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// third call hits, returns second result after cache reset
	token, err = v(context.Background(), ref2, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)
}

func TestCacheMissWithExpiredItem(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(time.Nanosecond) // near instant expiration
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// expiry routine runs once per second
	time.Sleep(1500 * time.Millisecond)

	// second call misses as it's expired
	token, err = v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)
}

func TestCacheProfileWithDifferentRepo(t *testing.T) {
	wrapped := sequenceVendor("first-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "shared-profile",
		Type:         profile.ProfileTypeOrg,
	}
	// first call misses cache
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "org:shared-profile",
		Repositories:           []string{"any-repo", "different-repo"},
		Permissions:            []string{"read", "write"},
	}, token)
	// second call hits, but repo changes, so token content is the same but repo is different
	token, err = v(context.Background(), ref, "different-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "different-repo",
		Profile:                "org:shared-profile",
		Repositories:           []string{"any-repo", "different-repo"},
		Permissions:            []string{"read", "write"},
	}, token)
}

// calls wrapped when value expires
// returns error from wrapped on miss
func TestReturnsErrorForWrapperError(t *testing.T) {
	wrapped := sequenceVendor(E{"failed"})

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache and returns error from wrapped
	token, err := v(context.Background(), ref, "any-repo")
	assert.Error(t, err)
	assert.EqualError(t, err, "failed")
	assert.Nil(t, token)
}

func TestCacheMissWithNilVendorResponse(t *testing.T) {
	wrapped := sequenceVendor(nil, "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	// First call returns nil from the wrapped vendor
	token, err := v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Nil(t, token)

	// Second call should not be served from cache; it should invoke the wrapped vendor again
	// and return the second token value. This verifies that nil results are not cached.
	token, err = v(context.Background(), ref, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)
}

// E must be an error
var _ error = E{}

type E struct {
	M string
}

func (e E) Error() string {
	return e.M
}

// sequenceVendor returns each of the calls in sequence, either a token or an error
func sequenceVendor(calls ...any) vendor.ProfileTokenVendor {
	callIndex := 0

	var testProfile = github.ProfileConfig{
		Organization: struct {
			Defaults struct {
				Permissions []string `yaml:"permissions"`
			} `yaml:"defaults"`
			Profiles        []github.Profile `yaml:"profiles"`
			InvalidProfiles map[string]error `yaml:"-"`
		}{
			Defaults: struct {
				Permissions []string `yaml:"permissions"`
			}{
				Permissions: []string{},
			},
			InvalidProfiles: make(map[string]error),
			Profiles: []github.Profile{
				{
					Name:         "org:shared-profile",
					Repositories: []string{"any-repo", "different-repo"},
					Permissions:  []string{"read", "write"},
				},
				{
					Name:         "org:read-plugins",
					Repositories: []string{"any-repo", "another-secret-repo"},
					Permissions:  []string{"contents:read", "packages:read"},
				},
			},
		},
	}

	return vendor.ProfileTokenVendor(func(ctx context.Context, ref profile.ProfileRef, repo string) (*vendor.ProfileToken, error) {
		if len(calls) <= callIndex {
			return nil, errors.New("unregistered call")
		}

		var token *vendor.ProfileToken
		var err error

		c := calls[callIndex]

		switch v := any(c).(type) {
		case nil:
			// all nil return
		case string:
			if ref.Name == "default" {
				token = &vendor.ProfileToken{
					Token:                  v,
					RequestedRepositoryURL: repo,
					Profile:                ref.ShortString(),
				}
			} else {
				orgProfile, _ := testProfile.LookupProfile(ref.ShortString())
				token = &vendor.ProfileToken{
					Token:                  v,
					Repositories:           orgProfile.Repositories,
					Permissions:            orgProfile.Permissions,
					RequestedRepositoryURL: repo,
					Profile:                ref.ShortString(),
				}
			}
		case error:
			err = v
		}

		callIndex++

		return token, err
	})
}
