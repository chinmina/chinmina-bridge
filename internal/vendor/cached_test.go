package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheSetupFails(t *testing.T) {
	_, err := vendor.Cached(-1)
	require.Error(t, err)
}

func TestCacheMissOnFirstRequest(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
	require.NoError(t, err)
	assert.Equal(t, "first-call", token.Token)
}

func TestCacheMissWithNilResponse(t *testing.T) {
	wrapped := sequenceVendor("first-call", nil)

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// second call misses and returns nil
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id-not-recognized"}, "any-repo", "")
	require.NoError(t, err)
	assert.Nil(t, token)
}

func TestCacheHitWithOrgProfileAndDifferentRepo(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "org:read-plugins")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "org:read-plugins",
		Repositories:           []string{"any-repo", "another-secret-repo"},
		Permissions:            []string{"contents:read", "packages:read"},
	}, token)

	// second call hits (even though it's for a different pipeline), return first value
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "second-pipeline-id"}, "any-repo", "org:read-plugins")
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

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// second call hits, return first value
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
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

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// second call hits, but repo changes so causes a miss
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "different-repo", "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "different-repo",
		Profile:                "repo:default",
	}, token)

	// third call hits, returns second result after cache reset
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "different-repo", "")
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

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// second call misses as it's for a different pipeline (cache key)
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "second-pipeline-id"}, "any-repo", "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "second-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// third call hits, returns second result after cache reset
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "second-pipeline-id"}, "any-repo", "")
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

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "repo:default",
	}, token)

	// expiry routine runs once per second
	time.Sleep(1500 * time.Millisecond)

	// second call misses as it's expired
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
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

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "org:shared-profile")
	require.NoError(t, err)
	assert.Equal(t, &vendor.ProfileToken{
		Token:                  "first-call",
		RequestedRepositoryURL: "any-repo",
		Profile:                "org:shared-profile",
		Repositories:           []string{"any-repo", "different-repo"},
		Permissions:            []string{"read", "write"},
	}, token)
	// second call hits, but repo changes, so token content is the same but repo is different
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "different-repo", "org:shared-profile")
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

	// first call misses cache and returns error from wrapped
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "")
	assert.Error(t, err)
	assert.EqualError(t, err, "failed")
	assert.Nil(t, token)
}

func TestBadProfileFormat(t *testing.T) {
	wrapped := sequenceVendor(nil)

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	// call with bad profile format does not hit cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo", "bad-profile-format")
	assert.Error(t, err)
	assert.EqualError(t, err, "unexpected profile format: bad-profile-format")
	assert.Nil(t, token)
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
			Profiles []github.Profile `yaml:"profiles"`
		}{
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

	return vendor.ProfileTokenVendor(func(ctx context.Context, claims jwt.BuildkiteClaims, repo string, profile string) (*vendor.ProfileToken, error) {
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
			if profile == "" {
				token = &vendor.ProfileToken{
					Token:                  v,
					RequestedRepositoryURL: repo,
					Profile:                profile,
				}
			} else {
				orgProfile, _ := testProfile.LookupProfile(profile)
				token = &vendor.ProfileToken{
					Token:                  v,
					Repositories:           orgProfile.Repositories,
					Permissions:            orgProfile.Permissions,
					RequestedRepositoryURL: repo,
					Profile:                profile,
				}
			}
		case error:
			err = v
		}

		callIndex++

		return token, err
	})
}
