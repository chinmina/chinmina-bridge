package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, "first-call", token.Token)
}

func TestCacheMissWithNilResponse(t *testing.T) {
	wrapped := sequenceVendor("first-call", nil)

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "first-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "pipeline-id",
	}, token)

	// second call misses and returns nil
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id-not-recognized"}, "any-repo")
	require.NoError(t, err)
	assert.Nil(t, token)
}

func TestCacheHitOnSecondRequest(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "first-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "pipeline-id",
	}, token)

	// second call hits, return first value
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "first-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "pipeline-id",
	}, token)
}

var defaultTTL = 60 * time.Minute

func TestCacheMissWithRepoChange(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "first-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "pipeline-id",
	}, token)

	// second call hits, but repo changes so causes a miss
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "different-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "second-call",
		RepositoryURL: "different-repo",
		PipelineSlug:  "pipeline-id",
	}, token)

	// third call hits, returns second result after cache reset
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "different-repo")
	require.NoError(t, err)

	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "second-call",
		RepositoryURL: "different-repo",
		PipelineSlug:  "pipeline-id",
	}, token)
}

func TestCacheMissWithPipelineIDChange(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(defaultTTL)
	require.NoError(t, err)

	v := c(wrapped)

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "first-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "pipeline-id",
	}, token)

	// second call misses as it's for a different pipeline (cache key)
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "second-pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "second-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "second-pipeline-id",
	}, token)

	// third call hits, returns second result after cache reset
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "second-pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "second-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "second-pipeline-id",
	}, token)
}

func TestCacheMissWithExpiredItem(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c, err := vendor.Cached(time.Nanosecond) // near instant expiration
	require.NoError(t, err)

	v := c(wrapped)

	// first call misses cache
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "first-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "pipeline-id",
	}, token)

	// expiry routine runs once per second
	time.Sleep(1500 * time.Millisecond)

	// second call misses as it's expired
	token, err = v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	require.NoError(t, err)
	assert.Equal(t, &vendor.PipelineRepositoryToken{
		Token:         "second-call",
		RepositoryURL: "any-repo",
		PipelineSlug:  "pipeline-id",
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
	token, err := v(context.Background(), jwt.BuildkiteClaims{PipelineID: "pipeline-id"}, "any-repo")
	assert.Error(t, err)
	assert.EqualError(t, err, "failed")
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
func sequenceVendor(calls ...any) vendor.PipelineTokenVendor {
	callIndex := 0

	return vendor.PipelineTokenVendor(func(ctx context.Context, claims jwt.BuildkiteClaims, repo string) (*vendor.PipelineRepositoryToken, error) {
		if len(calls) <= callIndex {
			return nil, errors.New("unregistered call")
		}

		var token *vendor.PipelineRepositoryToken
		var err error

		c := calls[callIndex]

		switch v := any(c).(type) {
		case nil:
			// all nil return
		case string:
			token = &vendor.PipelineRepositoryToken{
				Token:         v,
				RepositoryURL: repo,
				PipelineSlug:  claims.PipelineID,
			}
		case error:
			err = v
		}

		callIndex++

		return token, err
	})
}
