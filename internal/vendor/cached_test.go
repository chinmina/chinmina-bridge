package vendor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/cache"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/chinmina/chinmina-bridge/internal/vendor"
	"github.com/stretchr/testify/require"
)

func TestCacheMissOnFirstRequest(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheMissWithNilResponse(t *testing.T) {
	wrapped := sequenceVendor("first-call", nil)

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// second call misses and returns nil
	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id-not-recognized",
	}
	result = v(context.Background(), ref2, "https://github.com/test-org/any-repo.git")
	assertVendorUnmatched(t, result)
}

func TestCacheHitWithOrgProfileAndDifferentRepo(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "read-plugins",
		Type:         profile.ProfileTypeOrg,
	}
	// first call misses cache
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Profile:             "org:read-plugins",
		Repositories:        []string{"any-repo", "another-secret-repo"},
		Permissions:         []string{"contents:read", "packages:read", "metadata:read"},
	})

	// second call hits (even though it's for a different pipeline), return first value
	result = v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Profile:             "org:read-plugins",
		Repositories:        []string{"any-repo", "another-secret-repo"},
		Permissions:         []string{"contents:read", "packages:read", "metadata:read"},
	})
}

func TestCacheHitOnSecondRequest(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// second call hits, return first value
	result = v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

var defaultTTL = 60 * time.Minute

func TestCacheHitWithEmptyRepoParameter(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache, vends with repository
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// second call hits with empty repo parameter (non-Git credentials request)
	// should return cached token even though it was vended for a specific repo
	result = v(context.Background(), ref, "")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheMissWithRepoChange(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// second call hits, but repo changes so causes a miss
	result = v(context.Background(), ref, "https://github.com/test-org/different-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "https://github.com/test-org/different-repo.git",
		Repositories:        []string{"different-repo"},
		Profile:             "repo:default",
	})

	// third call hits, returns second result after cache reset
	result = v(context.Background(), ref, "https://github.com/test-org/different-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "https://github.com/test-org/different-repo.git",
		Repositories:        []string{"different-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheMissWithPipelineIDChange(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref1 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	result := v(context.Background(), ref1, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	ref2 := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "second-pipeline-id",
	}
	// second call misses as it's for a different pipeline (cache key)
	result = v(context.Background(), ref2, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// third call hits, returns second result after cache reset
	result = v(context.Background(), ref2, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheMissWithExpiredItem(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, time.Nanosecond, "test-digest") // near instant expiration
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// expiry routine runs once per second
	time.Sleep(1500 * time.Millisecond)

	// second call misses as it's expired
	result = v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheProfileWithDifferentRepo(t *testing.T) {
	wrapped := sequenceVendor("first-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "shared-profile",
		Type:         profile.ProfileTypeOrg,
	}
	// first call misses cache
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Profile:             "org:shared-profile",
		Repositories:        []string{"any-repo", "different-repo"},
		Permissions:         []string{"read", "write"},
	})
	// second call hits, but repo changes, so token content is the same but repo is different
	result = v(context.Background(), ref, "https://github.com/test-org/different-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/different-repo.git",
		Profile:             "org:shared-profile",
		Repositories:        []string{"any-repo", "different-repo"},
		Permissions:         []string{"read", "write"},
	})
}

// calls wrapped when value expires
// returns error from wrapped on miss
func TestReturnsErrorForWrapperError(t *testing.T) {
	wrapped := sequenceVendor(E{"failed"})

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}
	// first call misses cache and returns error from wrapped
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorFailure(t, result, "failed")
}

func TestCacheMissWithNilVendorResponse(t *testing.T) {
	wrapped := sequenceVendor(nil, "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
		PipelineSlug: "my-pipeline",
	}

	// First call returns nil from the wrapped vendor
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorUnmatched(t, result)

	// Second call should not be served from cache; it should invoke the wrapped vendor again
	// and return the second token value. This verifies that nil results are not cached.
	result = v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

// E must be an error
var _ error = E{}

type E struct {
	M string
}

func (e E) Error() string {
	return e.M
}

// Test error handling in cache operations
func TestCacheGetError(t *testing.T) {
	wrapped := sequenceVendor("first-call")
	errorCache := &errorReturningCache{
		getError: errors.New("cache get failed"),
	}

	c := vendor.Cached(errorCache, mockDigester{digest: "test-digest"})
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}

	// Should log warning but proceed to fetch from vendor
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheSetError(t *testing.T) {
	wrapped := sequenceVendor("first-call")
	errorCache := &errorReturningCache{
		setError: errors.New("cache set failed"),
	}

	c := vendor.Cached(errorCache, mockDigester{digest: "test-digest"})
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}

	// Should log warning but return successful result
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheInvalidateError(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")
	errorCache := &errorReturningCache{
		invalidateError: errors.New("cache invalidate failed"),
		storedToken: &vendor.ProfileToken{
			Token:               "cached-token",
			VendedRepositoryURL: "https://github.com/test-org/old-repo.git",
			Repositories:        []string{"old-repo"},
			Profile:             "repo:default",
		},
	}

	c := vendor.Cached(errorCache, mockDigester{digest: "test-digest"})
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}

	// First call hits cache but repo mismatches, tries to invalidate (fails), then fetches
	result := v(context.Background(), ref, "https://github.com/test-org/different-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/different-repo.git",
		Repositories:        []string{"different-repo"},
		Profile:             "repo:default",
	})
}

func TestCacheInvalidRepositoryURL(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}

	// First call with valid repo
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// Second call with invalid repo URL (should trigger repo mismatch and fetch)
	result = v(context.Background(), ref, "not-a-valid-url")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "not-a-valid-url",
		Repositories:        []string{"not-a-valid-url"},
		Profile:             "repo:default",
	})
}

func TestCacheDigestChange(t *testing.T) {
	wrapped := sequenceVendor("first-call", "second-call")

	digester := &mutableDigester{digest: "digest-v1"}
	tokenCache, err := cache.NewMemory[vendor.ProfileToken](defaultTTL, 10_000)
	require.NoError(t, err)

	c := vendor.Cached(tokenCache, digester)
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "default",
		Type:         profile.ProfileTypeRepo,
		PipelineID:   "pipeline-id",
	}

	// First call misses cache
	result := v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "first-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})

	// Change digest (simulates config change)
	digester.digest = "digest-v2"

	// Second call misses cache due to different digest in key
	result = v(context.Background(), ref, "https://github.com/test-org/any-repo.git")
	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "second-call",
		VendedRepositoryURL: "https://github.com/test-org/any-repo.git",
		Repositories:        []string{"any-repo"},
		Profile:             "repo:default",
	})
}

// errorReturningCache is a mock cache that can return errors for testing
type errorReturningCache struct {
	getError        error
	setError        error
	invalidateError error
	storedToken     *vendor.ProfileToken
}

func (e *errorReturningCache) Get(ctx context.Context, key string) (vendor.ProfileToken, bool, error) {
	if e.getError != nil {
		return vendor.ProfileToken{}, false, e.getError
	}
	if e.storedToken != nil {
		return *e.storedToken, true, nil
	}
	return vendor.ProfileToken{}, false, nil
}

func (e *errorReturningCache) Set(ctx context.Context, key string, token vendor.ProfileToken) error {
	if e.setError != nil {
		return e.setError
	}
	return nil
}

func (e *errorReturningCache) Invalidate(ctx context.Context, key string) error {
	if e.invalidateError != nil {
		return e.invalidateError
	}
	return nil
}

// mutableDigester allows digest to be changed during tests
type mutableDigester struct {
	digest string
}

func (m *mutableDigester) Digest() string {
	return m.digest
}

// sequenceVendor returns each of the calls in sequence, either a token or an error
func sequenceVendor(calls ...any) vendor.ProfileTokenVendor {
	callIndex := 0

	// Profile data for test fixtures
	profileData := map[string]struct {
		repositories []string
		permissions  []string
	}{
		"org:shared-profile": {
			repositories: []string{"any-repo", "different-repo"},
			permissions:  []string{"read", "write"},
		},
		"org:read-plugins": {
			repositories: []string{"any-repo", "another-secret-repo"},
			permissions:  []string{"contents:read", "packages:read", "metadata:read"},
		},
	}

	return vendor.ProfileTokenVendor(func(ctx context.Context, ref profile.ProfileRef, repo string) vendor.VendorResult {
		if len(calls) <= callIndex {
			return vendor.NewVendorFailed(errors.New("unregistered call"))
		}

		c := calls[callIndex]
		callIndex++

		switch v := c.(type) {
		case nil:
			// unmatched return
			return vendor.NewVendorUnmatched()
		case string:
			if ref.Name == "default" {
				repoNames, _ := github.GetRepoNames([]string{repo})
				repoName := repo
				if len(repoNames) > 0 {
					repoName = repoNames[0]
				}
				return vendor.NewVendorSuccess(vendor.ProfileToken{
					Token:               v,
					VendedRepositoryURL: repo,
					Repositories:        []string{repoName},
					Profile:             ref.ShortString(),
				})
			} else {
				data, ok := profileData[ref.ShortString()]
				if !ok {
					return vendor.NewVendorFailed(errors.New("unknown profile"))
				}
				return vendor.NewVendorSuccess(vendor.ProfileToken{
					Token:               v,
					Repositories:        data.repositories,
					Permissions:         data.permissions,
					VendedRepositoryURL: repo,
					Profile:             ref.ShortString(),
				})
			}
		case error:
			return vendor.NewVendorFailed(v)
		default:
			return vendor.NewVendorFailed(errors.New("invalid call type"))
		}
	})
}
