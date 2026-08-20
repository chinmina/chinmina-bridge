package github

import (
	"context"
	"sync"
	"testing"

	api "github.com/google/go-github/v90/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A malformed AWS_MAX_ATTEMPTS fails the load in the SDK's environment parsing,
// with no credentials, network or region lookup involved: the cheapest
// deterministic stand-in for the transient credential-provider failures this
// loader has to survive.
const invalidAWSMaxAttempts = "not-a-number"

// One failed resolution must not become the answer for the process lifetime:
// every KMS-backed app in the registry shares a single loader, so a cached
// error would disable all of them until a restart.
func TestAWSConfigLoader_RetriesAfterAFailedLoad(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-southeast-2")
	t.Setenv("AWS_MAX_ATTEMPTS", invalidAWSMaxAttempts)

	load := newAWSConfigLoader(context.Background())

	_, err := load()
	require.Error(t, err)

	// A tracked t.Setenv, not a raw unset: the latter bypasses the
	// testing package's env synchronization and escapes its cleanup.
	t.Setenv("AWS_MAX_ATTEMPTS", "3")

	cfg, err := load()

	require.NoError(t, err, "a failed load must not be cached")
	assert.Equal(t, "ap-southeast-2", cfg.Region)
}

// The loader exists so that resolution happens once, lazily: a deployment with
// no ARN-backed key never resolves at all, and one with several resolves once.
// Poisoning the environment after the first success makes a second resolution
// visible — it would either fail or report the new region.
func TestAWSConfigLoader_ReusesASuccessfulLoad(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-southeast-2")

	load := newAWSConfigLoader(context.Background())

	first, err := load()
	require.NoError(t, err)

	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_MAX_ATTEMPTS", invalidAWSMaxAttempts)

	second, err := load()

	require.NoError(t, err, "a resolved configuration must not be resolved again")
	assert.Equal(t, first.Region, second.Region)
	assert.Equal(t, "ap-southeast-2", second.Region)
}

// Registry startup verifies every app concurrently, so apps sharing a loader
// can call it at the same time. Run under -race, this is the check that the
// cache is guarded.
func TestAWSConfigLoader_IsSafeForConcurrentUse(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-southeast-2")

	load := newAWSConfigLoader(context.Background())

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			cfg, err := load()
			assert.NoError(t, err)
			assert.Equal(t, "ap-southeast-2", cfg.Region)
		})
	}
	wg.Wait()
}

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
				Contents: new("read"),
				Packages: new("write"),
			},
		},
		{
			name:   "multiple scopes",
			scopes: []string{"pull_requests:write", "actions:read", "metadata:read"},
			expected: &api.InstallationPermissions{
				PullRequests: new("write"),
				Actions:      new("read"),
				Metadata:     new("read"),
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
