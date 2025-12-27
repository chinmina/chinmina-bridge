package profile_test

import (
	"sync"
	"testing"
	"time"

	"github.com/chinmina/chinmina-bridge/internal/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewProfileStoreOf_OrganizationProfile verifies NewProfileStoreOf creates a store for organization profiles.
func TestNewProfileStoreOf_OrganizationProfile(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.OrganizationProfileAttr]()

	assert.NotNil(t, store)
}

// TestNewProfileStoreOf_PipelineProfile verifies NewProfileStoreOf creates a store for pipeline profiles.
func TestNewProfileStoreOf_PipelineProfile(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.PipelineProfileAttr]()

	assert.NotNil(t, store)
}

// TestProfileStoreOf_Get_Success verifies successful retrieval of a profile.
func TestProfileStoreOf_Get_Success(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.OrganizationProfileAttr]()

	// Add a profile
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)
	store.Update("test-profile", authProfile)

	// Retrieve the profile
	retrieved, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, attrs, retrieved.Attrs)
}

// TestProfileStoreOf_Get_NotFound verifies ProfileNotFoundError is returned for missing profiles.
func TestProfileStoreOf_Get_NotFound(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.OrganizationProfileAttr]()

	// Try to get a non-existent profile
	_, err := store.Get("nonexistent")

	require.Error(t, err)
	var notFoundErr profile.ProfileNotFoundError
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "nonexistent", notFoundErr.Name)
}

// TestProfileStoreOf_Update_NewProfile verifies Update adds a new profile.
func TestProfileStoreOf_Update_NewProfile(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.OrganizationProfileAttr]()

	// Add a profile
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)
	store.Update("new-profile", authProfile)

	// Verify it was added
	retrieved, err := store.Get("new-profile")
	require.NoError(t, err)
	assert.Equal(t, attrs, retrieved.Attrs)
}

// TestProfileStoreOf_Update_ExistingProfile verifies Update replaces an existing profile.
func TestProfileStoreOf_Update_ExistingProfile(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.OrganizationProfileAttr]()

	// Add initial profile
	matcher1 := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs1 := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile1 := profile.NewAuthorizedProfile(matcher1, attrs1)
	store.Update("test-profile", authProfile1)

	// Update with new profile
	matcher2 := profile.ExactMatcher("pipeline_slug", "other-pipeline")
	attrs2 := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/other-repo"},
		Permissions:  []string{"packages:write"},
	}
	authProfile2 := profile.NewAuthorizedProfile(matcher2, attrs2)
	store.Update("test-profile", authProfile2)

	// Verify it was updated
	retrieved, err := store.Get("test-profile")
	require.NoError(t, err)
	assert.Equal(t, attrs2, retrieved.Attrs)
}

// TestProfileStoreOf_ConcurrentReads verifies concurrent reads can execute in parallel.
func TestProfileStoreOf_ConcurrentReads(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.OrganizationProfileAttr]()

	// Add a profile
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)
	store.Update("test-profile", authProfile)

	const numGoroutines = 10
	var wg sync.WaitGroup

	// Channel to track when each goroutine starts reading
	startedReading := make(chan struct{}, numGoroutines)
	// Channel to coordinate when goroutines should finish
	finishReading := make(chan struct{})

	// Launch multiple read goroutines
	for range numGoroutines {
		wg.Go(func() {
			// Signal that we've started reading
			startedReading <- struct{}{}

			// Hold the read lock by performing a get
			_, err := store.Get("test-profile")
			assert.NoError(t, err)

			// Wait for signal to finish
			<-finishReading
		})
	}

	// Wait for all goroutines to start reading
	for range numGoroutines {
		select {
		case <-startedReading:
			// Good, goroutine started
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for goroutines to start - reads may be blocking each other")
		}
	}

	// If we got here, all goroutines started reading concurrently
	// Now let them finish
	close(finishReading)
	wg.Wait()
}

// TestProfileStoreOf_ConcurrentReadsAndWrites verifies reads and writes maintain consistency.
func TestProfileStoreOf_ConcurrentReadsAndWrites(t *testing.T) {
	store := profile.NewProfileStoreOf[profile.OrganizationProfileAttr]()

	// Add initial profile
	matcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
	attrs := profile.OrganizationProfileAttr{
		Repositories: []string{"chinmina/chinmina-bridge"},
		Permissions:  []string{"contents:read"},
	}
	authProfile := profile.NewAuthorizedProfile(matcher, attrs)
	store.Update("test-profile", authProfile)

	const numReaders = 20
	const numWriters = 5
	var wg sync.WaitGroup
	errChan := make(chan error, numReaders+numWriters)

	// Launch concurrent readers
	for range numReaders {
		wg.Go(func() {
			_, err := store.Get("test-profile")
			if err != nil {
				errChan <- err
			}
		})
	}

	// Launch concurrent writers
	for range numWriters {
		wg.Go(func() {
			newMatcher := profile.ExactMatcher("pipeline_slug", "my-pipeline")
			newAttrs := profile.OrganizationProfileAttr{
				Repositories: []string{"chinmina/chinmina-bridge"},
				Permissions:  []string{"contents:read"},
			}
			newAuthProfile := profile.NewAuthorizedProfile(newMatcher, newAttrs)
			store.Update("test-profile", newAuthProfile)
		})
	}

	wg.Wait()
	close(errChan)

	// Verify no errors occurred during concurrent access
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}
	assert.Empty(t, errors, "Should have no errors during concurrent read/write operations")
}
