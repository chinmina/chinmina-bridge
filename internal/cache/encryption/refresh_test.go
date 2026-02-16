package encryption

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestRefreshableAEAD_EncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	aead := &recordingAEAD{}
	r, err := newRefreshableAEAD(ctx, staticLoader(aead), time.Hour)
	require.NoError(t, err)
	defer func() { assert.NoError(t, r.Close()) }()

	plaintext := []byte("hello")
	aad := []byte("context")

	ct, err := r.Encrypt(plaintext, aad)
	require.NoError(t, err)

	pt, err := r.Decrypt(ct, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestRefreshableAEAD_InitialLoadFailure(t *testing.T) {
	ctx := context.Background()
	loadErr := errors.New("kms unavailable")

	r, err := newRefreshableAEAD(ctx, failingLoader(loadErr), time.Hour)

	assert.Nil(t, r)
	assert.ErrorIs(t, err, loadErr)
	assert.ErrorContains(t, err, "loading initial AEAD")
}

func TestRefreshableAEAD_RefreshReplacesAEAD(t *testing.T) {
	ctx := context.Background()
	first := &recordingAEAD{id: "first"}
	second := &recordingAEAD{id: "second"}

	calls := atomic.Int32{}
	loader := func(_ context.Context) (tink.AEAD, error) {
		n := calls.Add(1)
		if n == 1 {
			return first, nil
		}
		return second, nil
	}

	r, err := newRefreshableAEAD(ctx, loader, 10*time.Millisecond)
	require.NoError(t, err)
	defer func() { assert.NoError(t, r.Close()) }()

	// Wait for at least one refresh to occur.
	require.Eventually(t, func() bool {
		return calls.Load() >= 2
	}, time.Second, 5*time.Millisecond)

	// The active AEAD should now be the second one.
	r.mu.RLock()
	active := r.aead
	r.mu.RUnlock()
	assert.Same(t, second, active)
}

func TestRefreshableAEAD_RefreshFailureContinuesWithExisting(t *testing.T) {
	ctx := context.Background()
	original := &recordingAEAD{id: "original"}

	calls := atomic.Int32{}
	loader := func(_ context.Context) (tink.AEAD, error) {
		n := calls.Add(1)
		if n == 1 {
			return original, nil
		}
		return nil, errors.New("refresh failed")
	}

	r, err := newRefreshableAEAD(ctx, loader, 10*time.Millisecond)
	require.NoError(t, err)
	defer func() { assert.NoError(t, r.Close()) }()

	// Wait for at least one failed refresh attempt.
	require.Eventually(t, func() bool {
		return calls.Load() >= 2
	}, time.Second, 5*time.Millisecond)

	// The original AEAD should still be active.
	r.mu.RLock()
	active := r.aead
	r.mu.RUnlock()
	assert.Same(t, original, active)
}

func TestRefreshableAEAD_CloseStopsGoroutine(t *testing.T) {
	ctx := context.Background()

	calls := atomic.Int32{}
	loader := func(_ context.Context) (tink.AEAD, error) {
		calls.Add(1)
		return &recordingAEAD{}, nil
	}

	r, err := newRefreshableAEAD(ctx, loader, 10*time.Millisecond)
	require.NoError(t, err)

	err = r.Close()
	assert.NoError(t, err)

	// Record call count after close, then wait and verify no more calls occur.
	countAfterClose := calls.Load()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, countAfterClose, calls.Load(), "loader should not be called after Close")
}

func TestRefreshableAEAD_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()

	loader := func(_ context.Context) (tink.AEAD, error) {
		return &recordingAEAD{}, nil
	}

	r, err := newRefreshableAEAD(ctx, loader, 5*time.Millisecond)
	require.NoError(t, err)
	defer func() { assert.NoError(t, r.Close()) }()

	// Hammer encrypt/decrypt concurrently while refreshes happen.
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 50 {
				_, _ = r.Encrypt([]byte("data"), []byte("aad"))
				_, _ = r.Decrypt([]byte("data"), []byte("aad"))
			}
		})
	}
	wg.Wait()
}

func TestRefreshableAEAD_CloseCancelsInflightRefresh(t *testing.T) {
	ctx := context.Background()
	loaderStarted := make(chan struct{})

	calls := atomic.Int32{}
	loader := func(ctx context.Context) (tink.AEAD, error) {
		n := calls.Add(1)
		if n == 1 {
			return &recordingAEAD{}, nil
		}
		// Signal that the slow refresh has started, then block until
		// the context is cancelled (which Close should trigger).
		close(loaderStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	r, err := newRefreshableAEAD(ctx, loader, 10*time.Millisecond)
	require.NoError(t, err)

	// Wait for the slow refresh call to be in-flight.
	select {
	case <-loaderStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for refresh to start")
	}

	// Close should return promptly because it cancels the in-flight loader.
	done := make(chan struct{})
	go func() {
		assert.NoError(t, r.Close())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked despite in-flight refresh; context cancellation not working")
	}
}

func TestRefreshableAEAD_DoubleCloseIsSafe(t *testing.T) {
	ctx := context.Background()
	r, err := newRefreshableAEAD(ctx, staticLoader(&recordingAEAD{}), time.Hour)
	require.NoError(t, err)

	assert.NoError(t, r.Close())
	assert.NoError(t, r.Close(), "second Close should not panic")
}

// -- test helpers --

// recordingAEAD is a passthrough AEAD that lets tests identify which instance
// is active.
type recordingAEAD struct {
	id string
}

func (a *recordingAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return plaintext, nil
}

func (a *recordingAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return ciphertext, nil
}

func staticLoader(a tink.AEAD) aeadLoader {
	return func(_ context.Context) (tink.AEAD, error) {
		return a, nil
	}
}

func failingLoader(err error) aeadLoader {
	return func(_ context.Context) (tink.AEAD, error) {
		return nil, err
	}
}
