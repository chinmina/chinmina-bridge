package encryption

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// aeadLoader loads an AEAD from external key material. This abstraction allows
// testing without real KMS/Secrets Manager dependencies.
type aeadLoader func(ctx context.Context) (tink.AEAD, error)

// RefreshableAEAD wraps a tink.AEAD with periodic keyset refresh capability.
// It reloads the keyset on a configurable interval, enabling hot key rotation
// without service restart. Refresh failures are logged but non-fatal: the
// existing keyset continues to be used.
type RefreshableAEAD struct {
	mu     sync.RWMutex
	aead   tink.AEAD
	loader aeadLoader
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewRefreshableAEAD creates an AEAD that refreshes its keyset every 15 minutes.
// The initial keyset is loaded synchronously; if that fails the error is returned
// and no goroutine is started. On success, a background goroutine begins periodic
// refresh. Call Close to stop it.
func NewRefreshableAEAD(ctx context.Context, keysetURI, kmsEnvelopeKeyURI string) (*RefreshableAEAD, error) {
	loader := func(ctx context.Context) (tink.AEAD, error) {
		return NewAEADFromKMS(ctx, keysetURI, kmsEnvelopeKeyURI)
	}

	return newRefreshableAEAD(ctx, loader, 15*time.Minute)
}

// newRefreshableAEAD is the internal constructor that accepts a loader and
// interval, enabling testing with short intervals and fake AEADs.
func newRefreshableAEAD(ctx context.Context, loader aeadLoader, interval time.Duration) (*RefreshableAEAD, error) {
	initial, err := loader(ctx)
	if err != nil {
		return nil, err
	}

	r := &RefreshableAEAD{
		aead:   initial,
		loader: loader,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	go r.refreshLoop(ctx, interval)

	return r, nil
}

// Encrypt delegates to the current AEAD under a read lock.
func (r *RefreshableAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.aead.Encrypt(plaintext, associatedData)
}

// Decrypt delegates to the current AEAD under a read lock.
func (r *RefreshableAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.aead.Decrypt(ciphertext, associatedData)
}

// Close stops the refresh goroutine and waits for it to exit.
func (r *RefreshableAEAD) Close() error {
	close(r.stopCh)
	<-r.doneCh
	return nil
}

// refreshLoop runs in a goroutine, refreshing the keyset at each tick.
func (r *RefreshableAEAD) refreshLoop(ctx context.Context, interval time.Duration) {
	defer close(r.doneCh)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refresh(ctx)
		}
	}
}

// refresh loads a new keyset and atomically replaces the current AEAD.
// Failures are logged but non-fatal: the service continues with the existing
// keyset.
func (r *RefreshableAEAD) refresh(ctx context.Context) {
	log.Info().Msg("refreshing encryption keyset")

	newAEAD, err := r.loader(ctx)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("failed to refresh encryption keyset, continuing with current keyset")
		return
	}

	r.mu.Lock()
	r.aead = newAEAD
	r.mu.Unlock()

	log.Info().Msg("encryption keyset refreshed successfully")
}
