package encryption

import (
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// Validate performs a test encryption/decryption cycle to verify the AEAD is
// working. Call this at startup to fail fast if encryption is misconfigured.
func Validate(a tink.AEAD) error {
	testPlaintext := []byte("chinmina-bridge-encryption-test")
	testAAD := []byte("validation")

	ciphertext, err := a.Encrypt(testPlaintext, testAAD)
	if err != nil {
		return fmt.Errorf("validation encrypt failed: %w", err)
	}

	decrypted, err := a.Decrypt(ciphertext, testAAD)
	if err != nil {
		return fmt.Errorf("validation decrypt failed: %w", err)
	}

	if !bytes.Equal(testPlaintext, decrypted) {
		return fmt.Errorf("validation round-trip failed: plaintext mismatch")
	}

	return nil
}

// NewTestAEAD creates a tink.AEAD for testing without KMS.
// Only use in tests — keys are not persisted or protected.
func NewTestAEAD() (tink.AEAD, error) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("creating test keyset handle: %w", err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		return nil, fmt.Errorf("creating test AEAD primitive: %w", err)
	}
	return primitive, nil
}
