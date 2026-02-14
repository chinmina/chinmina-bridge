package encryption

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/tink-crypto/tink-go-awskms/v3/integration/awskms"
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

// NewAEADFromKMS creates a tink.AEAD from a keyset stored in AWS Secrets
// Manager, encrypted with an AWS KMS key. The KMS key is only used at startup
// to decrypt the keyset; all subsequent encrypt/decrypt operations are local.
//
// keysetURI format: aws-secretsmanager://secret-name
// kmsEnvelopeKeyURI format: aws-kms://arn:aws:kms:region:account:key/key-id
func NewAEADFromKMS(ctx context.Context, keysetURI, kmsEnvelopeKeyURI string) (tink.AEAD, error) {
	kmsAEAD, err := awskms.NewAEADWithContext(kmsEnvelopeKeyURI)
	if err != nil {
		return nil, fmt.Errorf("creating KMS AEAD: %w", err)
	}

	keysetReader, err := readKeysetFromSecretsManager(ctx, keysetURI)
	if err != nil {
		return nil, fmt.Errorf("reading keyset: %w", err)
	}

	handle, err := keyset.ReadWithContext(ctx, keysetReader, kmsAEAD, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting keyset: %w", err)
	}

	primitive, err := aead.New(handle)
	if err != nil {
		return nil, fmt.Errorf("creating AEAD primitive: %w", err)
	}

	if err := Validate(primitive); err != nil {
		return nil, fmt.Errorf("validating AEAD: %w", err)
	}

	return primitive, nil
}

// readKeysetFromSecretsManager reads a Tink keyset from AWS Secrets Manager.
// URI format: aws-secretsmanager://secret-name
func readKeysetFromSecretsManager(ctx context.Context, uri string) (*keyset.JSONReader, error) {
	const prefix = "aws-secretsmanager://"
	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("invalid secrets manager URI %q: must start with %s", uri, prefix)
	}

	secretName := strings.TrimPrefix(uri, prefix)
	if secretName == "" {
		return nil, fmt.Errorf("invalid secrets manager URI %q: secret name is empty", uri)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return nil, fmt.Errorf("getting secret %q: %w", secretName, err)
	}

	if result.SecretString == nil {
		return nil, fmt.Errorf("secret %q has no string value", secretName)
	}

	return keyset.NewJSONReader(strings.NewReader(*result.SecretString)), nil
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
