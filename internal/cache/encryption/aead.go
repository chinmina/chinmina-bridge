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

// KMSAPI is the interface for AWS KMS operations required by this package.
type KMSAPI = awskms.KMSAPI

// SecretsManagerAPI is the interface for AWS Secrets Manager operations
// required by this package.
type SecretsManagerAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput,
		optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type awsOptions struct {
	kmsClient KMSAPI
	smClient  SecretsManagerAPI
}

// AWSOption configures LoadKeysetFromAWS behaviour.
type AWSOption func(*awsOptions)

// WithKMSClient provides a custom KMS client, bypassing default AWS
// credential resolution for KMS.
func WithKMSClient(c KMSAPI) AWSOption {
	return func(o *awsOptions) {
		o.kmsClient = c
	}
}

// WithSecretsManagerClient provides a custom Secrets Manager client, bypassing
// default AWS credential resolution for Secrets Manager.
func WithSecretsManagerClient(c SecretsManagerAPI) AWSOption {
	return func(o *awsOptions) {
		o.smClient = c
	}
}

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

// NewAEAD creates a validated tink.AEAD from a keyset handle.
func NewAEAD(handle *keyset.Handle) (tink.AEAD, error) {
	primitive, err := aead.New(handle)
	if err != nil {
		return nil, fmt.Errorf("creating AEAD primitive: %w", err)
	}

	if err := Validate(primitive); err != nil {
		return nil, fmt.Errorf("validating AEAD: %w", err)
	}

	return primitive, nil
}

// LoadKeysetFromAWS fetches an encrypted keyset from Secrets Manager,
// decrypts it with KMS, and returns the handle. By default, AWS clients are
// created from the default credential chain. Use WithKMSClient and
// WithSecretsManagerClient to inject custom clients.
//
// keysetURI format: aws-secretsmanager://secret-name
// kmsKeyURI format: aws-kms://arn:aws:kms:region:account:key/key-id
func LoadKeysetFromAWS(ctx context.Context, keysetURI, kmsKeyURI string, opts ...AWSOption) (*keyset.Handle, error) {
	var o awsOptions
	for _, opt := range opts {
		opt(&o)
	}

	var kmsOpts []awskms.ClientOption
	if o.kmsClient != nil {
		kmsOpts = append(kmsOpts, awskms.WithKMS(o.kmsClient))
	}
	kmsAEAD, err := awskms.NewAEADWithContext(kmsKeyURI, kmsOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating KMS AEAD: %w", err)
	}

	smClient := o.smClient
	if smClient == nil {
		cfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading AWS config: %w", err)
		}
		smClient = secretsmanager.NewFromConfig(cfg)
	}

	keysetReader, err := readKeysetFromSecretsManager(ctx, keysetURI, smClient)
	if err != nil {
		return nil, fmt.Errorf("reading keyset: %w", err)
	}

	handle, err := keyset.ReadWithContext(ctx, keysetReader, kmsAEAD, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting keyset: %w", err)
	}

	return handle, nil
}

// readKeysetFromSecretsManager reads a Tink keyset from AWS Secrets Manager.
// URI format: aws-secretsmanager://secret-name
func readKeysetFromSecretsManager(ctx context.Context, uri string, client SecretsManagerAPI) (*keyset.JSONReader, error) {
	const prefix = "aws-secretsmanager://"
	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("invalid secrets manager URI %q: must start with %s", uri, prefix)
	}

	secretName := strings.TrimPrefix(uri, prefix)
	if secretName == "" {
		return nil, fmt.Errorf("invalid secrets manager URI %q: secret name is empty", uri)
	}

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
