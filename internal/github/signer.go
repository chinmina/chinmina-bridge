package github

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func init() {
	MustRegisterSigner()
}

// MustRegisterSigner registers the delegating signer for RS256. This must be
// called before any JWT signing operations. It panics if registration fails,
// as this indicates a fundamental configuration error that prevents the
// application from functioning.
func MustRegisterSigner() {
	if err := registerDelegatingSigner(); err != nil {
		panic(fmt.Sprintf("failed to initialize delegating signer: %v", err))
	}
}

// KMSClient defines the AWS API surface required for KMS signing.
type KMSClient interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// kmsSigningKey is the key type passed to kmsSigner.Sign(). It carries the
// KMS client needed for AWS KMS-based signing without exposing private key
// material.
//
// It deliberately holds no context. Signing is lazy and recurring — a fresh
// App JWT roughly every ten minutes for the life of the process — so a
// context captured at construction (startup, or app registry verification)
// would produce a clean boot followed by permanent `context canceled` on
// every mint once that context expired. The failure reproduces only for
// ARN-backed keys, never PEM, so it is invisible to most tests.
type kmsSigningKey struct {
	client KMSClient
	arn    string
}

// kmsSignTimeout bounds a single KMS signing call. Sign has no caller-supplied
// context (jws.Signer2 does not carry one), so the call supplies its own
// rather than inheriting a lifetime it cannot reason about.
const kmsSignTimeout = 30 * time.Second

// kmsSigner implements jws.Signer2 for AWS KMS-based signing. The actual
// signing parameters are extracted from the kmsSigningKey passed to Sign().
type kmsSigner struct{}

// Algorithm returns the signature algorithm (RS256).
func (kmsSigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.RS256()
}

// Sign performs RS256 signing using AWS KMS. The key parameter must be a
// kmsSigningKey containing the KMS client and key ARN.
func (kmsSigner) Sign(key any, payload []byte) ([]byte, error) {
	k, ok := key.(kmsSigningKey)
	if !ok {
		return nil, fmt.Errorf("kmsSigner requires kmsSigningKey, got %T", key)
	}

	ctx, cancel := context.WithTimeout(context.Background(), kmsSignTimeout)
	defer cancel()

	hash := sha256.Sum256(payload)
	out, err := k.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(k.arn),
		Message:          hash[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS signing failed: %w", err)
	}
	return out.Signature, nil
}

// delegatingSigner implements jws.Signer2 and dispatches signing operations
// based on key type. This allows using the same jwt.Sign() call for both
// RSA private keys and KMS-based signing.
type delegatingSigner struct {
	builtinRS256 jws.Signer2 // for *rsa.PrivateKey and jwk.Key
	kmsSigner    jws.Signer2 // for kmsSigningKey
}

// Algorithm returns the signature algorithm (RS256).
func (d *delegatingSigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.RS256()
}

// Sign dispatches to the appropriate signing implementation based on key type.
// Supports *rsa.PrivateKey for direct signing, jwk.Key for JWK-wrapped keys,
// and kmsSigningKey for AWS KMS signing.
func (d *delegatingSigner) Sign(key any, payload []byte) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey, jwk.Key:
		return d.builtinRS256.Sign(k, payload)
	case kmsSigningKey:
		return d.kmsSigner.Sign(k, payload)
	default:
		return nil, fmt.Errorf("unsupported key type for RS256: %T", key)
	}
}

// registerDelegatingSigner replaces the built-in RS256 signer with our delegating
// signer. It captures the built-in signer first so it can be used for RSA keys.
func registerDelegatingSigner() error {
	builtin, err := jws.SignerFor(jwa.RS256())
	if err != nil {
		return fmt.Errorf("failed to get built-in RS256 signer: %w", err)
	}

	delegating := &delegatingSigner{
		builtinRS256: builtin,
		kmsSigner:    kmsSigner{},
	}
	if err := jws.RegisterSigner(jwa.RS256(), delegating); err != nil {
		return fmt.Errorf("failed to register delegating signer: %w", err)
	}
	return nil
}
