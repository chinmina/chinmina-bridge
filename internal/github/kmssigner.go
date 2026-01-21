package github

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	// Explicitly import this to ensure the hash is available. This allows us to
	// assume that crypto.SHA256.Available() will return true.
	_ "crypto/sha256"
)

var _ ghinstallation.Signer = KMSSigner{}
var _ jwt.SigningMethod = KMSSigningMethod{}

// KMSClient defines the AWS API surface required by the KMSSigner.
type KMSClient interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func NewAWSKMSSigner(ctx context.Context, arn string) (KMSSigner, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return KMSSigner{}, err
	}
	client := kms.NewFromConfig(cfg)

	return NewKMSSigner(client, arn), nil
}

// KMSSigner defines a Signer compatible with the ghinstallation plugin that
// uses KMS to sign the JWT. KMS signing ensures that the private key is never
// exposed to the application.
type KMSSigner struct {
	ARN    string
	Method jwt.SigningMethod
}

func NewKMSSigner(client KMSClient, arn string) KMSSigner {
	method := NewSigningMethod(client)

	return KMSSigner{
		ARN:    arn,
		Method: method,
	}
}

func (s KMSSigner) Sign(claims jwt.Claims) (string, error) {
	defer functionDuration(func(l zerolog.Logger) { l.Info().Msg("KMSSigner.Sign()") })()

	tok, err := jwt.NewWithClaims(s.Method, claims).SignedString(s.ARN)

	return tok, err
}

// KMSSigningMethod defines a golang-jwt compatible signing method that uses AWS KMS.
type KMSSigningMethod struct {
	client KMSClient
	hash   crypto.Hash
}

func NewSigningMethod(client KMSClient) KMSSigningMethod {
	alg := crypto.SHA256

	return KMSSigningMethod{
		client: client,
		hash:   alg,
	}
}

// Alg returns the signing algorithm allowed for this method, which is "RS256".
func (k KMSSigningMethod) Alg() string {
	return "RS256"
}

// Sign uses AWS KMS to sign the given string with the provided key (the string
// ARN of the KMS key to use). This will fail if the current AWS user does not
// have permission to sign the key, or if KMS cannot be reached, or if the key
// doesn't exist.
func (k KMSSigningMethod) Sign(signingString string, key any) (string, error) {
	keyArn, ok := key.(string)
	if !ok {
		return "", errors.New("unexpected key type supplied (string expected)")
	}

	// create a digest of the source material, ensuring that the data sent to AWS
	// is both anonymous and a constant size.
	hasher := k.hash.New()
	hasher.Write([]byte(signingString))
	digest := hasher.Sum(nil)

	// Use KMS to sign the digest with the given ARN.
	//
	// Note: there is an outstanding PR on ghinstallation to allow this method to
	// pass a context: https://github.com/bradleyfalzon/ghinstallation/pull/119
	result, err := k.client.Sign(context.Background(), &kms.SignInput{
		KeyId:            aws.String(keyArn),
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		MessageType:      types.MessageTypeDigest,
		Message:          digest,
	})
	if err != nil {
		return "", fmt.Errorf("KMS signing failed: %w", err)
	}

	// Return the base64 encoded signature. The JWT spec defines that no base64
	// padding should be included, so RawURLEncoding is used.
	sig := result.Signature
	encodedSig := base64.RawURLEncoding.EncodeToString(sig)

	return encodedSig, nil
}

func (k KMSSigningMethod) Verify(signingString string, signature string, key any) error {
	// Not implemented as we are only signing JWTs for GitHub access, not
	// verifying them
	return errors.New("not implemented")
}

func functionDuration(l func(zerolog.Logger)) func() {
	start := time.Now()

	return func() {
		d := time.Since(start)
		l(log.With().Dur("duration", d).Logger())
	}
}
