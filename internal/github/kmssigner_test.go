package github_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/chinmina/chinmina-bridge/internal/github"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type KMSClientFunc func(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)

func (f KMSClientFunc) Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return f(ctx, in, optFns...)
}

func TestSigner_Sign(t *testing.T) {
	signature := []byte("test_signature")
	expectedSignature := base64.RawURLEncoding.EncodeToString(signature)

	client := KMSClientFunc(func(ctx context.Context, si *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
		return &kms.SignOutput{
			Signature: signature,
		}, nil
	})
	s := github.NewKMSSigner(client, "arn:fictional")

	tok, err := s.Sign(jwt.RegisteredClaims{Issuer: "test"})
	require.NoError(t, err)

	segments := strings.SplitN(tok, ".", 3)

	assert.Equal(t, expectedSignature, segments[2])
}

func TestSigningMethod_AlgCorrect(t *testing.T) {
	m := github.NewSigningMethod(nil)
	assert.Equal(t, "RS256", m.Alg())
}

func TestSigningMethod_SignReturnsEncoded(t *testing.T) {
	signature := []byte("test_signature")
	expectedSignature := base64.RawURLEncoding.EncodeToString(signature)

	client := KMSClientFunc(func(ctx context.Context, si *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
		return &kms.SignOutput{
			Signature: signature,
		}, nil
	})

	m := github.NewSigningMethod(client)

	sig, err := m.Sign("input-string", "keyArn")
	require.NoError(t, err)
	assert.Equal(t, expectedSignature, sig)
}

func TestSigningMethod_SignFailsWhenKMSFails(t *testing.T) {
	client := KMSClientFunc(func(ctx context.Context, si *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
		return nil, errors.New("simulated KMS failure")
	})

	m := github.NewSigningMethod(client)

	_, err := m.Sign("input-string", "keyArn")
	assert.ErrorContains(t, err, "simulated KMS failure")
}

func TestSigningMethod_SignFailsWithInvalidKey(t *testing.T) {
	client := KMSClientFunc(func(ctx context.Context, si *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
		return nil, errors.New("simulated KMS failure")
	})

	m := github.NewSigningMethod(client)

	_, err := m.Sign("input-string", 222)
	assert.ErrorContains(t, err, "unexpected key type supplied")
}

func TestSigningMethod_VerifyFails(t *testing.T) {
	client := KMSClientFunc(func(ctx context.Context, si *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
		return nil, errors.New("simulated KMS failure")
	})

	m := github.NewSigningMethod(client)

	err := m.Verify("source", "sig", "key")
	assert.ErrorContains(t, err, "not implemented")
}
