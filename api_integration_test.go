//go:build integration

package main

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/testhelpers"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// TestIntegrationSetup verifies the integration test framework is configured correctly
func TestIntegrationSetup(t *testing.T) {
	t.Log("Integration test framework initialized successfully")
}

// TestJWTHelpers verifies JWT generation helpers work correctly
func TestJWTHelpers(t *testing.T) {
	// Generate key pair
	jwk := testhelpers.GenerateJWK(t)
	if jwk == nil {
		t.Fatal("expected JWK to be generated")
	}

	// Setup JWKS server
	jwksServer := testhelpers.SetupJWKSServer(t, jwk)
	defer jwksServer.Close()

	// Create valid claims
	claims := testhelpers.ValidClaims(josejwt.Claims{
		Audience: []string{"test-audience"},
		Subject:  "test-subject",
	})

	// Generate JWT
	token := testhelpers.CreateJWT(t, jwk, jwksServer.URL, claims)
	if token == "" {
		t.Fatal("expected token to be generated")
	}

	t.Log("JWT helpers verified successfully")
}
