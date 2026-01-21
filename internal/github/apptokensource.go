package github

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"
)

// appTokenSource implements oauth2.TokenSource for generating GitHub App JWTs.
// The JWT is used to authenticate as the GitHub App (not as an installation).
//
// This token source generates tokens that are valid for 10 minutes, following
// GitHub's requirements for App JWTs. The IssuedAt claim is backdated by 60
// seconds to account for clock drift between systems.
type appTokenSource struct {
	signingKey any    // jwk.Key or kmsSigningKey
	appID      string // GitHub App ID (used as JWT issuer)
}

// NewAppTokenSource creates a new AppTokenSource with the given signing key and app ID.
// The signingKey must be either a jwk.Key (from PEM parsing) or a kmsSigningKey.
// The returned TokenSource is wrapped in ReuseTokenSource for automatic caching.
func NewAppTokenSource(signingKey any, appID string) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, newAppTokenSource(signingKey, appID))
}

// newAppTokenSource creates the underlying token source without caching.
// Exported for testing purposes.
func newAppTokenSource(signingKey any, appID string) *appTokenSource {
	return &appTokenSource{
		signingKey: signingKey,
		appID:      appID,
	}
}

// Token generates a new GitHub App JWT.
// The token has a 10-minute expiry (GitHub's maximum for App JWTs).
// The IssuedAt time is backdated by 60 seconds to handle clock drift.
func (a *appTokenSource) Token() (*oauth2.Token, error) {
	now := time.Now()
	iat := now.Add(-60 * time.Second)
	exp := now.Add(10 * time.Minute)

	// Build JWT claims using jwx
	token, err := jwt.NewBuilder().
		Issuer(a.appID).
		IssuedAt(iat).
		Expiration(exp).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build JWT claims: %w", err)
	}

	// Sign with RS256 - key type determines signing behavior via delegatingSigner
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), a.signingKey))
	if err != nil {
		return nil, fmt.Errorf("sign JWT: %w", err)
	}

	return &oauth2.Token{
		AccessToken: string(signed),
		TokenType:   "Bearer",
		Expiry:      exp,
	}, nil
}
