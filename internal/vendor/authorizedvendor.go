package vendor

import (
	"context"
	"fmt"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// Authorized decorates a vendor so that the profile's match rules are
// evaluated against the caller's claims on every call, cache hit or miss.
//
// Match-rule evaluation used to live inside the minting vendors, but Cached
// short-circuits and returns a cached token before the wrapped vendor ever
// runs. That let any caller who could name a profile already warmed in the
// cache receive that profile's token regardless of its match rules. Composing
// Authorized outside Cached closes the gap: the gate runs on every request, so
// a cache hit can never bypass it.
//
// The rules come from the profile resolved at the request boundary, so the
// decision is made against the same configuration generation that determines
// the cache key and the token's permissions.
func Authorized[T any](v ProfileTokenVendor[T]) ProfileTokenVendor[T] {
	return func(ctx context.Context, r Resolved[T], repo string) VendorResult {
		claims := profile.NewValidatingLookup(
			jwt.RequireBuildkiteClaimsFromContext(ctx),
		)
		result := AuditingMatcher(ctx, r.Profile.Match)(claims)

		if result.Err != nil {
			return NewVendorFailed(fmt.Errorf("profile match evaluation failed: %w", result.Err))
		}
		if !result.Matched {
			return NewVendorFailed(profile.ProfileMatchFailedError{Name: r.Ref.Name})
		}

		return v(ctx, r, repo)
	}
}
