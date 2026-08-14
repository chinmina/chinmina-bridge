package vendor

import (
	"context"
	"fmt"

	"github.com/chinmina/chinmina-bridge/internal/jwt"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// Authorized decorates a vendor so that the profile's match rules are
// evaluated on every call, cache hit or miss. It must be composed outside
// Cached, which short-circuits on a hit before the wrapped vendor runs;
// placed inside, a warmed cache entry would bypass the match rules entirely.
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
