package vendor

import (
	"context"
	"fmt"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// Auditor is a function that wraps a PipelineTokenVendor and records the result
// of vending a token to the audit log.
func Auditor(vendor ProfileTokenVendor) ProfileTokenVendor {
	return func(ctx context.Context, ref profile.ProfileRef, repo string) (*ProfileToken, error) {
		token, err := vendor(ctx, ref, repo)

		entry := audit.Log(ctx)
		if err != nil {
			entry.Error = fmt.Sprintf("vendor failure: %v", err)
		} else if token == nil {
			entry.Error = "repository mismatch, no token vended"
		} else {
			entry.RequestedRepository = token.RequestedRepositoryURL
			entry.Repositories = token.Repositories
			entry.Permissions = token.Permissions
			entry.RequestedProfile = ref.String()
			entry.ExpirySecs = token.Expiry.Unix()
		}

		return token, err
	}
}
