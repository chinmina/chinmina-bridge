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

			// Populate match results for audit logging
			result := token.MatchResult
			if result.Err != nil {
				// Validation error: populate ClaimsFailed if attempt details available
				if result.Attempt != nil {
					entry.ClaimsFailed = []audit.ClaimFailure{
						{
							Claim:   result.Attempt.Claim,
							Pattern: result.Attempt.Pattern,
							Value:   result.Attempt.ActualValue,
						},
					}
				}
			} else if !result.Matched {
				// Match failed: populate ClaimsFailed with attempt details
				if result.Attempt != nil {
					entry.ClaimsFailed = []audit.ClaimFailure{
						{
							Claim:   result.Attempt.Claim,
							Pattern: result.Attempt.Pattern,
							Value:   result.Attempt.ActualValue,
						},
					}
				}
			} else {
				// Successful match: populate ClaimsMatched
				// Always initialize as empty array (not nil) to distinguish "no rules" from "not processed"
				entry.ClaimsMatched = make([]audit.ClaimMatch, 0, len(result.Matches))
				for _, match := range result.Matches {
					entry.ClaimsMatched = append(entry.ClaimsMatched, audit.ClaimMatch{
						Claim: match.Claim,
						Value: match.Value,
					})
				}
			}
		}

		return token, err
	}
}
