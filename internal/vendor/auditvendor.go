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
	return func(ctx context.Context, ref profile.ProfileRef, repo string) VendorResult {
		entry := audit.Log(ctx)
		entry.RequestedProfile = ref.String()
		entry.RequestedRepository = repo

		result := vendor(ctx, ref, repo)

		if err, failed := result.Failed(); failed {
			entry.Error = fmt.Sprintf("vendor failure: %v", err)
		} else if token, tokenVended := result.Token(); tokenVended {
			entry.VendedRepository = token.VendedRepositoryURL
			entry.Repositories = token.Repositories
			entry.Permissions = token.Permissions
			entry.ExpirySecs = token.Expiry.Unix()
		} else {
			// this is a successful no-result: it's not an error, but we don't have credentials for the request
			// this happens on a repository mismatch, or on a profile request where the requested repo doesn't match.
			entry.Error = "skipped(success): profile has no credentials for requested repository"
		}

		return result
	}
}

// AuditingMatcher wraps a profile.Matcher to record the results of profile
// matching to the audit log in a single place.
func AuditingMatcher(ctx context.Context, wrapped profile.Matcher) profile.Matcher {
	return func(claims profile.ClaimValueLookup) profile.MatchResult {

		result := wrapped(claims)

		entry := audit.Log(ctx)

		if result.Err != nil || !result.Matched {
			// Validation error: populate ClaimsFailed if attempt details available
			// Match failed: populate ClaimsFailed with attempt details
			entry.ClaimsFailed = asAuditAttempts(result.Attempt)
		} else if result.Matched {
			// Successful match: populate ClaimsMatched
			// Always initialize as empty array (not nil) to distinguish "no rules" from "not processed"
			entry.ClaimsMatched = asAuditClaimMatches(result.Matches)
		}

		return result
	}
}

func asAuditAttempts(attempt *profile.MatchAttempt) []audit.ClaimFailure {
	if attempt == nil {
		return nil
	}

	return []audit.ClaimFailure{
		{
			Claim:   attempt.Claim,
			Pattern: attempt.Pattern,
			Value:   attempt.ActualValue,
		},
	}
}

func asAuditClaimMatches(matches []profile.ClaimMatch) []audit.ClaimMatch {
	// Always initialize as empty array (not nil) to distinguish "no rules" from "not processed"
	auditMatches := make([]audit.ClaimMatch, 0, len(matches))
	for _, match := range matches {
		auditMatches = append(auditMatches, audit.ClaimMatch{
			Claim: match.Claim,
			Value: match.Value,
		})
	}
	return auditMatches
}
