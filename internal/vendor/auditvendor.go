package vendor

import (
	"context"
	"fmt"

	"github.com/chinmina/chinmina-bridge/internal/audit"
	"github.com/chinmina/chinmina-bridge/internal/profile"
)

// Auditor wraps a ProfileTokenVendor and records the outcome of vending to the
// audit log. The request's intent — the requested profile and repository — is
// stamped at the handler boundary instead, so it survives failures that occur
// before the chain is reached; Auditor records only what the chain produced.
func Auditor[T any](vendor ProfileTokenVendor[T]) ProfileTokenVendor[T] {
	return func(ctx context.Context, r Resolved[T], repo string) VendorResult {
		entry := audit.Log(ctx)

		result := vendor(ctx, r, repo)

		switch result.Status() {
		case VendStatusFailed:
			entry.Error = fmt.Sprintf("vendor failure: %v", result.Err())
		case VendStatusSuccess:
			token := result.Token()
			entry.VendedRepository = token.VendedRepositoryURL
			entry.Repositories = token.Repositories.NamesForDisplay()
			entry.Permissions = token.Permissions
			entry.ExpirySecs = token.Expiry.Unix()
			entry.HashedToken = token.HashedToken
		case VendStatusSuccessUnmatched:
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
