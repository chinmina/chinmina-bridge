package audit

import (
	"encoding/json"
	"log/slog"
	"time"
)

const (
	// SlogLevel is the slog level at which audit logs are written.
	// Level 20 is a custom level above Info, chosen to ensure audit events are always emitted.
	SlogLevel = slog.Level(20)

	// SlogLevelName is the human-readable label for SlogLevel.
	SlogLevelName = "AUDIT"
)

// LogValue implements slog.LogValuer for ClaimMatch, emitting a flat group with
// claim and value keys.
func (cm ClaimMatch) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("claim", cm.Claim),
		slog.String("value", cm.Value),
	)
}

// LogValue implements slog.LogValuer for ClaimFailure, emitting a flat group
// with claim, pattern, and value keys.
func (cf ClaimFailure) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("claim", cf.Claim),
		slog.String("pattern", cf.Pattern),
		slog.String("value", cf.Value),
	)
}

// slogMatchSlice wraps []ClaimMatch for JSON serialization via slog.Any.
// It produces an array of objects with "claim" and "value" keys.
type slogMatchSlice []ClaimMatch

func (s slogMatchSlice) MarshalJSON() ([]byte, error) {
	type item struct {
		Claim string `json:"claim"`
		Value string `json:"value"`
	}
	items := make([]item, len(s))
	for i, m := range s {
		items[i] = item(m)
	}
	return json.Marshal(items)
}

// slogFailureSlice wraps []ClaimFailure for JSON serialization via slog.Any.
// It produces an array of objects with "claim", "pattern", and "value" keys.
type slogFailureSlice []ClaimFailure

func (s slogFailureSlice) MarshalJSON() ([]byte, error) {
	type item struct {
		Claim   string `json:"claim"`
		Pattern string `json:"pattern"`
		Value   string `json:"value"`
	}
	items := make([]item, len(s))
	for i, f := range s {
		items[i] = item(f)
	}
	return json.Marshal(items)
}

// SlogAttrs returns the audit entry as a flat slice of slog.Attr for emission
// via slog.LogAttrs. This is the slog equivalent of MarshalZerologObject.
//
// Optional groups (pipeline, token) are elided when all their fields are
// zero/empty. The authorization group always appears because it includes the
// bool authorized field.
//
//nolint:gocyclo // marshaling function with many conditional fields
func (e *Entry) SlogAttrs() []slog.Attr {
	attrs := make([]slog.Attr, 0, 5)

	// request group — always present, all fields included regardless of value
	attrs = append(attrs, slog.Group("request",
		slog.String("method", e.Method),
		slog.String("path", e.Path),
		slog.Int("status", e.Status),
		slog.String("sourceIP", e.SourceIP),
		slog.String("userAgent", e.UserAgent),
	))

	// pipeline group — elided when all fields are zero/empty
	pipeline := NewOptionalGroup()
	pipeline.
		Str("pipelineSlug", e.PipelineSlug).
		Str("organizationSlug", e.OrganizationSlug).
		Str("jobID", e.JobID).
		Int("buildNumber", e.BuildNumber).
		Str("buildBranch", e.BuildBranch)
	if a, hasAttrs := pipeline.Group("pipeline"); hasAttrs {
		attrs = append(attrs, a)
	}

	// authorization group — always present because Bool("authorized") is always added
	now := time.Now()
	authDetails := NewOptionalGroup()
	authDetails.
		Bool("authorized", e.Authorized).
		Str("subject", e.AuthSubject).
		Str("issuer", e.AuthIssuer).
		Strs("audience", e.AuthAudience)

	if e.AuthExpirySecs > 0 {
		exp := time.Unix(e.AuthExpirySecs, 0).UTC()
		remaining := exp.Sub(now).Round(time.Millisecond)
		authDetails.Attr(slog.Time("expiry", exp))
		authDetails.Attr(slog.Duration("expiryRemaining", remaining))
	}
	if a, hasAttrs := authDetails.Group("authorization"); hasAttrs {
		attrs = append(attrs, a)
	}

	// token group — elided when all fields are zero/empty
	tokenDetails := NewOptionalGroup()
	tokenDetails.
		Str("requestedProfile", e.RequestedProfile).
		Str("requestedRepository", e.RequestedRepository).
		Str("vendedRepository", e.VendedRepository).
		Str("hashedToken", e.HashedToken).
		Strs("repositories", e.Repositories).
		Strs("permissions", e.Permissions)

	// nil slice → skip; non-nil (even empty) → include
	if e.ClaimsMatched != nil {
		tokenDetails.Attr(slog.Any("matches", slogMatchSlice(e.ClaimsMatched)))
	}
	if e.ClaimsFailed != nil {
		tokenDetails.Attr(slog.Any("attemptedPatterns", slogFailureSlice(e.ClaimsFailed)))
	}
	if e.ExpirySecs > 0 {
		exp := time.Unix(e.ExpirySecs, 0).UTC()
		remaining := exp.Sub(now).Round(time.Millisecond)
		tokenDetails.Attr(slog.Time("expiry", exp))
		tokenDetails.Attr(slog.Duration("expiryRemaining", remaining))
	}
	if a, hasAttrs := tokenDetails.Group("token"); hasAttrs {
		attrs = append(attrs, a)
	}

	if e.Error != "" {
		attrs = append(attrs, slog.String("error", e.Error))
	}

	return attrs
}
