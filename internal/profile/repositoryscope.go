package profile

import (
	"log/slog"
	"slices"
)

// RepositoryScope describes the set of repositories a token covers.
// Use NewWildcardScope for all-repositories access, NewSpecificScope for
// a named set, or NewCallerScopedScope for caller-provided repositories.
// The zero value represents no repositories and is not wildcard.
type RepositoryScope struct {
	// Wildcard indicates the token covers all repositories accessible to the
	// GitHub App installation. When true, Names is meaningless.
	Wildcard bool `json:"wildcard,omitempty"`
	// Names lists the specific repository names covered by the token.
	Names []string `json:"names,omitempty"`
	// CallerScoped indicates the repository will be supplied at request time
	// rather than being stored in the profile. When true, Names is meaningless.
	CallerScoped bool `json:"callerScoped,omitempty"`
}

// NewWildcardScope returns a RepositoryScope that covers all repositories.
func NewWildcardScope() RepositoryScope {
	return RepositoryScope{Wildcard: true}
}

// NewSpecificScope returns a RepositoryScope covering the given named repositories.
func NewSpecificScope(names ...string) RepositoryScope {
	if names == nil {
		names = []string{}
	}
	return RepositoryScope{Names: names}
}

// NewCallerScopedScope returns a RepositoryScope where the repository is supplied
// at request time rather than being stored in the profile.
func NewCallerScopedScope() RepositoryScope {
	return RepositoryScope{CallerScoped: true}
}

// IsWildcard reports whether this scope covers all repositories.
func (rs RepositoryScope) IsWildcard() bool {
	return rs.Wildcard
}

// IsEmpty reports whether this scope covers no repositories. The wildcard is
// not empty: it deliberately covers every repository in the installation, and
// carries no names because that is how GitHub is asked for it.
//
// A caller-scoped value is empty until it is resolved against the request. It
// is reported as empty rather than excused, because a caller-scoped scope that
// still names nothing at vend time has been narrowed to nothing, and sending
// it to GitHub would ask for the whole installation.
func (rs RepositoryScope) IsEmpty() bool {
	return !rs.Wildcard && len(rs.Names) == 0
}

// IsCallerScoped reports whether the repository is supplied at request time.
func (rs RepositoryScope) IsCallerScoped() bool {
	return rs.CallerScoped
}

// Contains reports whether the given repository name is covered by this scope.
// Wildcard scopes always return true. Caller-scoped scopes return false (no stored repositories).
func (rs RepositoryScope) Contains(repo string) bool {
	if rs.Wildcard {
		return true
	}
	if rs.CallerScoped {
		return false
	}
	return slices.Contains(rs.Names, repo)
}

// IsZero reports whether this scope is the zero value: empty, and without
// either explicit state that would explain why. A caller-scoped scope is
// empty but not zero — it declares that the request will supply the name.
func (rs RepositoryScope) IsZero() bool {
	return rs.IsEmpty() && !rs.CallerScoped
}

// NamesForDisplay returns a human-readable representation of the scope.
// Wildcard and caller-scoped values return their literal, keeping these states
// distinguishable from the zero value, which returns nil; specific scopes
// return their Names slice.
func (rs RepositoryScope) NamesForDisplay() []string {
	if rs.Wildcard {
		// the legacy "*" literal will be displayed using the new
		// LiteralAllRepositories constant, but we still want to preserve the old
		// literal for backwards compatibility
		return []string{LiteralAllRepositories}
	}
	if rs.CallerScoped {
		return []string{LiteralCallerScoped}
	}
	return rs.Names
}

// LogValue implements slog.LogValuer for structured logging.
func (rs RepositoryScope) LogValue() slog.Value {
	return slog.AnyValue(rs.NamesForDisplay())
}
