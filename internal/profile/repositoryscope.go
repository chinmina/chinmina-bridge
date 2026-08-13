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

// IsUnresolved reports whether this scope resolved to nothing that can be
// asked for. A wildcard is resolved — it covers every repository in the
// installation, and carries no names because that is how GitHub is asked for
// it. A named set is resolved once it holds a name.
//
// A caller-scoped value is unresolved until narrowed against the request, and
// is reported as such rather than excused: one that still names nothing at
// vend time was narrowed to nothing, and GitHub reads a request carrying no
// repositories as a request for all of them.
func (rs RepositoryScope) IsUnresolved() bool {
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

// IsAbsent reports whether no scope was declared at all: the zero value, which
// is neither of the two explicit forms nor a named set. Distinct from
// IsUnresolved, which a caller-scoped value also satisfies until the request
// narrows it — that value declares where its repository will come from,
// whereas this one declares nothing.
func (rs RepositoryScope) IsAbsent() bool {
	return rs.IsUnresolved() && !rs.CallerScoped
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
