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

// IsZero reports whether this scope is the zero value (no repositories, not wildcard, not caller-scoped).
func (rs RepositoryScope) IsZero() bool {
	return !rs.Wildcard && !rs.CallerScoped && len(rs.Names) == 0
}

// NamesForDisplay returns a human-readable representation of the scope.
// Wildcard scopes return ["*"]; caller-scoped returns empty slice; specific scopes return their Names slice.
func (rs RepositoryScope) NamesForDisplay() []string {
	if rs.Wildcard {
		return []string{"*"}
	}
	if rs.CallerScoped {
		return []string{}
	}
	return rs.Names
}

// LogValue implements slog.LogValuer for structured logging.
func (rs RepositoryScope) LogValue() slog.Value {
	return slog.AnyValue(rs.NamesForDisplay())
}
