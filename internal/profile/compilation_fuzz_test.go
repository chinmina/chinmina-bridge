//go:build fuzz

package profile

import (
	"testing"
)

func FuzzValidateRepositories(f *testing.F) {
	// --- single-entry seeds ---
	f.Add(1, "*")                            // deprecated wildcard
	f.Add(1, "{{all-repositories}}")         // new wildcard literal
	f.Add(1, "{{caller-scoped-repository}}") // caller-scoped literal
	f.Add(1, "repo-name")                    // plain repo name
	f.Add(1, "owner/repo")                   // slash → rejected
	f.Add(1, "")                             // empty string
	f.Add(1, " ")                            // whitespace only
	f.Add(1, "{{unknown-literal}}")          // looks like a literal but isn't
	f.Add(1, "repo\x00name")                 // null byte
	f.Add(1, "repo\nname")                   // newline
	f.Add(1, "{{")                           // partial literal
	f.Add(1, "}}")                           // partial literal close
	f.Add(1, "{{caller-scoped-repository")   // unclosed literal
	f.Add(1, "a/b/c")                        // multiple slashes
	f.Add(1, "/")                            // bare slash
	f.Add(1, ".")                            // dot
	f.Add(1, "..")                           // double dot
	f.Add(1, "-")                            // hyphen only

	// --- multi-entry seeds (count=2) ---
	f.Add(2, "repo-a")                       // two plain repos
	f.Add(2, "*")                            // wildcard with second entry
	f.Add(2, "{{caller-scoped-repository}}") // literal with second entry
	f.Add(2, "{{all-repositories}}")         // literal with second entry

	f.Fuzz(func(t *testing.T, count int, entry string) {
		// Clamp count to a reasonable range
		if count < 1 {
			count = 1
		}
		if count > 5 {
			count = 5
		}

		// Build a repos list by repeating the entry
		repos := make([]string, count)
		for i := range repos {
			repos[i] = entry
		}

		// Property 1: No panics
		err := validateRepositories(repos)

		// Property 2: If a special literal is present with other entries, it must be rejected
		isSpecial := entry == "*" || entry == LiteralCallerScoped || entry == LiteralAllRepositories
		if isSpecial && count > 1 && err == nil {
			t.Errorf("special literal %q with %d entries should be rejected but wasn't", entry, count)
		}

		// Property 3: If validation passes, resolveRepositoryScope must not produce a zero scope
		if err == nil && count > 0 {
			scope := resolveRepositoryScope(repos)
			if scope.IsZero() {
				t.Errorf("resolveRepositoryScope returned zero scope for valid input %v", repos)
			}
		}

		// Property 4: Slash in repo name must be rejected
		if count == 1 && !isSpecial && len(entry) > 0 {
			for _, ch := range entry {
				if ch == '/' {
					if err == nil {
						t.Errorf("entry containing '/' should be rejected: %q", entry)
					}
					break
				}
			}
		}

		// Property 5: validateRepositories + resolveRepositoryScope consistency.
		// If validation passes with a single special literal, resolve must
		// return the matching scope type.
		if err == nil && count == 1 {
			scope := resolveRepositoryScope(repos)
			switch entry {
			case LiteralCallerScoped:
				if !scope.IsCallerScoped() {
					t.Errorf("expected caller-scoped scope for %q, got %+v", entry, scope)
				}
			case LiteralAllRepositories, "*":
				if !scope.IsWildcard() {
					t.Errorf("expected wildcard scope for %q, got %+v", entry, scope)
				}
			default:
				if scope.IsWildcard() || scope.IsCallerScoped() {
					t.Errorf("expected specific scope for %q, got %+v", entry, scope)
				}
			}
		}
	})
}
