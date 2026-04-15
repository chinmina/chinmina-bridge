//go:build fuzz

package vendor

import (
	"testing"

	"github.com/chinmina/chinmina-bridge/internal/profile"
)

func FuzzResolveRequestScope(f *testing.F) {
	// The three profile scope types that resolveRequestScope must handle:
	//   0 = caller-scoped, 1 = wildcard (all-repositories), 2 = specific (static list)
	// repositoryScope: the query parameter value (empty when absent)
	// requestedRepoURL: the git-credentials URL (empty for /token endpoint)

	// --- caller-scoped profile: scope parameter provided ---
	f.Add(0, "my-repo", "")
	f.Add(0, "repo-with-hyphens", "")
	f.Add(0, "UPPERCASE", "")
	f.Add(0, "repo123", "")

	// --- caller-scoped profile: scope derived from URL ---
	f.Add(0, "", "https://github.com/org/target-repo")
	f.Add(0, "", "https://github.com/org/target-repo.git")
	f.Add(0, "", "https://github.com/org/MIXED-Case-Repo")

	// --- caller-scoped profile: both present (scope wins) ---
	f.Add(0, "explicit-repo", "https://github.com/org/url-repo")

	// --- caller-scoped profile: neither present (error) ---
	f.Add(0, "", "")

	// --- wildcard profile ---
	f.Add(1, "", "")
	f.Add(1, "unwanted-scope", "")
	f.Add(1, "", "https://github.com/org/repo")

	// --- specific profile ---
	f.Add(2, "", "")
	f.Add(2, "unwanted-scope", "")
	f.Add(2, "", "https://github.com/org/repo")

	// --- adversarial scope values (passed extractRepositoryScope validation: no /, not empty) ---
	f.Add(0, "repo\x00name", "") // null byte
	f.Add(0, "repo\nname", "")   // newline
	f.Add(0, "repo\tname", "")   // tab
	f.Add(0, "<script>alert(1)</script>", "")
	f.Add(0, "repo; DROP TABLE repos", "")
	f.Add(0, "{{caller-scoped-repository}}", "")
	f.Add(0, "{{all-repositories}}", "")
	f.Add(0, "*", "")
	f.Add(0, "repo%00name", "") // percent-encoded null
	f.Add(0, "..", "")
	f.Add(0, ".", "")

	// --- adversarial URLs ---
	f.Add(0, "", "https://evil.com/org/repo")
	f.Add(0, "", "://malformed")
	f.Add(0, "", "not-a-url")
	f.Add(0, "", "https://github.com/")
	f.Add(0, "", "https://github.com")
	f.Add(0, "", "https://github.com/org/repo/extra/path")
	f.Add(0, "", "https://github.com/org/repo?query=1")
	f.Add(0, "", "file:///etc/passwd")

	f.Fuzz(func(t *testing.T, scopeType int, repositoryScope string, requestedRepoURL string) {
		// Select profile scope based on type.
		n := scopeType
		if n < 0 {
			n = -n
		}
		normalized := n % 3
		var profileScope profile.RepositoryScope
		switch normalized {
		case 0:
			profileScope = profile.NewCallerScopedScope()
		case 1:
			profileScope = profile.NewWildcardScope()
		case 2:
			profileScope = profile.NewSpecificScope("allowed-repo")
		}

		// Property 1: No panics
		result, err := resolveRequestScope(profileScope, repositoryScope, requestedRepoURL, "test-profile")

		// Property 2: Non-caller-scoped profiles must reject a repositoryScope
		if !profileScope.IsCallerScoped() && repositoryScope != "" {
			if err == nil {
				t.Errorf("expected error when scope %q provided to non-caller-scoped profile (type=%d)", repositoryScope, normalized)
			}
		}

		// Property 3: Caller-scoped profiles with no scope and no URL must error
		if profileScope.IsCallerScoped() && repositoryScope == "" && requestedRepoURL == "" {
			if err == nil {
				t.Error("expected error when caller-scoped profile has no scope and no URL")
			}
		}

		// Property 4: If resolution succeeds, the result must not be zero
		if err == nil {
			if result.IsZero() {
				t.Errorf("resolveRequestScope returned zero scope for inputs: scopeType=%d, repoScope=%q, url=%q", scopeType, repositoryScope, requestedRepoURL)
			}
		}

		// Property 5: Caller-scoped with explicit scope must produce a specific scope containing that name
		if profileScope.IsCallerScoped() && repositoryScope != "" && err == nil {
			if result.IsWildcard() || result.IsCallerScoped() {
				t.Errorf("caller-scoped with explicit scope should produce specific scope, got %+v", result)
			}
			if !result.Contains(repositoryScope) {
				t.Errorf("result scope should contain %q but doesn't: %+v", repositoryScope, result)
			}
		}

		// Property 6: Wildcard profile without scope must produce wildcard result
		if profileScope.IsWildcard() && repositoryScope == "" && err == nil {
			if !result.IsWildcard() {
				t.Errorf("wildcard profile without scope should produce wildcard result, got %+v", result)
			}
		}
	})
}
