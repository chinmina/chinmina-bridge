# Dynamic Repository Scoping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend organization profiles to support caller-scoped repository tokens and an explicit `{{all-repositories}}` literal, replacing the terse `*` wildcard with deprecation.

**Architecture:** The `RepositoryScope` type gains a third state (caller-scoped). Profile compilation resolves the new YAML literals at load time. The org vendor accepts a `repositoryScope` parameter from the handler, validates bidirectional scoping rules, and issues narrowed tokens. The cache key includes the repository name for caller-scoped profiles.

**Tech Stack:** Go 1.26, testify, slog, alice middleware, github.com/google/go-github

**Spec:** `docs/superpowers/specs/2026-04-15-dynamic-repository-scoping-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `internal/profile/repositoryscope.go` | Add `CallerScoped` state to `RepositoryScope` |
| Modify | `internal/profile/repositoryscope_test.go` | Tests for the new state |
| Modify | `internal/profile/profiles.go` | Change `OrganizationProfileAttr` to store compiled `RepositoryScope` |
| Modify | `internal/profile/profiles_test.go` | Tests for updated attr |
| Modify | `internal/profile/compilation.go` | Recognise new literals, deprecation warning, compile-time resolution |
| Modify | `internal/profile/compilation_test.go` | Compilation tests for new literals |
| Modify | `internal/profile/config.go` | New error types for scoping mismatches |
| Modify | `internal/vendor/orgvendor.go` | Accept `repositoryScope` parameter, bidirectional validation |
| Modify | `internal/vendor/orgvendor_test.go` | Tests for scoping validation and token narrowing |
| Modify | `internal/vendor/cached.go` | Include repository name in cache key for caller-scoped profiles |
| Modify | `internal/vendor/cached_test.go` | Cache key tests for scoped profiles |
| Modify | `internal/vendor/vendor.go` | Add `RepositoryScope` field to `ProfileTokenVendor` signature |
| Modify | `internal/vendor/auditvendor.go` | Audit scoping mismatch rejections |
| Modify | `handlers.go` | Extract `repository-scope` query parameter, input validation |
| Modify | `handlers_test.go` | Handler tests for parameter extraction and validation |
| Modify | `main.go` | No structural changes expected (vendor composition unchanged) |
| Modify | `internal/profile/profiletest/testdata/profiles.yaml` | Add test profiles with new literals |

---

## Task 1: Extend RepositoryScope with CallerScoped state

**Spec refs:** Req 1.9, 1.10

**Files:**
- Modify: `internal/profile/repositoryscope.go`
- Modify: `internal/profile/repositoryscope_test.go`

- [ ] **Step 1: Write failing tests for the new CallerScoped state**

Add these test cases to `internal/profile/repositoryscope_test.go`:

```go
func TestNewCallerScopedScope(t *testing.T) {
	rs := NewCallerScopedScope()
	assert.False(t, rs.Wildcard)
	assert.Nil(t, rs.Names)
	assert.True(t, rs.CallerScoped)
}
```

Add to the existing `TestRepositoryScope_IsWildcard` table:
```go
{"caller-scoped scope", NewCallerScopedScope(), false},
```

Add a new table-driven test:
```go
func TestRepositoryScope_IsCallerScoped(t *testing.T) {
	tests := []struct {
		name     string
		scope    RepositoryScope
		expected bool
	}{
		{"caller-scoped scope", NewCallerScopedScope(), true},
		{"wildcard scope", NewWildcardScope(), false},
		{"specific scope", NewSpecificScope("repo-a"), false},
		{"zero value", RepositoryScope{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.scope.IsCallerScoped())
		})
	}
}
```

Add to existing `TestRepositoryScope_Contains` table:
```go
{"caller-scoped matches nothing", NewCallerScopedScope(), "any-repo", false},
```

Add to existing `TestRepositoryScope_IsZero` table:
```go
{"caller-scoped scope", NewCallerScopedScope(), false},
```

Add to existing `TestRepositoryScope_NamesForDisplay` table:
```go
{"caller-scoped returns empty", NewCallerScopedScope(), []string{}},
```

Add to existing `TestRepositoryScope_JSONRoundTrip` table:
```go
{
	name:         "caller-scoped",
	scope:        NewCallerScopedScope(),
	expectedJSON: `{"callerScoped":true}`,
},
```

Add to existing `TestRepositoryScope_LogValue` table:
```go
{
	name:     "caller-scoped logs empty",
	scope:    NewCallerScopedScope(),
	expected: slog.AnyValue([]string{}),
},
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/profile/ -run "TestNewCallerScopedScope|TestRepositoryScope_IsCallerScoped" -v`
Expected: FAIL — `NewCallerScopedScope` and `IsCallerScoped` not defined

- [ ] **Step 3: Implement CallerScoped state in RepositoryScope**

In `internal/profile/repositoryscope.go`, add the `CallerScoped` field to the struct and implement the new constructor and method:

```go
type RepositoryScope struct {
	// Wildcard indicates the token covers all repositories accessible to the
	// GitHub App installation. When true, Names is meaningless.
	Wildcard bool `json:"wildcard,omitempty"`
	// CallerScoped indicates the repository will be supplied at request time.
	// When true, Names is meaningless and Wildcard must be false.
	CallerScoped bool `json:"callerScoped,omitempty"`
	// Names lists the specific repository names covered by the token.
	Names []string `json:"names,omitempty"`
}
```

Add the constructor:
```go
// NewCallerScopedScope returns a RepositoryScope where the caller supplies
// the repository at request time.
func NewCallerScopedScope() RepositoryScope {
	return RepositoryScope{CallerScoped: true}
}
```

Add the method:
```go
// IsCallerScoped reports whether this scope requires the caller to supply
// a repository at request time.
func (rs RepositoryScope) IsCallerScoped() bool {
	return rs.CallerScoped
}
```

Update `Contains` to return false for caller-scoped (it has no repositories by definition):
```go
func (rs RepositoryScope) Contains(repo string) bool {
	if rs.Wildcard {
		return true
	}
	if rs.CallerScoped {
		return false
	}
	return slices.Contains(rs.Names, repo)
}
```

Update `IsZero` to exclude caller-scoped:
```go
func (rs RepositoryScope) IsZero() bool {
	return !rs.Wildcard && !rs.CallerScoped && len(rs.Names) == 0
}
```

Update `NamesForDisplay` for caller-scoped:
```go
func (rs RepositoryScope) NamesForDisplay() []string {
	if rs.Wildcard {
		return []string{"*"}
	}
	if rs.CallerScoped {
		return []string{}
	}
	return rs.Names
}
```

- [ ] **Step 4: Run all RepositoryScope tests to verify they pass**

Run: `go test ./internal/profile/ -run "TestRepositoryScope|TestNewWildcardScope|TestNewSpecificScope|TestNewCallerScopedScope" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/profile/repositoryscope.go internal/profile/repositoryscope_test.go
git commit -m "$(cat <<'EOF'
feat: extend RepositoryScope with CallerScoped state

Add a third state to RepositoryScope for caller-supplied repository
scoping. This is the domain model for the {{caller-scoped-repository}}
literal: the repository name is not stored in the profile but supplied
at request time.

CallerScoped is distinct from both Wildcard (all repos) and specific
Names: it represents a deferred scope that must be resolved per-request.
EOF
)"
```

---

## Task 2: Update OrganizationProfileAttr to store compiled RepositoryScope

**Spec refs:** Req 1.8

**Files:**
- Modify: `internal/profile/profiles.go`
- Modify: `internal/profile/profiles_test.go`

- [ ] **Step 1: Write failing tests for the new Scope field**

In `internal/profile/profiles_test.go`, add tests that verify `OrganizationProfileAttr` has a `Scope` field and `RepositoryScope()` returns it:

```go
func TestOrganizationProfileAttr_RepositoryScope_UsesCompiledScope(t *testing.T) {
	tests := []struct {
		name     string
		attr     OrganizationProfileAttr
		expected RepositoryScope
	}{
		{
			name: "wildcard scope",
			attr: OrganizationProfileAttr{
				Scope: NewWildcardScope(),
			},
			expected: NewWildcardScope(),
		},
		{
			name: "specific scope",
			attr: OrganizationProfileAttr{
				Scope: NewSpecificScope("repo-a", "repo-b"),
			},
			expected: NewSpecificScope("repo-a", "repo-b"),
		},
		{
			name: "caller-scoped",
			attr: OrganizationProfileAttr{
				Scope: NewCallerScopedScope(),
			},
			expected: NewCallerScopedScope(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.attr.RepositoryScope())
		})
	}
}
```

```go
func TestOrganizationProfileAttr_HasRepository(t *testing.T) {
	tests := []struct {
		name     string
		attr     OrganizationProfileAttr
		repo     string
		expected bool
	}{
		{
			name: "wildcard matches any repo",
			attr: OrganizationProfileAttr{Scope: NewWildcardScope()},
			repo: "any-repo",
			expected: true,
		},
		{
			name: "specific scope matches member",
			attr: OrganizationProfileAttr{Scope: NewSpecificScope("repo-a")},
			repo: "repo-a",
			expected: true,
		},
		{
			name: "specific scope rejects non-member",
			attr: OrganizationProfileAttr{Scope: NewSpecificScope("repo-a")},
			repo: "repo-b",
			expected: false,
		},
		{
			name: "caller-scoped matches nothing directly",
			attr: OrganizationProfileAttr{Scope: NewCallerScopedScope()},
			repo: "any-repo",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.attr.HasRepository(tt.repo))
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/profile/ -run "TestOrganizationProfileAttr_RepositoryScope_UsesCompiledScope|TestOrganizationProfileAttr_HasRepository" -v`
Expected: FAIL — `Scope` field not defined on `OrganizationProfileAttr`

- [ ] **Step 3: Refactor OrganizationProfileAttr to use compiled Scope**

In `internal/profile/profiles.go`, replace the `Repositories []string` field with `Scope RepositoryScope`:

```go
type OrganizationProfileAttr struct {
	Scope       RepositoryScope
	Permissions []string
}
```

Update `HasRepository` to delegate to `Scope`:
```go
func (attr OrganizationProfileAttr) HasRepository(repo string) bool {
	return attr.Scope.Contains(repo)
}
```

Update `RepositoryScope()` to return the stored scope directly:
```go
func (attr OrganizationProfileAttr) RepositoryScope() RepositoryScope {
	return attr.Scope
}
```

Remove the now-unused `allowAllRepositories()` method entirely.

- [ ] **Step 4: Update compilation.go to populate the Scope field**

In `internal/profile/compilation.go`, update `compileOrganizationProfiles` where it builds `OrganizationProfileAttr` (around line 84):

```go
		scope := resolveRepositoryScope(p.Repositories)

		attrs := OrganizationProfileAttr{
			Scope:       scope,
			Permissions: ensureMetadataRead(p.Permissions),
		}
```

Add the `resolveRepositoryScope` function:

```go
// resolveRepositoryScope converts a raw repositories list into a typed RepositoryScope.
// This is called after validation, so the input is known to be well-formed.
func resolveRepositoryScope(repos []string) RepositoryScope {
	if len(repos) == 1 && repos[0] == "*" {
		return NewWildcardScope()
	}
	return NewSpecificScope(repos...)
}
```

- [ ] **Step 5: Fix all compilation and downstream tests**

The existing tests that check `Attrs.Repositories` (a `[]string`) must now check `Attrs.Scope` (a `RepositoryScope`). Update all occurrences in:

In `internal/profile/compilation_test.go`, replace field checks like:
```go
// Old:
assert.Equal(t, []string{"silk"}, validProfile.Attrs.Repositories)
// New:
assert.Equal(t, NewSpecificScope("silk"), validProfile.Attrs.Scope)
```

Do the same for all other `Attrs.Repositories` references in the file:
- `TestCompile_GracefulDegradation`: `"silk"` → `NewSpecificScope("silk")`, `"silk", "cotton"` → `NewSpecificScope("silk", "cotton")`, `"shared"` → `NewSpecificScope("shared")`
- `TestCompile_OrganizationProfile_InvalidRepositories`: `[]string{"*"}` → `NewWildcardScope()`, `[]string{"repo1", "repo2"}` → `NewSpecificScope("repo1", "repo2")`

In `internal/vendor/orgvendor_test.go`, the `assertVendorSuccess` calls reference `profile.NewSpecificScope("secret-repo", "another-secret-repo")` in the expected `ProfileToken.Repositories` field — these remain correct since `RepositoryScope()` now returns the `Scope` field directly.

In `internal/profile/profiletest/testdata/profiles.yaml`, existing profiles use `["repo-1", "repo-2"]` syntax — no change needed, compilation now stores these as `NewSpecificScope(...)`.

- [ ] **Step 6: Run all tests to verify the refactor is clean**

Run: `go test ./internal/profile/... ./internal/vendor/... -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/profile/profiles.go internal/profile/profiles_test.go internal/profile/compilation.go internal/profile/compilation_test.go
git commit -m "$(cat <<'EOF'
refactor: store compiled RepositoryScope in OrganizationProfileAttr

Replace the raw Repositories []string field with a typed Scope field
resolved at compile time. This eliminates repeated runtime interpretation
of the wildcard marker and prepares the type for the caller-scoped state.

The RepositoryScope() method now returns the stored value directly instead
of re-deriving it on each call.
EOF
)"
```

---

## Task 3: Profile compilation — recognise new literals and deprecation

**Spec refs:** Req 1.1–1.7, 1.8, 13.1

**Files:**
- Modify: `internal/profile/compilation.go`
- Modify: `internal/profile/compilation_test.go`
- Modify: `internal/profile/profiletest/testdata/profiles.yaml`

- [ ] **Step 1: Write failing tests for new literal acceptance**

Add to `internal/profile/compilation_test.go`:

```go
func TestCompile_OrganizationProfile_CallerScopedRepository(t *testing.T) {
	yamlContent := `
organization:
  profiles:
    - name: scoped-profile
      repositories:
        - "{{caller-scoped-repository}}"
      permissions:
        - "contents:write"
      match:
        - claim: pipeline_slug
          value: agent-workflows

pipeline:
  defaults:
    permissions:
      - "contents:read"
`
	config, digest, err := parse(yamlContent)
	require.NoError(t, err)

	profiles, err := compile(config, digest, "local")
	require.NoError(t, err)

	p, err := profiles.GetOrgProfile("scoped-profile")
	require.NoError(t, err)
	assert.Equal(t, NewCallerScopedScope(), p.Attrs.Scope)
}

func TestCompile_OrganizationProfile_AllRepositories(t *testing.T) {
	yamlContent := `
organization:
  profiles:
    - name: all-repos-profile
      repositories:
        - "{{all-repositories}}"
      permissions:
        - "contents:read"

pipeline:
  defaults:
    permissions:
      - "contents:read"
`
	config, digest, err := parse(yamlContent)
	require.NoError(t, err)

	profiles, err := compile(config, digest, "local")
	require.NoError(t, err)

	p, err := profiles.GetOrgProfile("all-repos-profile")
	require.NoError(t, err)
	assert.Equal(t, NewWildcardScope(), p.Attrs.Scope)
}
```

- [ ] **Step 2: Write failing tests for mixed-entry rejection**

```go
func TestCompile_OrganizationProfile_LiteralsMustBeAlone(t *testing.T) {
	tests := []struct {
		name         string
		repositories string
		profileName  string
	}{
		{
			name:         "caller-scoped mixed with static",
			repositories: `["{{caller-scoped-repository}}", "repo-a"]`,
			profileName:  "mixed-caller-scoped",
		},
		{
			name:         "all-repositories mixed with static",
			repositories: `["{{all-repositories}}", "repo-a"]`,
			profileName:  "mixed-all-repos",
		},
		{
			name:         "caller-scoped mixed with all-repositories",
			repositories: `["{{caller-scoped-repository}}", "{{all-repositories}}"]`,
			profileName:  "mixed-both-literals",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlContent := fmt.Sprintf(`
organization:
  profiles:
    - name: %s
      repositories: %s
      permissions:
        - "contents:read"
      match:
        - claim: pipeline_slug
          value: test

pipeline:
  defaults:
    permissions:
      - "contents:read"
`, tt.profileName, tt.repositories)

			config, digest, err := parse(yamlContent)
			require.NoError(t, err)

			profiles, err := compile(config, digest, "local")
			require.NoError(t, err)

			_, err = profiles.GetOrgProfile(tt.profileName)
			require.Error(t, err)
			var unavailErr ProfileUnavailableError
			require.ErrorAs(t, err, &unavailErr)
		})
	}
}
```

- [ ] **Step 3: Write failing test for `*` deprecation warning**

```go
func TestCompile_OrganizationProfile_WildcardDeprecationWarning(t *testing.T) {
	yamlContent := `
organization:
  profiles:
    - name: old-wildcard
      repositories:
        - "*"
      permissions:
        - "contents:read"

pipeline:
  defaults:
    permissions:
      - "contents:read"
`
	config, digest, err := parse(yamlContent)
	require.NoError(t, err)

	profiles, err := compile(config, digest, "local")
	require.NoError(t, err)

	// Profile should still compile successfully as an alias for {{all-repositories}}
	p, err := profiles.GetOrgProfile("old-wildcard")
	require.NoError(t, err)
	assert.Equal(t, NewWildcardScope(), p.Attrs.Scope)

	// The deprecation warning is emitted via slog.Warn during compilation.
	// Verifying exact log output is fragile; the key assertion is that '*'
	// compiles to the same wildcard scope as '{{all-repositories}}'.
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./internal/profile/ -run "TestCompile_OrganizationProfile_CallerScopedRepository|TestCompile_OrganizationProfile_AllRepositories|TestCompile_OrganizationProfile_LiteralsMustBeAlone|TestCompile_OrganizationProfile_WildcardDeprecationWarning" -v`
Expected: FAIL — new literals not recognised by `validateRepositories`

- [ ] **Step 5: Implement literal recognition in compilation**

Add constants in `internal/profile/compilation.go`:

```go
const (
	// LiteralCallerScoped is the YAML literal for caller-supplied repository scoping.
	LiteralCallerScoped = "{{caller-scoped-repository}}"
	// LiteralAllRepositories is the YAML literal for all-repositories access.
	LiteralAllRepositories = "{{all-repositories}}"
)
```

Replace `validateRepositories` with a version that recognises the new literals:

```go
func validateRepositories(repos []string) error {
	if len(repos) == 0 {
		return fmt.Errorf("repositories list must be non-empty")
	}

	// Check for special literals that must be alone
	for _, repo := range repos {
		switch repo {
		case LiteralCallerScoped, LiteralAllRepositories, "*":
			if len(repos) > 1 {
				return fmt.Errorf("%q must be the only repository entry", repo)
			}
			return nil
		}
	}

	// Check for owner prefix (slash in repo name)
	for _, repo := range repos {
		if strings.Contains(repo, "/") {
			return fmt.Errorf("repository %q must not contain owner prefix", repo)
		}
	}
	return nil
}
```

Update `resolveRepositoryScope` to handle all cases:

```go
func resolveRepositoryScope(repos []string) RepositoryScope {
	if len(repos) == 1 {
		switch repos[0] {
		case LiteralCallerScoped:
			return NewCallerScopedScope()
		case LiteralAllRepositories, "*":
			return NewWildcardScope()
		}
	}
	return NewSpecificScope(repos...)
}
```

Add deprecation warning emission in `compileOrganizationProfiles`, after the validation loop where valid profiles are built (around line 77). Add this inside the loop where attrs are constructed:

```go
		// Emit deprecation warning for '*' wildcard
		if len(p.Repositories) == 1 && p.Repositories[0] == "*" {
			slog.Warn("organization profile: '*' is deprecated, use '{{all-repositories}}' instead",
				"profile", p.Name,
			)
		}
```

Also remove the redundant empty-repositories check from `compileOrganizationProfiles` (lines 29-33) since `validateRepositories` now handles it.

- [ ] **Step 6: Run all compilation tests**

Run: `go test ./internal/profile/ -v`
Expected: PASS

- [ ] **Step 7: Add new literal profiles to shared test data**

Add to `internal/profile/profiletest/testdata/profiles.yaml`:

```yaml
    - name: caller-scoped-profile
      repositories:
        - "{{caller-scoped-repository}}"
      permissions:
        - contents:write
      match:
        - claim: pipeline_slug
          valuePattern: "agent-workflows.*"
    - name: all-repos-profile
      repositories:
        - "{{all-repositories}}"
      permissions:
        - contents:read
```

- [ ] **Step 8: Run full test suite**

Run: `go test ./... -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/profile/compilation.go internal/profile/compilation_test.go internal/profile/profiletest/testdata/profiles.yaml
git commit -m "$(cat <<'EOF'
feat: recognise {{caller-scoped-repository}} and {{all-repositories}} in profiles

The profile compiler now accepts two new YAML literals:
- {{caller-scoped-repository}}: resolved to CallerScoped scope
- {{all-repositories}}: resolved to Wildcard scope

Both must be the sole entry in the repositories list. The existing '*'
wildcard is preserved as a deprecated alias for {{all-repositories}}
with a warning emitted at compile time.
EOF
)"
```

---

## Task 4: Handler — extract and validate `repository-scope` query parameter

**Spec refs:** Req 6.1–6.3

**Files:**
- Modify: `handlers.go`
- Modify: `handlers_test.go`

- [ ] **Step 1: Write failing tests for parameter extraction and validation**

Add to `handlers_test.go`:

```go
func TestExtractRepositoryScope_Valid(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected string
	}{
		{"simple name", "repository-scope=my-repo", "my-repo"},
		{"hyphenated name", "repository-scope=my-cool-repo", "my-cool-repo"},
		{"mixed case", "repository-scope=MyRepo", "MyRepo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/organization/token/test?"+tt.query, nil)
			require.NoError(t, err)
			scope, err := extractRepositoryScope(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, scope)
		})
	}
}

func TestExtractRepositoryScope_Absent(t *testing.T) {
	req, err := http.NewRequest("POST", "/organization/token/test", nil)
	require.NoError(t, err)
	scope, err := extractRepositoryScope(req)
	require.NoError(t, err)
	assert.Equal(t, "", scope)
}

func TestExtractRepositoryScope_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"contains slash", "repository-scope=owner/repo"},
		{"empty value", "repository-scope="},
		{"whitespace only", "repository-scope=%20%20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/organization/token/test?"+tt.query, nil)
			require.NoError(t, err)
			_, err = extractRepositoryScope(req)
			require.Error(t, err)
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test . -run "TestExtractRepositoryScope" -v`
Expected: FAIL — `extractRepositoryScope` not defined

- [ ] **Step 3: Implement extractRepositoryScope**

Add to `handlers.go`:

```go
// extractRepositoryScope extracts and validates the repository-scope query parameter.
// Returns empty string if the parameter is absent.
// Returns an error if the parameter is present but invalid (empty, whitespace-only, or contains '/').
func extractRepositoryScope(r *http.Request) (string, error) {
	if !r.URL.Query().Has("repository-scope") {
		return "", nil
	}

	scope := r.URL.Query().Get("repository-scope")
	if strings.TrimSpace(scope) == "" {
		return "", fmt.Errorf("repository-scope must not be empty")
	}
	if strings.Contains(scope, "/") {
		return "", fmt.Errorf("repository-scope must not contain '/'")
	}
	return scope, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test . -run "TestExtractRepositoryScope" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add handlers.go handlers_test.go
git commit -m "$(cat <<'EOF'
feat: extract and validate repository-scope query parameter

Add extractRepositoryScope() to parse the repository-scope query
parameter from organization token requests. Rejects empty values,
whitespace-only values, and values containing '/' (no owner prefix).
The value is passed through without case normalization per spec.
EOF
)"
```

---

## Task 5: Scoping error types and vendor signature update

**Spec refs:** Req 2.2, 2.3, 5.2, 9.2

**Files:**
- Modify: `internal/profile/config.go`
- Modify: `internal/vendor/vendor.go`
- Modify: `internal/vendor/orgvendor.go`
- Modify: `internal/vendor/auditvendor.go`
- Modify: `internal/vendor/repovendor.go`
- Modify: `internal/vendor/cached.go`
- Modify: `handlers.go`
- Modify: `main.go`

This task threads the `repositoryScope` parameter through the vendor chain. It's a mechanical change that touches many files but the logic is straightforward: pass the string through every layer so the org vendor can use it.

- [ ] **Step 1: Add scoping mismatch error types**

Add to `internal/profile/config.go`:

```go
// RepositoryScopeUnexpectedError indicates a repository-scope was provided
// to a profile that does not accept caller scoping.
type RepositoryScopeUnexpectedError struct {
	ProfileName string
}

func (e RepositoryScopeUnexpectedError) Error() string {
	return fmt.Sprintf("profile %q does not accept repository scoping", e.ProfileName)
}

func (e RepositoryScopeUnexpectedError) Status() (int, string) {
	return http.StatusBadRequest, "profile does not accept repository scoping"
}

// RepositoryScopeRequiredError indicates a repository-scope was not provided
// but the profile requires one.
type RepositoryScopeRequiredError struct {
	ProfileName string
}

func (e RepositoryScopeRequiredError) Error() string {
	return fmt.Sprintf("profile %q requires a repository scope", e.ProfileName)
}

func (e RepositoryScopeRequiredError) Status() (int, string) {
	return http.StatusBadRequest, "repository scope is required for this profile"
}
```

- [ ] **Step 2: Update ProfileTokenVendor signature**

In `internal/vendor/vendor.go`, change the `ProfileTokenVendor` type to accept a fourth `repositoryScope` parameter:

```go
type ProfileTokenVendor func(ctx context.Context, ref profile.ProfileRef, repo string, repositoryScope string) VendorResult
```

- [ ] **Step 3: Update all call sites mechanically**

This is a compile-driven refactor. Update every file that references `ProfileTokenVendor` to pass or accept the new parameter:

In `internal/vendor/orgvendor.go`, update the function signature:
```go
return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string, repositoryScope string) VendorResult {
```

In `internal/vendor/repovendor.go`, update the function signature (pipeline profiles never use scoping, ignore the parameter):
```go
return func(ctx context.Context, ref profile.ProfileRef, requestedRepoURL string, repositoryScope string) VendorResult {
```

In `internal/vendor/cached.go`, update the closure signature and pass through:
```go
return func(ctx context.Context, ref profile.ProfileRef, requestedRepository string, repositoryScope string) VendorResult {
    // ... existing cache logic ...
    result := v(ctx, ref, requestedRepository, repositoryScope)
    // ...
}
```

In `internal/vendor/auditvendor.go`, update the closure signature and pass through:
```go
return func(ctx context.Context, ref profile.ProfileRef, repo string, repositoryScope string) VendorResult {
    // ...
    result := vendor(ctx, ref, repo, repositoryScope)
    // ...
}
```

In `handlers.go`, update both handler call sites:

In `handlePostToken`:
```go
result := tokenVendor(r.Context(), ref, "", "")
```
(The actual scope extraction will be wired in Task 6.)

In `handlePostGitCredentials`:
```go
result := tokenVendor(r.Context(), ref, requestedRepoURL, "")
```

- [ ] **Step 4: Update all test call sites**

Update all test files that construct or call `ProfileTokenVendor` to include the fourth parameter. This includes:
- `internal/vendor/orgvendor_test.go`: update `sequenceVendor` closure and direct vendor calls
- `internal/vendor/cached_test.go`: update `sequenceVendor` call site
- `internal/vendor/repovendor_test.go`: update vendor calls
- `internal/vendor/auditvendor_test.go`: update vendor calls
- `internal/vendor/testhelpers_test.go`: update `sequenceVendor` closure signature
- `handlers_test.go`: update `tv()` helper and vendor calls

The `sequenceVendor` helper in `testhelpers_test.go` signature becomes:
```go
func(ctx context.Context, ref profile.ProfileRef, repo string, repositoryScope string) vendor.VendorResult {
```

- [ ] **Step 5: Build and test**

Run: `go build ./... && go test ./...`
Expected: PASS — all compilation and tests succeed with the new parameter threaded through

- [ ] **Step 6: Commit**

```bash
git add internal/profile/config.go internal/vendor/vendor.go internal/vendor/orgvendor.go internal/vendor/repovendor.go internal/vendor/cached.go internal/vendor/auditvendor.go handlers.go main.go internal/vendor/orgvendor_test.go internal/vendor/cached_test.go internal/vendor/repovendor_test.go internal/vendor/auditvendor_test.go internal/vendor/testhelpers_test.go handlers_test.go
git commit -m "$(cat <<'EOF'
refactor: thread repositoryScope parameter through vendor chain

Add repositoryScope string parameter to ProfileTokenVendor and all
implementations. Currently passed as empty string everywhere — the
actual scoping logic follows in the next commit.

Also add RepositoryScopeUnexpectedError and RepositoryScopeRequiredError
types for bidirectional validation.
EOF
)"
```

---

## Task 6: Wire repository-scope from handler to org vendor

**Spec refs:** Req 2.1–2.3, 5.2, 7.1–7.2, 9.2

**Files:**
- Modify: `handlers.go`
- Modify: `handlers_test.go`
- Modify: `internal/vendor/orgvendor.go`
- Modify: `internal/vendor/orgvendor_test.go`
- Modify: `internal/vendor/auditvendor.go`

- [ ] **Step 1: Write failing tests for org vendor scoping validation**

Add to `internal/vendor/orgvendor_test.go`:

```go
func TestOrgVendor_CallerScopedRepository_Success(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	var capturedRepoNames []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		capturedRepoNames = repoNames
		return "scoped-token", vendedDate, nil
	})

	profileYAML := `
organization:
  profiles:
    - name: caller-scoped-profile
      repositories: ["{{caller-scoped-repository}}"]
      permissions: [contents:write]
      match:
        - claim: pipeline_slug
          valuePattern: "agent-workflows.*"
`

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(t, profileYAML), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "caller-scoped-profile",
		Type:         profile.ProfileTypeOrg,
	}

	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, ref, "", "target-repo")

	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "scoped-token",
		HashedToken:         vendor.HashToken("scoped-token"),
		Repositories:        profile.NewSpecificScope("target-repo"),
		Permissions:         []string{"contents:write", "metadata:read"},
		Profile:             "org:caller-scoped-profile",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "",
	})
	assert.Equal(t, []string{"target-repo"}, capturedRepoNames)
}

func TestOrgVendor_CallerScoped_MissingScopeParameter(t *testing.T) {
	profileYAML := `
organization:
  profiles:
    - name: caller-scoped-profile
      repositories: ["{{caller-scoped-repository}}"]
      permissions: [contents:write]
      match:
        - claim: pipeline_slug
          valuePattern: "agent-workflows.*"
`

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(t, profileYAML), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "caller-scoped-profile",
		Type:         profile.ProfileTypeOrg,
	}

	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, ref, "", "")
	assertVendorFailure(t, result, "requires a repository scope")
}

func TestOrgVendor_ScopeProvidedToNonScopedProfile(t *testing.T) {
	v := vendor.NewOrgVendor(profiletest.DefaultTestProfileStore(t), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "non-default-profile",
		Type:         profile.ProfileTypeOrg,
	}

	ctx := createTestClaimsContext()
	result := v(ctx, ref, "", "unwanted-scope")
	assertVendorFailure(t, result, "does not accept repository scoping")
}

func TestOrgVendor_ScopeProvidedToAllReposProfile(t *testing.T) {
	profileYAML := `
organization:
  profiles:
    - name: all-repos-profile
      repositories: ["{{all-repositories}}"]
      permissions: [contents:read]
`

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(t, profileYAML), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "all-repos-profile",
		Type:         profile.ProfileTypeOrg,
	}

	ctx := createTestClaimsContext()
	result := v(ctx, ref, "", "unwanted-scope")
	assertVendorFailure(t, result, "does not accept repository scoping")
}
```

Add the helper:
```go
func createTestClaimsContextWithPipeline(pipelineSlug string) context.Context {
	claims := &jwt.BuildkiteClaims{
		OrganizationSlug: "organization-slug",
		PipelineSlug:     pipelineSlug,
		PipelineID:       "pipeline-123",
		BuildNumber:      1,
	}
	return jwt.ContextWithBuildkiteClaims(context.Background(), claims)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vendor/ -run "TestOrgVendor_CallerScoped|TestOrgVendor_ScopeProvided" -v`
Expected: FAIL — scoping validation not implemented

- [ ] **Step 3: Implement bidirectional scoping validation in org vendor**

In `internal/vendor/orgvendor.go`, add scoping validation after the match evaluation and before the repository check. Replace the section from the match evaluation through to token vending (approximately lines 50–76) with:

```go
		// --- Bidirectional scoping validation ---
		repoScope := authProfile.Attrs.RepositoryScope()

		if repoScope.IsCallerScoped() {
			// Profile requires caller to supply a repository name.
			if repositoryScope == "" {
				return NewVendorFailed(profile.RepositoryScopeRequiredError{ProfileName: ref.Name})
			}
			// Narrow the scope to the single caller-supplied repository.
			repoScope = profile.NewSpecificScope(repositoryScope)
		} else if repositoryScope != "" {
			// Caller supplied a scope but the profile doesn't accept one.
			return NewVendorFailed(profile.RepositoryScopeUnexpectedError{ProfileName: ref.Name})
		}

		// The repository is only supplied for the git-credentials endpoint:
		// checking it allows Git to respond properly: it's not a security measure.
		if requestedRepoURL != "" {
			repo, err := url.Parse(requestedRepoURL)
			if err != nil {
				return NewVendorFailed(fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err))
			}

			_, repository := github.RepoForURL(*repo)

			if repoScope.IsWildcard() || repoScope.IsCallerScoped() {
				// Wildcard and caller-scoped profiles claim coverage of all repos.
				// Failure is a hard error, not a credential helper fallback.
			} else if !repoScope.Contains(repository) {
				slog.Debug("profile doesn't support requested repository: no token vended.",
					"organization", ref.Organization,
					"profile", ref.ShortString(),
					"requestedRepo", requestedRepoURL,
				)
				return NewVendorUnmatched()
			}
		}

		// Use the GitHub API to vend a token for the repository
		token, expiry, err := tokenVendor(ctx, repoScope.Names, authProfile.Attrs.Permissions)
```

Wait — the `repoScope` for caller-scoped is now a `NewSpecificScope(repositoryScope)`, so `repoScope.IsCallerScoped()` is false in the git-credentials check. The logic should instead check whether the *profile's* scope is caller-scoped or wildcard. Let me correct:

```go
		// --- Bidirectional scoping validation ---
		profileScope := authProfile.Attrs.RepositoryScope()

		var repoScope profile.RepositoryScope

		if profileScope.IsCallerScoped() {
			if repositoryScope == "" {
				return NewVendorFailed(profile.RepositoryScopeRequiredError{ProfileName: ref.Name})
			}
			repoScope = profile.NewSpecificScope(repositoryScope)
		} else if repositoryScope != "" {
			return NewVendorFailed(profile.RepositoryScopeUnexpectedError{ProfileName: ref.Name})
		} else {
			repoScope = profileScope
		}

		// The repository is only supplied for the git-credentials endpoint:
		// checking it allows Git to respond properly: it's not a security measure.
		if requestedRepoURL != "" {
			repo, err := url.Parse(requestedRepoURL)
			if err != nil {
				return NewVendorFailed(fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err))
			}

			_, repository := github.RepoForURL(*repo)

			// Profiles that claim coverage of all repositories (wildcard or caller-scoped)
			// treat failure as a hard error — no credential helper fallback.
			// Static-list profiles return unmatched for repos outside their list.
			if !profileScope.IsWildcard() && !profileScope.IsCallerScoped() && !repoScope.Contains(repository) {
				slog.Debug("profile doesn't support requested repository: no token vended.",
					"organization", ref.Organization,
					"profile", ref.ShortString(),
					"requestedRepo", requestedRepoURL,
				)
				return NewVendorUnmatched()
			}
		}

		// Use the GitHub API to vend a token
		token, expiry, err := tokenVendor(ctx, repoScope.Names, authProfile.Attrs.Permissions)
```

The rest of the function (success path, ProfileToken construction) uses `repoScope` which is now correctly narrowed for caller-scoped profiles.

- [ ] **Step 4: Wire repository-scope extraction in handlePostToken for org routes**

In `handlers.go`, update `handlePostToken` to extract the scope for org profiles:

```go
func handlePostToken(tokenVendor vendor.ProfileTokenVendor, expectedType profile.ProfileType) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer drainRequestBody(r)

		ref, err := buildProfileRef(r, expectedType)
		if err != nil {
			requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid profile parameter: %w", err))
			return
		}

		var repositoryScope string
		if expectedType == profile.ProfileTypeOrg {
			repositoryScope, err = extractRepositoryScope(r)
			if err != nil {
				requestError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid repository-scope: %w", err))
				return
			}
		}

		result := tokenVendor(r.Context(), ref, "", repositoryScope)
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/vendor/ ./. -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add handlers.go handlers_test.go internal/vendor/orgvendor.go internal/vendor/orgvendor_test.go
git commit -m "$(cat <<'EOF'
feat: implement bidirectional repository scoping validation

The org vendor now enforces strict bidirectional scoping rules:
- caller-scoped profiles require a repository-scope parameter
- non-scoped profiles reject a repository-scope parameter
- all-repositories profiles reject a repository-scope parameter

The handler extracts the repository-scope query parameter for org
token requests and passes it through to the vendor chain.
EOF
)"
```

---

## Task 7: Git-credentials endpoint — caller-scoped and all-repositories behaviour

**Spec refs:** Req 3.1–3.3, 4.1

**Files:**
- Modify: `internal/vendor/orgvendor.go`
- Modify: `internal/vendor/orgvendor_test.go`
- Modify: `handlers.go`
- Modify: `handlers_test.go`

- [ ] **Step 1: Write failing tests for git-credentials caller-scoped behaviour**

Add to `internal/vendor/orgvendor_test.go`:

```go
func TestOrgVendor_GitCredentials_CallerScoped_DerivesRepoFromURL(t *testing.T) {
	vendedDate := time.Date(1970, 1, 1, 0, 0, 10, 0, time.UTC)

	var capturedRepoNames []string
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		capturedRepoNames = repoNames
		return "scoped-token", vendedDate, nil
	})

	profileYAML := `
organization:
  profiles:
    - name: caller-scoped-profile
      repositories: ["{{caller-scoped-repository}}"]
      permissions: [contents:write]
      match:
        - claim: pipeline_slug
          valuePattern: "agent-workflows.*"
`

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(t, profileYAML), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "caller-scoped-profile",
		Type:         profile.ProfileTypeOrg,
	}

	// Git-credentials passes requestedRepoURL, not repositoryScope
	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, ref, "https://github.com/org/target-repo", "")

	assertVendorSuccess(t, result, vendor.ProfileToken{
		Token:               "scoped-token",
		HashedToken:         vendor.HashToken("scoped-token"),
		Repositories:        profile.NewSpecificScope("target-repo"),
		Permissions:         []string{"contents:write", "metadata:read"},
		Profile:             "org:caller-scoped-profile",
		Expiry:              vendedDate,
		OrganizationSlug:    "organization-slug",
		VendedRepositoryURL: "https://github.com/org/target-repo",
	})
	assert.Equal(t, []string{"target-repo"}, capturedRepoNames)
}

func TestOrgVendor_GitCredentials_CallerScoped_NoRepoURL_Fails(t *testing.T) {
	profileYAML := `
organization:
  profiles:
    - name: caller-scoped-profile
      repositories: ["{{caller-scoped-repository}}"]
      permissions: [contents:write]
      match:
        - claim: pipeline_slug
          valuePattern: "agent-workflows.*"
`

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(t, profileYAML), nil)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "caller-scoped-profile",
		Type:         profile.ProfileTypeOrg,
	}

	// Neither repositoryScope nor requestedRepoURL provided
	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, ref, "", "")
	assertVendorFailure(t, result, "requires a repository scope")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vendor/ -run "TestOrgVendor_GitCredentials_CallerScoped" -v`
Expected: FAIL — git-credentials path doesn't derive scope from URL

- [ ] **Step 3: Implement git-credentials caller-scoped derivation in org vendor**

Update the scoping validation in `internal/vendor/orgvendor.go` to derive the repository scope from the requested URL when the profile is caller-scoped and `repositoryScope` is empty but `requestedRepoURL` is present:

```go
		if profileScope.IsCallerScoped() {
			if repositoryScope != "" {
				repoScope = profile.NewSpecificScope(repositoryScope)
			} else if requestedRepoURL != "" {
				// Git-credentials path: derive scope from the Git-supplied repository
				repo, err := url.Parse(requestedRepoURL)
				if err != nil {
					return NewVendorFailed(fmt.Errorf("could not parse requested repo URL %s: %w", requestedRepoURL, err))
				}
				_, repository := github.RepoForURL(*repo)
				repoScope = profile.NewSpecificScope(repository)
			} else {
				return NewVendorFailed(profile.RepositoryScopeRequiredError{ProfileName: ref.Name})
			}
		} else if repositoryScope != "" {
			return NewVendorFailed(profile.RepositoryScopeUnexpectedError{ProfileName: ref.Name})
		} else {
			repoScope = profileScope
		}
```

Since the repo URL is now parsed in the scoping block for caller-scoped profiles, the subsequent git-credentials URL check must not re-parse or re-check — the repo is already validated. Update the git-credentials repo check to skip when the profile was caller-scoped (the scope was derived from the same URL):

```go
		if requestedRepoURL != "" && !profileScope.IsCallerScoped() {
```

- [ ] **Step 4: Write test for git-credentials 403 on failure for all-repositories and caller-scoped**

The vendor itself returns `NewVendorFailed` when GitHub rejects the token. The handler converts failures to HTTP errors. The spec says both `{{caller-scoped-repository}}` and `{{all-repositories}}` profiles must return 403 on failure rather than empty-success. This is already the behaviour because:
1. Caller-scoped profiles never reach the `NewVendorUnmatched()` path (the scoping block handles all cases).
2. All-repositories profiles have `profileScope.IsWildcard() == true`, so the `!profileScope.IsWildcard()` check prevents the unmatched path.

Write a test confirming this:

```go
func TestOrgVendor_GitCredentials_AllRepos_NoUnmatched(t *testing.T) {
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("GitHub API rejected request")
	})

	profileYAML := `
organization:
  profiles:
    - name: all-repos-profile
      repositories: ["{{all-repositories}}"]
      permissions: [contents:read]
`

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(t, profileYAML), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "all-repos-profile",
		Type:         profile.ProfileTypeOrg,
	}

	ctx := createTestClaimsContext()
	result := v(ctx, ref, "https://github.com/org/any-repo", "")

	// Must be a failure, not an unmatched (empty-success)
	assertVendorFailure(t, result, "GitHub API rejected request")
}
```

- [ ] **Step 5: Run all vendor tests**

Run: `go test ./internal/vendor/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/vendor/orgvendor.go internal/vendor/orgvendor_test.go
git commit -m "$(cat <<'EOF'
feat: git-credentials endpoint derives scope from request URL

For caller-scoped profiles at the git-credentials endpoint, the
repository scope is derived from the Git-supplied URL in the request
body. No new plugin parameters are needed.

Both caller-scoped and all-repositories profiles return hard errors
(not empty-success) on token issuance failure, since they claim
coverage of all repositories.
EOF
)"
```

---

## Task 8: Cache key includes repository name for caller-scoped profiles

**Spec refs:** Req 8.1–8.3

**Files:**
- Modify: `internal/vendor/cached.go`
- Modify: `internal/vendor/cached_test.go`

- [ ] **Step 1: Write failing tests for caller-scoped cache key behaviour**

Add to `internal/vendor/cached_test.go`:

```go
func TestCacheCallerScoped_DifferentReposAreSeparateEntries(t *testing.T) {
	wrapped := sequenceVendor("token-for-repo-a", "token-for-repo-b")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "scoped-profile",
		Type:         profile.ProfileTypeOrg,
	}

	// First call for repo-a: cache miss
	result := v(context.Background(), ref, "", "repo-a")
	token, ok := result.Token()
	require.True(t, ok)
	assert.Equal(t, "token-for-repo-a", token.Token)

	// Second call for repo-b: must also miss (different cache key)
	result = v(context.Background(), ref, "", "repo-b")
	token, ok = result.Token()
	require.True(t, ok)
	assert.Equal(t, "token-for-repo-b", token.Token)

	// Third call for repo-a: cache hit (returns first token)
	result = v(context.Background(), ref, "", "repo-a")
	token, ok = result.Token()
	require.True(t, ok)
	assert.Equal(t, "token-for-repo-a", token.Token)
}

func TestCacheAllRepositories_SameKeyAsWildcard(t *testing.T) {
	wrapped := sequenceVendor("first-call", "should-not-be-called")

	c := newTestCached(t, defaultTTL, "test-digest")
	v := c(wrapped)

	ref := profile.ProfileRef{
		Organization: "org",
		Name:         "all-repos-profile",
		Type:         profile.ProfileTypeOrg,
	}

	// First call: cache miss
	result := v(context.Background(), ref, "", "")
	token, ok := result.Token()
	require.True(t, ok)
	assert.Equal(t, "first-call", token.Token)

	// Second call: cache hit (same key, no repository scope component)
	result = v(context.Background(), ref, "", "")
	token, ok = result.Token()
	require.True(t, ok)
	assert.Equal(t, "first-call", token.Token)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vendor/ -run "TestCacheCallerScoped|TestCacheAllRepositories" -v`
Expected: FAIL — cache key doesn't include repository scope

- [ ] **Step 3: Implement cache key extension**

In `internal/vendor/cached.go`, update the cache key construction to include the repository scope when present:

```go
			// Cache key includes digest prefix for config version namespacing
			key := fmt.Sprintf("%s:%s", digester.Digest(), ref.String())
			if repositoryScope != "" {
				key = fmt.Sprintf("%s:%s:%s", digester.Digest(), ref.String(), repositoryScope)
			}
```

- [ ] **Step 4: Run all cached vendor tests**

Run: `go test ./internal/vendor/ -run "TestCache" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vendor/cached.go internal/vendor/cached_test.go
git commit -m "$(cat <<'EOF'
feat: include repository name in cache key for caller-scoped profiles

When a repositoryScope is present, the cache key becomes
{digest}:{profile-ref}:{repository-name}. This ensures tokens for
different repositories under the same caller-scoped profile are cached
independently.

All-repositories profiles continue to use the two-component key since
a single token covers all repositories.
EOF
)"
```

---

## Task 9: Error handling — generic 403 for GitHub API rejections

**Spec refs:** Req 7.1–7.2

**Files:**
- Modify: `internal/vendor/orgvendor.go`
- Modify: `internal/vendor/orgvendor_test.go`

- [ ] **Step 1: Write failing test for generic error on GitHub API rejection**

Add to `internal/vendor/orgvendor_test.go`:

```go
func TestOrgVendor_CallerScoped_GitHubRejection_Returns403(t *testing.T) {
	tokenVendor := vendor.TokenVendor(func(ctx context.Context, repoNames []string, scopes []string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("resource not accessible by integration")
	})

	profileYAML := `
organization:
  profiles:
    - name: caller-scoped-profile
      repositories: ["{{caller-scoped-repository}}"]
      permissions: [contents:write]
      match:
        - claim: pipeline_slug
          valuePattern: "agent-workflows.*"
`

	v := vendor.NewOrgVendor(profiletest.CreateTestProfileStore(t, profileYAML), tokenVendor)

	ref := profile.ProfileRef{
		Organization: "organization-slug",
		Name:         "caller-scoped-profile",
		Type:         profile.ProfileTypeOrg,
	}

	ctx := createTestClaimsContextWithPipeline("agent-workflows")
	result := v(ctx, ref, "", "nonexistent-repo")

	err, failed := result.Failed()
	require.True(t, failed)

	// The error must implement HTTPStatuser and return 403
	var statuser HTTPStatuser
	require.ErrorAs(t, err, &statuser)
	status, _ := statuser.Status()
	assert.Equal(t, http.StatusForbidden, status)

	// The error message must NOT reveal why GitHub rejected the request
	assert.NotContains(t, err.Error(), "resource not accessible")
}
```

Note: You'll need to either add `HTTPStatuser` interface import or define it in the test — it's already defined in `handlers.go`. Since the vendor tests are in `vendor_test` package, define a local interface:
```go
type HTTPStatuser interface {
	Status() (int, string)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vendor/ -run "TestOrgVendor_CallerScoped_GitHubRejection" -v`
Expected: FAIL — error doesn't implement HTTPStatuser with 403

- [ ] **Step 3: Add a token issuance error type and wrap GitHub rejections**

Add to `internal/profile/config.go`:

```go
// TokenIssuanceError wraps a GitHub API rejection with a generic 403 response.
// The underlying cause is available for audit logging but not exposed in the
// HTTP response.
type TokenIssuanceError struct {
	ProfileName string
	Cause       error
}

func (e TokenIssuanceError) Error() string {
	return fmt.Sprintf("token issuance failed for profile %q: %v", e.ProfileName, e.Cause)
}

func (e TokenIssuanceError) Unwrap() error {
	return e.Cause
}

func (e TokenIssuanceError) Status() (int, string) {
	return http.StatusForbidden, "token request denied"
}
```

In `internal/vendor/orgvendor.go`, wrap the token vendor error for caller-scoped and all-repositories profiles:

```go
		token, expiry, err := tokenVendor(ctx, repoScope.Names, authProfile.Attrs.Permissions)
		if err != nil {
			if profileScope.IsCallerScoped() || profileScope.IsWildcard() {
				return NewVendorFailed(profile.TokenIssuanceError{ProfileName: ref.Name, Cause: err})
			}
			return NewVendorFailed(fmt.Errorf("could not issue token for profile %s: %w", ref, err))
		}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/vendor/ -run "TestOrgVendor_CallerScoped_GitHubRejection" -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/profile/config.go internal/vendor/orgvendor.go internal/vendor/orgvendor_test.go
git commit -m "$(cat <<'EOF'
feat: return generic 403 for GitHub API rejections on scoped profiles

When the GitHub API rejects a token request for caller-scoped or
all-repositories profiles, the bridge returns a generic 403 "token
request denied" rather than exposing the underlying error. This
prevents information leakage about whether a repository exists.

The full GitHub error is preserved in the error chain for audit
logging via TokenIssuanceError.Unwrap().
EOF
)"
```

---

## Task 10: Audit logging for scoping mismatches

**Spec refs:** Req 9.2

**Files:**
- Modify: `internal/vendor/auditvendor.go`
- Modify: `internal/vendor/auditvendor_test.go`

- [ ] **Step 1: Write failing tests for audit logging of scoping mismatches**

Add to `internal/vendor/auditvendor_test.go`:

```go
func TestAuditor_RecordsScopingMismatchError(t *testing.T) {
	tests := []struct {
		name          string
		vendorError   error
		expectedAudit string
	}{
		{
			name:          "scope provided to non-scoped profile",
			vendorError:   profile.RepositoryScopeUnexpectedError{ProfileName: "static-profile"},
			expectedAudit: "does not accept repository scoping",
		},
		{
			name:          "scope missing for caller-scoped profile",
			vendorError:   profile.RepositoryScopeRequiredError{ProfileName: "scoped-profile"},
			expectedAudit: "requires a repository scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := vendor.ProfileTokenVendor(func(ctx context.Context, ref profile.ProfileRef, repo string, repositoryScope string) vendor.VendorResult {
				return vendor.NewVendorFailed(tt.vendorError)
			})

			auditor := vendor.Auditor(inner)

			ctx, entry := audit.Context(context.Background())
			ref := profile.ProfileRef{Organization: "org", Name: "test", Type: profile.ProfileTypeOrg}
			auditor(ctx, ref, "", "")

			assert.Contains(t, entry.Error, tt.expectedAudit)
		})
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/vendor/ -run "TestAuditor_RecordsScopingMismatchError" -v`
Expected: The existing audit error recording in `Auditor` already captures `vendor failure: <error message>` for any failed result. The scoping error types produce descriptive messages, so the audit log will contain them. This test should PASS with the existing code.

If it passes, no code changes are needed — the existing audit infrastructure handles scoping errors correctly. The error types from Task 5 produce messages like "profile X does not accept repository scoping" which flow naturally through the audit vendor's `entry.Error = fmt.Sprintf("vendor failure: %v", err)`.

- [ ] **Step 3: Commit (if test changes were needed)**

If tests pass without changes, skip this commit. Otherwise:

```bash
git add internal/vendor/auditvendor.go internal/vendor/auditvendor_test.go
git commit -m "$(cat <<'EOF'
test: verify audit logging captures scoping mismatch errors
EOF
)"
```

---

## Task 11: Integration tests

**Spec refs:** Cross-cutting validation

**Files:**
- Modify: `api_integration_test.go`

- [ ] **Step 1: Identify integration test patterns**

Read `api_integration_test.go` to understand the `APITestHarness` pattern, how requests are made, and how assertions work.

- [ ] **Step 2: Write integration tests for the token endpoint**

Add integration tests covering:
- Caller-scoped profile with valid `repository-scope` query parameter → 200 with scoped token
- Caller-scoped profile without `repository-scope` → error response
- Static-list profile with unexpected `repository-scope` → error response
- All-repositories profile with `repository-scope` → error response
- `repository-scope` containing `/` → 400

- [ ] **Step 3: Write integration tests for git-credentials endpoint**

Add integration tests covering:
- Caller-scoped profile at git-credentials → derives repo from request body, returns credentials
- All-repositories profile at git-credentials → returns credentials as before

- [ ] **Step 4: Run integration tests**

Run: `make integration`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api_integration_test.go
git commit -m "$(cat <<'EOF'
test: add integration tests for dynamic repository scoping

Cover caller-scoped and all-repositories profiles at both the token
and git-credentials endpoints, including bidirectional validation
and input rejection.
EOF
)"
```

---

## Task 12: Final validation — make agent

**Files:** None (validation only)

- [ ] **Step 1: Run make agent**

Run: `make agent`
Expected: PASS — build, format, lint, and all tests pass

- [ ] **Step 2: Run integration tests**

Run: `make integration`
Expected: PASS

- [ ] **Step 3: Review git log**

Run: `git log --oneline main..HEAD`
Review that all commits are present and well-structured.

---

## Deferred Tasks (out of scope for this plan)

These are explicitly out of scope per the spec but noted for future work:

- **JSON schema publication** (Req 12.1) — publish after feature release
- **Chinmina-token plugin changes** (Req 10.1–10.3) — separate repository
- **Chinmina-git-credentials plugin** (Req 11.1) — no changes needed
- **Documentation updates** — separate documentation repository
- **Removal of `*` in v1** (Req 13.2) — tracked separately
