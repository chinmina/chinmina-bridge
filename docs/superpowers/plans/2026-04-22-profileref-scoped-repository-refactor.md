# Plan: ProfileRef-carried Scope Refactor

> Source PRD: Derived from code review of PR #297 (dynamic repository scoping) and subsequent design discussion. Resolves review findings 1 (scope priority) and 2 (cache behaviour) by encoding the scoped repository into `ProfileRef`.

## Architectural decisions

Durable decisions that apply across all phases:

- **URN format (full)**: scoped org refs render as `profile://organization/{org}/profile/{name}/repository/{repo}`. Non-scoped refs unchanged. Repo refs are never scoped.
- **URN format (short)**: scoped org refs render as `org:{name}/{repo}`. Non-scoped refs unchanged (`org:{name}` / `repo:{name}`). The `/` separator is safe because repo-scope values reject `/` (`extractRepositoryScope`) and profile names do not contain `/`.
- **Scope resolution location**: handler boundary. The `profile` package stays free of request-level concerns; the `vendor` package receives refs with scope already resolved.
- **Handler flow ordering**: repository resolution runs *before* ref construction in both handlers. `/organization/token` extracts `?repository-scope=`, validates, and constructs a URL form of it. `/organization/git-credentials` reads the body and constructs the URL from the Git properties. Both handlers then call the builder with the resolved repository name. The URL is also retained by the handler for passing to the vendor (`requestedRepoURL` role — response URL, static-list matching).
- **`PathValuer` interface** (single-function): `type PathValuer interface { PathValue(name string) string }`. `*http.Request` satisfies this directly. Defined in the handler package. Replaces the need to pass `*http.Request` into ref-building code; keeps the builder free of HTTP concerns.
- **ProfileRefBuilder contract**: `type ProfileRefBuilder func(ctx context.Context, pv PathValuer, scopedRepo string) (profile.ProfileRef, error)`. Builders are closures over the profile store, injected per route at wiring time. Claims come from context via existing `jwt.RequireBuildkiteClaimsFromContext`. Because URL/scope resolution happens in the handler before this is called, the builder's inputs are already normalised.
- **Scope source per endpoint** (resolved in handler, validated in builder):
  - `/organization/token/{profile}`: `?repository-scope=` query parameter
  - `/organization/git-credentials/{profile}`: repository name derived from the Git-supplied URL in the request body
  - Pipeline endpoints: never scoped
- **Trust model** (captured in code comments, not just spec): `ScopedRepository` narrows within an already-authorised profile. It does not grant access. The profile's match rules gate who may invoke a profile at all, and GitHub is the final enforcement boundary for whether a specific repository is reachable. This informs why caller-supplied scope is acceptable to honour without additional cross-checks.
- **Bidirectional validation stays**: Req 2.2 (scope on non-caller-scoped profile → reject) and 5.2 (scope on all-repositories profile → reject) are kept and enforced at the handler boundary, now trivially because the handler has the profile type from its store lookup.
- **Vendor signature endpoint**: after Phase 4, `ProfileTokenVendor = func(ctx, ref, requestedRepoURL) VendorResult`. `requestedRepoURL` retains two roles — git-credentials response URL and static-list profile repo-matching — neither of which concerns scope resolution.
- **Cache key derivation**: unchanged in shape — `{digest}:{ref.String()}`. Correctness for caller-scoped per-repo entries emerges naturally from the ref including `ScopedRepository`. The `repositoryScope != ""` branch in `cached.go` is removed.

---

## Phase 0: Baseline anchor

Not a refactor phase — a pre-condition. Captures the reference behaviour baseline that Phase 4's verification step diffs against.

### What to do

- Record the branch-tip commit hash.
- Run `make agent` and `make integration`; confirm both pass at that commit.
- Capture representative integration test outputs (one per profile type × endpoint combination — six scenarios) as the "pre-refactor baseline": request, response body, response status, audit log entry. Store as text files under `.beans/tmp/` or equivalent scratch area for later diff.

No code changes. This exists so that "behaviour preserved" is verifiable, not asserted.

---

## Phase 1: ProfileRef carries scoped-repository

**User stories**: Goals 1, 5. Foundational — no functional change yet.

### What to build

Extend `ProfileRef` with an optional `ScopedRepository string` field. The URN rendering (`String()`), short form (`ShortString()`), parser (`ParseProfileRef`) and constructor (`NewProfileRef` or a companion) all understand the new field. Non-scoped refs render and parse exactly as before — existing URN strings remain valid and roundtrip unchanged.

The field is populated only by caller-supplied input in later phases. In this phase, no production code constructs a scoped ref.

Confirm (don't add) that profile-name validation in `internal/profile/compilation.go` already rejects `/` and `:` in names — this is prerequisite for unambiguous URN parsing and is enforced elsewhere, not in `ref.go`.

### Acceptance criteria

- [ ] `[observable]` `ProfileRef{Type: Org, Organization: "o", Name: "p", ScopedRepository: "r"}.String()` renders `profile://organization/o/profile/p/repository/r`
- [ ] `[observable]` `ShortString()` for the same ref renders `org:p/r`; non-scoped ref unchanged
- [ ] `[observable]` `ParseProfileRef` roundtrips all four URN variants: org non-scoped, org scoped, repo new-format, repo old-format (backward compat)
- [ ] `[observable]` `ParseProfileRef` rejects malformed scoped URNs: trailing empty (`…/profile/p/repository/`), extra segments (`…/repository/r/extra`), scope on a pipeline ref (`…/pipeline/…/repository/r`)
- [ ] `[structural]` `NewProfileRef` (or a companion constructor) accepts a scoped-repository parameter; zero-value input produces a non-scoped ref
- [ ] `[structural]` Confirmed via grep / existing tests that profile-name validation already rejects `/` and `:`; no new constraint added in `ref.go`
- [ ] `[observable]` `make agent` passes with no regressions

### Verification

Run `go test ./internal/profile/...` and `make agent`. Manually inspect URN output from new unit tests to confirm the suffix is only present when `ScopedRepository` is non-empty.

---

## Phase 2a: Handler restructure + `ProfileRefBuilder` wiring

**User stories**: Goals 2, 3 (plumbing only — validation in 2b).

**Carry-forward**: Verify Phase 0 and 1 before starting.

### What to build

Two concurrent changes:

1. **Handler flow reorder.** Repository resolution runs *before* ref construction.
   - `handlePostToken` first calls `extractRepositoryScope(r)` to obtain a repo name (or `""`). No behaviour change — just moved earlier.
   - `handlePostGitCredentials` reads the body (`credentialhandler.ReadProperties`, `ConstructRepositoryURL`) first. From the URL, derive the repo name. No behaviour change.

2. **`ProfileRefBuilder` + `PathValuer` introduction.** Define `PathValuer` (single-function interface) and `ProfileRefBuilder` in the handler package. Provide a default builder implementation, a closure over `*profile.ProfileStore` + expected `ProfileType`, that currently replicates today's `buildProfileRef` behaviour — ignoring the `scopedRepo` argument. Wire a distinct builder per route in `main.go`.

Result: the handler now has a clean ordering (resolve repo → build ref → call vendor) and the ref-building call site is one injected function. No new validation, no scope flowing into the ref yet.

Update handler unit tests to inject a simple test builder (usually an inline closure) instead of threading path/claim scaffolding. Integration tests pass unchanged.

### Acceptance criteria

- [ ] `[structural]` `PathValuer` interface defined as `interface { PathValue(string) string }` in the handler package; `*http.Request` satisfies it implicitly
- [ ] `[structural]` `ProfileRefBuilder` type defined as `func(ctx, PathValuer, scopedRepo string) (ProfileRef, error)`; handler signatures accept one
- [ ] `[structural]` Handler flow: both handlers resolve repo (scope param / body URL) *before* calling the builder
- [ ] `[observable]` `main.go` wires one builder per route (4 routes: org token, org git-credentials, pipeline token, pipeline git-credentials); builders are closures over `*profile.ProfileStore` + expected `ProfileType`
- [ ] `[observable]` All existing handler unit tests pass (possibly with mechanical test-setup updates)
- [ ] `[observable]` `make integration` passes — no behavioural change end-to-end
- [ ] `[observable]` Handler tests can now swap in a test builder without constructing a full `*http.Request` or profile store (demonstrates testability improvement)

### Verification

Run `go test ./... && make integration`. End-to-end behaviour identical: same status codes, same token responses, same audit entries. Confirm via diff against Phase 0 baseline outputs for at least the org-token and org-git-credentials happy paths.

---

## Phase 2b: Scope validation in builder

**User stories**: Reqs 2.1, 2.2, 2.3, 5.2, 6.1, 6.2, 9.2 (a–c).

**Carry-forward**: Verify Phase 1 and 2a before starting.

### What to build

Add profile-type-aware validation to the builder. The `scopedRepo` argument passed by the handler is now consumed:

1. Builder looks up the profile from the store (closure-scoped).
2. If profile is caller-scoped and `scopedRepo == ""` → return `RepositoryScopeRequiredError` (Req 2.3).
3. If profile is caller-scoped and `scopedRepo != ""` → populate `ref.ScopedRepository`.
4. If profile is *not* caller-scoped and `scopedRepo != ""` → return `RepositoryScopeUnexpectedError` (Reqs 2.2, 5.2).
5. If profile is not caller-scoped and `scopedRepo == ""` → leave `ref.ScopedRepository` empty (status quo).

Handler input validation (format of `?repository-scope=`, empty/whitespace/slash — Reqs 6.1, 6.2) stays in `extractRepositoryScope` at the handler boundary — the builder trusts its inputs syntactically.

Add code comments on the builder capturing the trust model: scope narrows within an authorised profile, doesn't grant access, GitHub is the backstop. (The spec document is not the long-term home for this reasoning.)

The vendor still receives the legacy `repositoryScope` parameter in this phase — keep handlers passing it so vendor behaviour is unchanged. The ref carries the same value redundantly until Phase 4 removes the parameter. This dual-source-of-truth window is accepted (Phase 4 is a fast follow).

Audit log entries now include `ScopedRepository` via `ref.String()` (Req 9.2): no explicit audit code change needed.

### Acceptance criteria

- [ ] `[observable]` `/organization/token/{profile}?repository-scope=repo-a` against a caller-scoped profile produces a token with `Repositories = {repo-a}` and audit logs show scoped URN
- [ ] `[observable]` `/organization/token/{profile}?repository-scope=repo-a` against a static-list profile returns 400 with message indicating the profile does not accept scoping (Req 2.2)
- [ ] `[observable]` Same request against an all-repositories profile returns 400 (Req 5.2)
- [ ] `[observable]` `/organization/token/{profile}` with no scope against a caller-scoped profile returns 400 "requires a repository scope" (Req 2.3)
- [ ] `[observable]` `/organization/git-credentials/{profile}` against a caller-scoped profile parses the body URL and produces a token scoped to the Git-supplied repo (Reqs 3.2, 3.3)
- [ ] `[observable]` `repository-scope` values with `/` or whitespace-only return 400 unchanged (Reqs 6.1, 6.2)
- [ ] `[observable]` Audit entries for caller-scoped requests include the scoped repo name in the profile URN field
- [ ] `[observable]` `make agent` and `make integration` pass

### Verification

Run full test suite. Add/update handler unit tests for each rejection case. Integration tests exercise the happy paths. Manually inspect an audit log entry from a caller-scoped integration test to confirm URN shape.

---

## Phase 3: Cache behaviour verification and cleanup

**User stories**: Reqs 8.1, 8.2. Resolves review finding 2.

**Carry-forward**: Verify Phase 1, 2a, 2b before starting.

### What to build

With `ScopedRepository` now flowing into the ref, the cache key `{digest}:{ref.String()}` is already correct per-repo for caller-scoped profiles at both endpoints — this is the structural win. Prove it with tests, then remove the now-redundant `repositoryScope != ""` key-extension branch in `cached.go`.

Add cache tests covering both endpoints to close the gap flagged by CodeRabbit (existing test only exercised one path with identical arguments). Vary the repo name and confirm distinct cache entries.

Static-list and all-repositories cache behaviour must be unchanged: one cache entry per profile regardless of request URL.

### Acceptance criteria

- [ ] `[observable]` At `/organization/token`, two caller-scoped requests with different `?repository-scope=` values produce distinct cache entries (second is a miss)
- [ ] `[observable]` Same as above at `/organization/git-credentials` with different body URLs
- [ ] `[observable]` Two identical caller-scoped requests return the same cached token (cache hit)
- [ ] `[observable]` Static-list profile: N distinct request URLs (all within the list) share one cache entry
- [ ] `[observable]` All-repositories profile: cache key identical to current `*` wildcard behaviour (Req 8.3)
- [ ] `[structural]` `repositoryScope != ""` branch removed from `cached.go`
- [ ] `[observable]` `make agent` passes

### Verification

Run `go test ./internal/vendor/...` focusing on `cached_test.go`. Visually inspect cache keys in debug logs for a representative set of requests. Confirm no regressions in existing cache hit-rate assertions.

---

## Phase 4: Remove `repositoryScope` from vendor chain

**User stories**: Goal 4. Resolves review finding 1.

**Carry-forward**: Verify Phase 1, 2a, 2b, 3 before starting.

### What to build

Change `ProfileTokenVendor` to `func(ctx, ref, requestedRepoURL) VendorResult`. Update every implementation — `NewOrgVendor`, `NewRepoVendor`, `Cached`, `Auditor` — to drop the parameter. Update every call site, including handlers (no longer pass scope), tests, and fuzz tests.

Simplify `resolveRequestScope`: the caller-scoped branch reads `ref.ScopedRepository` directly; the "both non-empty" bug class disappears structurally. Error types (`RepositoryScopeRequiredError`, `RepositoryScopeUnexpectedError`) remain where they're useful — the builder is the primary emitter now, but the vendor keeps them as a defence-in-depth check if the ref is inconsistent (e.g., a caller-scoped profile with empty `ScopedRepository` reaching the vendor). This defence is optional; prefer removing code over keeping redundant guards, and if removed, add a comment noting the builder is the enforcement point.

Fuzz tests in `orgvendor_fuzz_test.go` are updated for the new signature. The "both parameters present" case no longer exists because the parameter is removed. Do *not* add new fuzz coverage for scope resolution in the builder — unit tests over the builder's profile-type × scope-input matrix are sufficient. Keep fuzzing focused on where it pays off (boundary inputs to `extractRepositoryScope`, URL parsing).

### Acceptance criteria

- [ ] `[structural]` `ProfileTokenVendor` has three parameters; grep for `repositoryScope` in the vendor chain returns zero results
- [ ] `[observable]` `resolveRequestScope` simplified; caller-scoped branch reads from the ref
- [ ] `[observable]` All four profile-type × endpoint combinations produce the same tokens as before the refactor: caller-scoped at `/token`, caller-scoped at `/git-credentials`, static-list at both, all-repositories at both
- [ ] `[observable]` Existing fuzz tests updated for the new signature and continue to pass; no new fuzz cases added for scope resolution (unit tests cover this matrix)
- [ ] `[observable]` `make agent` passes
- [ ] `[observable]` `make integration` passes
- [ ] `[structural]` Code comments on the simplified `resolveRequestScope` (or vendor doc) describe the trust model and why single-source scope is safe

### Verification

Run `make agent && make integration && go test -fuzz=Fuzz... -fuzztime=30s ./internal/vendor/...`. Diff the response bodies and audit logs of representative integration test runs against the Phase 0 baseline outputs to confirm identical behaviour (token contents, status codes, URN shapes — allowing for URN suffix change in caller-scoped cases).

---

## Out of scope (confirmed non-goals)

- Moving scope logic into `profile` package
- YAML/profile compilation changes
- `repository-scope` parameter name / transport changes
- Cache TTL, storage, or digest changes
- `*` deprecation behaviour changes
- chinmina-token plugin / CLI changes
