# Plan: Migrate build tooling from `make` to `just`

> Source PRD: none — ad-hoc requirements supplied directly in chat (2026-07-20), normalized to EARS below.

## Normalization notes

- Original: "Replace Makefile with justfile, retaining general similarity to current surface (build, run, test, docker, docker-down, ensure-deps, agent targets etc.)" -> `R1`
- Original: "the `test` target to take `go test` parameters so an agent can narrow the test target but still have core things like GOEXPERIMENT set properly" -> `R2`
- Original: "same with build" -> `R3`
- Original: "jamestelfer/boxed has some good patterns for enabling just in CI" -> `R4`
- Original: "some other tools I have ... already use this tool" (imds-broker, kms-import, bridge-load) -> `R5`
- Original: "This needs to be done on a feature branch" -> `R6`
- Implied by "convert ... to use just **instead of** make" (not stated verbatim, confirmed as intent rather than a leftover dual-toolchain) -> `R7`

| ID | EARS requirement |
|---|---|
| R1 | The system shall provide a `justfile` with a recipe equivalent to every current Makefile target (`mod`, `format`, `lint`, `test`, `integration`, `fuzz`, `ci-unit`, `ci-integration`, `ci-fuzz`, `build`, `run`, `agent`, `docker`, `docker-down`, `ensure-deps`, `keygen`), preserving each target's existing external behaviour (flags, coverage output, environment). |
| R2 | When a developer invokes `just test` with additional arguments, the system shall forward those arguments to `go test` while still applying `GOEXPERIMENT=jsonv2` and the default coverage flags. |
| R3 | When a developer invokes `just build-local` with additional arguments, the system shall forward those arguments to the `go build` invocation for the local development binary, while the full `just build` recipe continues to produce all three current build artifacts unconditionally and without argument forwarding. |
| R4 | The GitHub Actions verification workflow shall invoke `just` targets instead of `make` targets, with the `just` binary version-pinned via `mise` and provisioned in CI via `mise`'s own cached install mechanism, consistent with the CI enablement approach explored in `jamestelfer/boxed`'s workflow (adapted after confirming `mise-action`'s cache, not `extractions/setup-just`, is what actually persists across runs). |
| R5 | The justfile's structure and conventions (default `--list` recipe, `*args` pass-through pattern, one-line recipe doc-comments) shall be consistent with the style already adopted in `jamestelfer/imds-broker`, `chinmina/kms-import`, and `chinmina/bridge-load`. |
| R6 | All work shall occur on a dedicated feature branch, never committed directly to `main`. |
| R7 | Once CI and local workflows are verified against the justfile, the `Makefile` shall be removed and all living documentation referencing `make` commands shall be updated to reference `just`. |

## Architectural decisions

Durable decisions that apply across all phases:

- **File**: `justfile` (lowercase) at the repo root, replacing `Makefile`.
- **Global env**: `export GOEXPERIMENT := "jsonv2"` declared once at the top of the justfile, mirroring the Makefile's `export GOEXPERIMENT := jsonv2` — applies to every recipe's invocation shell without repeating it per recipe.
- **Build recipe split** (resolves R3's ambiguity — confirmed with user): `build` keeps producing all three current artifacts (Linux container binary, `chinmina-bridge-local`, `oidc-local`) with no argument forwarding, so it stays safe to use unmodified wherever `make build` was relied on (CI, `agent`, `docker`). A new `build-local *args` recipe forwards `{{args}}` only to the `chinmina-bridge-local` `go build` invocation, for fast, narrowed local iteration.
- **Test/integration pass-through**: `test *args='./...'` and `integration *args='./...'` use just's variadic-parameter-with-default syntax so `just test` behaves exactly like today and `just test ./internal/jwt -run TestFoo` narrows scope. The CI-only recipes (`ci-unit`, `ci-integration`, `ci-fuzz`) stay fixed/argument-free so CI runs remain deterministic.
- **CI provisioning** (R4): add `just` to `mise.toml`'s `[tools]` table with a pinned version. In `.github/workflows/test.yaml`, the build-matrix job adds `jdx/mise-action` with `install_args: just`, matching how the existing `golangci` job already installs `golangci-lint` — this reuses the same `actions/cache`-backed cross-run cache mise-action already wires up (gated by `cache_save`), rather than adding a second, separate provisioning path.
  - Investigated `jamestelfer/boxed`'s literal pattern (`mise-action install:false` + `extractions/setup-just`) and deliberately deviated from it: `extractions/setup-just` delegates to `extractions/setup-crate`, which uses `@actions/tool-cache` — on GitHub-hosted runners each job is a fresh VM, so this **never persists across runs**, it just does a one-shot download from casey/just's GitHub releases every time. mise's registry resolves `just` via the same upstream releases (`aqua:casey/just` backend), but `mise-action`'s cache **does** persist across runs via `actions/cache`. Running both would mean paying for a redundant fetch path with no cross-run benefit, so `extractions/setup-just` is dropped from this plan.
- **Branch**: this work happens on the `adopt-just` branch (renamed from the worktree's auto-generated name; no divergence from `main` yet), satisfying R6.
- **Sequencing for safety**: the Makefile is *not* deleted until Phase 3, after CI has been proven green using `just`. This keeps `make` as a working fallback while the justfile and CI wiring are still being validated, rather than a single big-bang cutover that could leave the feature branch's own CI broken mid-migration.
- **Out of scope**: `docs/superpowers/plans/*.md` are dated historical records referencing `make agent` — these are not living docs and are not updated.

## P0 baseline and standard quality gate

- [ ] Standard commands: `make agent` (build + format + test + lint) and `make integration` (pre-migration); `just agent` and `just integration` (from Phase 1 onward).
- [ ] Run `make agent` and `make integration` on the current commit as the P0 baseline; both must pass before Phase 1 starts.
- [ ] If P0 fails, fix/stabilize before starting Phase 1.
- [ ] Re-run the current phase's equivalent command set before marking each phase complete.

---

## Phase 1: Author the justfile (local parity + pass-through args)

**EARS requirements**: R1, R2, R3, R5

### Why this phase exists

This is the core deliverable: a justfile a developer or agent can use for every local workflow the Makefile currently supports, plus the two narrowing capabilities that motivated the migration. Landing it without touching CI or deleting the Makefile keeps this phase's blast radius to "files only used when someone types `just`" — nothing else can regress.

### Locked decisions (non-negotiable)

- Every current Makefile target has a same-behaviour justfile recipe: `mod`, `format`, `lint`, `test`, `integration`, `fuzz`, `ci-unit`, `ci-integration`, `ci-fuzz`, `build`, `run`, `agent`, `docker`, `docker-down`, `ensure-deps`, `keygen`.
- `test *args='./...'` and `build`/`build-local *args` follow the shapes fixed in Architectural decisions above.
- `GOEXPERIMENT=jsonv2` is set once, globally, not per-recipe.
- A `default` recipe (`@just --list`) is present, matching the sibling repos' convention.
- The `Makefile` is left in place and untouched in this phase.

### Flex zone (implementation choice allowed)

- Whether `run` depends on `build` (full parity, slower) or `build-local` (faster iteration) — recommend `build-local` for speed since `run` only ever executes the local binary, but this is reversible and not load-bearing.
- Recipe body style (e.g., a bash script block with a loop for the five `fuzz`/`ci-fuzz` package invocations vs. five repeated lines) — either is fine as long as output/behaviour is unchanged.
- Use of `[private]` attribute for any internal helper recipe, if one emerges.
- Exact one-line doc-comment wording per recipe.

### End-to-end behaviour to implement

A contributor or agent can run `just <target>` for anything they'd currently run `make <target>` for, with identical results, plus `just test <extra args>` and `just build-local <extra args>` for narrowed local runs.

### Acceptance criteria

- [ ] `[observable]` `just --list` shows every recipe with a one-line description; the set matches the current Makefile target list (`build-local` is the one addition).
- [ ] `[observable]` `just test` and `make test` produce the same pass/fail result and coverage percentage on the same commit.
- [ ] `[observable]` `just test ./internal/jwt -run TestSomething` (or similar) runs only the narrowed scope, and a jsonv2-dependent test still passes, confirming `GOEXPERIMENT=jsonv2` propagated into the recipe's shell.
- [ ] `[observable]` `just build` produces `dist/chinmina-bridge`, `dist/chinmina-bridge-local`, and `dist/oidc-local`, matching `make build`'s artifacts (compare via `file dist/*` / `ls -la dist/`).
- [ ] `[observable]` `just build-local -v` builds only `dist/chinmina-bridge-local` and visibly forwards `-v` (verbose package list appears in output).
- [ ] `[structural]` `docker`, `docker-down`, `ensure-deps`, `keygen`, and `agent` recipes are reviewed line-by-line against their Makefile equivalents and match in shell logic.

### Verification

Run `make agent` and `just agent` back-to-back on the same commit and diff their output/exit codes; run `make integration` and `just integration` the same way; manually exercise `just test <args>` and `just build-local <args>` narrowing and inspect stdout for the forwarded flags taking effect.

### Regression watchpoints

- Codecov depends on `coverage.out`'s format/path from `ci-unit`/`ci-integration` — these recipes aren't touched by the pass-through work, but confirm their output is still byte-for-byte what codecov expects.
- Just's `export` semantics for variables differ subtly from Make's — confirm `GOEXPERIMENT` is actually visible inside a recipe's spawned shell (not just in `just`'s own evaluation context) before relying on it.

### Replan triggers

- The pinned/available `just` version doesn't support variadic-parameter defaults (`*args='./...'`) — fall back to a documented default inside the recipe body instead of the parameter signature.
- `GOEXPERIMENT` doesn't propagate into recipe shells without an explicit `set export` statement — add it and re-verify rather than proceeding with a silently-missing build flag.

---

## Phase 2: Enable `just` in CI

**EARS requirements**: R4

**Carry-forward**: Before starting, re-run `just agent` and `just integration` from Phase 1 to confirm no regressions before touching CI.

### Why this phase exists

A local-only justfile isn't a real migration — CI has to actually invoke it, or `make` and `just` silently drift apart. This phase adopts the CI enablement pattern already proven in `jamestelfer/boxed` and used across the sibling repos.

### Locked decisions (non-negotiable)

- `just` is added to `mise.toml`'s `[tools]` table with a pinned version.
- `.github/workflows/test.yaml`'s build-matrix job replaces `run: make ${{ matrix.make-target }}` with `jdx/mise-action` (`install_args: just`, mirroring the lint job's `install_args: golangci-lint`) followed by `run: just <target>`.
- The matrix's target values keep mapping 1:1 to `ci-unit`, `ci-integration`, `ci-fuzz`.
- No `extractions/setup-just` step — mise alone provisions `just` (see Architectural decisions for why this deviates from `jamestelfer/boxed`'s literal pattern).
- The `golangci` lint job is unaffected (it doesn't invoke `make` today, so it isn't in scope for R4); it may optionally gain `just` too later if `just lint` becomes the documented entry point, but that's not required for R4.

### Flex zone (implementation choice allowed)

- Whether the matrix's `make-target` key is renamed to `just-target` (cosmetic; either is fine) or left as-is to minimize diff noise.
- Whether `cache_save` on the build-matrix job's `mise-action` step follows the lint job's `${{ github.event_name != 'pull_request' }}` condition, or a simpler default.

### End-to-end behaviour to implement

Pushing a commit to the feature branch triggers the GitHub Actions "verification" workflow, whose unit/integration/fuzz matrix jobs provision `just` via `mise-action` (cached the same way `golangci-lint` already is) and run the equivalent `just` recipes, uploading coverage exactly as before.

### Acceptance criteria

- [ ] `[observable]` A push (or draft PR) on the feature branch shows the verification workflow's matrix jobs passing, with `just`'s resolved version visible in the job log.
- [ ] `[observable]` The Codecov check on that commit shows a coverage percentage (not "no coverage report found"), confirming `coverage.out` still lands where the upload step expects it.
- [ ] `[structural]` `mise.toml` has a pinned `just` version; no new external action was added to provision it.
- [ ] `[observable]` A second push (after the first) shows the `just` install step served from cache rather than re-fetching, confirming the cross-run cache is actually working.
- [ ] `[observable]` The `golangci` lint job still passes unmodified on the same run (regression check).

### Verification

Push the branch (or open/update a PR) and watch the Actions run to completion in the GitHub UI; compare the reported coverage % against the last `make`-based run on `main` for the same code to confirm no silent behaviour change.

### Regression watchpoints

- `FUZZING_CI_SECS` must still resolve to `10s` in CI (not fall back to the local `30s` default) — confirm the CI environment variable still reaches the `ci-fuzz` recipe the same way it reached `make ci-fuzz`.
- Removing/renaming the matrix key could silently break the `include:` mapping if not updated consistently across `matrix.type` and `matrix.make-target`/`matrix.just-target`.

### Replan triggers

- `mise-action` can't resolve/install `just` on the pinned version (e.g. aqua registry outage, unsupported platform) — fall back to `extractions/setup-just` or a direct install script before proceeding to Phase 3.
- CI run time or minutes regress noticeably versus the `make`-based baseline — investigate before committing to the new provisioning approach long-term.

---

## Phase 3: Cutover — remove the Makefile, update living docs

**EARS requirements**: R6, R7

**Carry-forward**: Before starting, confirm Phase 2's CI run is green on the latest commit — do not delete the fallback until the replacement has been proven end-to-end.

### Why this phase exists

Leaving both `Makefile` and `justfile` in place indefinitely defeats the point of migrating — contributors and agents would have two sources of truth that can silently drift. This phase completes the cutover the user asked for ("use `just` instead of `make`") and brings documentation in line.

### Locked decisions (non-negotiable)

- `Makefile` is deleted.
- `AGENTS.md`'s "Development Commands" and "Before Committing" sections are rewritten to reference `just` targets instead of `make` targets.
- No other living doc in the repo references a `make <target>` command afterward (`docs/superpowers/plans/*.md` is explicitly excluded — historical record, not living doc).

### Flex zone (implementation choice allowed)

- Whether to add a short note in `AGENTS.md` on why the project uses `just` (optional; low value, skip if it doesn't earn its place).
- Wording of the updated command comments.

### End-to-end behaviour to implement

A fresh clone of the repo has no `Makefile`; every documented dev command in `AGENTS.md` uses `just`; running `make agent` fails because there's no Makefile to fail gracefully — `just` is the only supported path.

### Acceptance criteria

- [ ] `[observable]` `make agent` fails with a "No such file or directory" / "No rule to make target" style error, confirming the Makefile is gone.
- [ ] `[observable]` `just agent` and `just integration` both pass on the feature branch's final commit.
- [ ] `[structural]` A repo-wide search for `make ` in living docs (excluding `docs/superpowers/plans/`) returns no dev-command references.
- [ ] `[observable]` The CI verification workflow is green on the final commit of the feature branch.

### Verification

Run `just agent` and `just integration` locally; run `grep -rn "make " AGENTS.md` and a repo-wide equivalent excluding the historical plans directory; confirm the CI check suite is green on the branch (via `gh pr checks` or the Actions UI) before considering the migration complete.

### Replan triggers

- Discovery of another consumer of the Makefile not yet accounted for (an internal tool, a Renovate `postUpgradeTask`, a downstream repo invoking `make` in this repo via automation) — if found, restore a thin compatibility shim rather than deleting outright, and re-plan the cutover.

---

## Requirements coverage matrix

| Requirement ID | Phase(s) | Notes |
|---|---|---|
| R1 | Phase 1, Phase 3 | Recipes land in Phase 1; Phase 3 removes the now-redundant Makefile they replaced. |
| R2 | Phase 1 | `test *args='./...'` with global `GOEXPERIMENT`. |
| R3 | Phase 1 | Resolved as `build` (full parity) + `build-local *args` (narrowed). |
| R4 | Phase 2 | mise-only provisioning (cache-backed); `extractions/setup-just` evaluated and dropped as redundant. |
| R5 | Phase 1 | Convention alignment with imds-broker / kms-import / bridge-load. |
| R6 | Architectural decisions (cross-cutting) | Satisfied by working on the `adopt-just` branch throughout. |
| R7 | Phase 3 | Makefile removal + doc updates, gated on Phase 2's CI proof. |
