# Plan: Multiple GitHub App Association

> Source PRD: `docs/prd-github-app-association.md`, implementation direction in
> `docs/github-app-association.design-notes.md`

## Architectural decisions

Durable decisions that apply across all phases:

- **Config**: `GITHUB_APPS` is the only new environment variable — a JSON array of
  named app entries (`name`, `appId`, `installationId`, exactly one of
  `privateKey`/`privateKeyArn`). Existing `GITHUB_APP_*` variables remain the
  default app, unchanged.
- **Registry**: lives in `internal/github`, built once at startup, immutable
  thereafter (value receivers over an unexported map). Lookup by name returns
  not-found for a disabled app — enabled state is exposed only for logging, so
  no caller can accidentally resolve a disabled app by forgetting to check a
  flag.
- **Two entry types**: a configuration entry (name, application ID,
  installation ID, key source — implements `slog.LogValuer`, never logs key
  material) and a resolved entry (verification results, no key material).
- **Same-organization verification**: the default app's installation account ID
  is the reference; every registry app's account ID is queried concurrently and
  compared by account ID (not login — logins are renameable and claimable).
- **Disabled is terminal until restart** — no background re-verification, no hot
  registry reload.
- **Resolution point**: an app name resolves to an identity (name, application
  ID, installation ID) once, in the profile resolver at the handler boundary —
  never inside the `Vending` stage of the chain, because `Cached` short-circuits
  on a hit before `Vending` runs. This is the single guard that prevents a
  cache hit from serving a token through an app that has since been disabled.
- **Cache key**: `digest:applicationID:installationID:profileURN`. Deploying
  this changes the key format for the default app too — every existing cache
  entry is orphaned once, accepted as a one-time cold cache.
- **No sensitive data in any observable surface, in any phase.** No private key,
  no private key ARN, and no other secret ever appears in a log line, error
  message, audit entry, trace span, or HTTP response, in this feature or in any
  phase that touches logging. This is a standing constraint on every phase
  below, not just the registry phase.
- **Service boundary**: the service records what it decided and when; it does
  not snapshot or cross-check external state (GitHub App permissions,
  installation repository selection) that it neither owns nor rechecks.

## Normalization notes

The PRD's requirements are already written in EARS syntax and numbered 1–57 in
the source document. They are referenced directly here as `R1`–`R57` with no
rewording; no separate traceability mapping is needed.

## Suggested PR grouping

Phases are the planning/acceptance-criteria unit; PRs may combine phases where
they are not independently shippable:

- **PR 1** — Phase 1 (edge-triggered invalid-profile logging)
- **PR 2** — Phase 2 (shutdown hooks on every startup exit path)
- **PR 3** — Phase 3 (startup gate)
- **PR 4** — Phase 4 (config-validation/route-construction split, transport
  ordering)
- **PR 5** — Phases 5–7 combined (registry; profile schema, resolution,
  cache-safe vending, response/audit attribution; span attributes for profile
  counts) — combined because Phase 6 cannot exist without Phase 5's registry,
  and Phase 7 is a small addition once Phase 6's compilation changes land.
- **PR 6** — Phase 8 (`.envrc` documentation only — R51). Reqs 52–57 are
  out of scope for this repository; they are published from the separate
  `chinmina.github.io` documentation repository.

Phases 1–4 are independent of `GITHUB_APPS` entirely and can land in any order
relative to each other, ahead of the feature itself.

## P0 baseline and standard quality gate

- [ ] `just agent` (format, lint, test, build) — run before Phase 1; must pass
- [ ] If it fails, stabilize before starting Phase 1
- [ ] Re-run `just agent` before marking each phase complete
- [ ] `just test`, `just integration`, and (where a phase changes concurrent or
      timing-sensitive code) `go test ./... -race` are part of "must pass" for
      the phases that touch those areas

---

## Phase 1: Edge-triggered invalid-profile logging; `ProfileUnavailableError` carries its cause

**EARS requirements**: R28, R44 (foundation — full audit-entry wiring lands in
Phase 6)

### Why this phase exists

Compilation logs its batched invalid-profile warning on every compile, and
compilation runs on every refresh — so today, one permanently-invalid profile
(for any existing reason, e.g. a bad match rule) produces a warning every
refresh interval for the life of the process. This is worth fixing on its own,
and it becomes load-bearing once app-caused invalidity exists in Phase 6:
`ProfileUnavailableError` currently discards its cause, and once logging is
edge-triggered, the audit entry becomes the only timely record of *why* a
profile is invalid.

### Locked decisions (non-negotiable)

- The comparison lives in the profile store (`ProfileStoreOf`) — the only
  component holding both the old and new generation, already under a write
  lock.
- Diff the profile-name-to-reason mapping, not just the set of invalid names —
  a profile whose reason changes must be logged again.
- Diff on the mapping, not the digest — an unchanged YAML whose validity flips
  must still be caught; the store update runs even when the digest is
  unchanged.
- `ProfileUnavailableError` gains its wrapped cause without changing the
  caller-facing message or HTTP behavior it already produces.
- No sensitive data enters the logged reason string.

### Flex zone (implementation choice allowed)

- Exact diffing data structure (map vs. sorted slice comparison).
- Whether the cause is exposed via `Unwrap()` or a dedicated accessor.
- Log level and field layout for the batched warning.

### End-to-end behaviour to implement

Two successive profile refreshes with the same invalid profile (same name,
same reason) log the warning once, not twice. A refresh whose invalid set or
reasons change logs again. `ProfileUnavailableError` retains its cause
internally even though the HTTP response and caller-facing message are
unchanged.

### Acceptance criteria

- [ ] `[observable]` A profile invalid for the same reason across two
      consecutive refreshes produces exactly one warning log line.
- [ ] `[observable]` A profile whose invalidity reason changes between
      refreshes (same name, different cause) produces a new warning log line.
- [ ] `[observable]` A profile that becomes valid, then invalid again, is
      logged again (not permanently suppressed).
- [ ] `[structural]` `ProfileUnavailableError` exposes its wrapped cause
      without changing the string returned to callers.
- [ ] `[structural]` Existing 404 behavior and caller-facing message for an
      unavailable profile are unchanged.

### Verification

`just test` on `internal/profile`; a new table-driven test asserting log-call
counts across synthetic refresh sequences (unchanged invalid set → one log;
changed reason → second log).

### Regression watchpoints

Existing profile refresh tests (e.g.
`TestIntegrationProfileRefresh_ServesNoMixedGeneration`) must keep passing;
the *first* log of a newly-invalid profile must not be accidentally
suppressed.

### Replan triggers

If diffing by reason string proves unstable (e.g. a wrapped error's message
contains non-deterministic content), revisit the comparison key before
proceeding.

---

## Phase 2: Shutdown hooks run on every startup exit path

**EARS requirements**: R42

**Carry-forward**: re-verify Phase 1's refresh-logging behavior still passes
(`just test` on `internal/profile`).

### Why this phase exists

Shutdown hooks currently run only via `server.RegisterOnShutdown`, which fires
only when `server.Shutdown(ctx)` runs from the HTTP serving path. Any exit
before serving starts — a configuration failure today, or the startup gate
(Phase 3) and default-app verification failure (Phase 5) added later — discards
buffered telemetry describing the failure and leaks a distributed cache
connection per restart. Fixing this now means every later phase that adds a
new startup-exit path inherits correct behavior for free.

### Locked decisions (non-negotiable)

- Shutdown hooks execute exactly once, on whichever path exits — normal HTTP
  shutdown or a startup-time failure/exit.
- Execution is guarded so the two call sites (existing server-shutdown wiring,
  new startup-exit wiring) cannot double-execute hooks.

### Flex zone (implementation choice allowed)

- Mechanism: deferred wrapping of `main`/`launchServer`, a `sync.Once` guard,
  or explicit calls at each known exit point.

### End-to-end behaviour to implement

If the server exits during startup, before `serveHTTP` begins accepting
connections, registered shutdown hooks (telemetry flush, cache connection
close) still execute before the process exits.

### Acceptance criteria

- [ ] `[observable]` A simulated startup failure still runs shutdown hooks
      (telemetry flush / cache close), verified via test hook counters.
- [ ] `[observable]` A normal HTTP shutdown (SIGTERM after serving starts)
      still runs hooks exactly once — no double execution.
- [ ] `[structural]` Hook execution is guarded so no code path can run hooks
      twice.

### Verification

Unit test around `launchServer`/`main` exit paths, asserting hook-execution
counts under (a) a startup failure and (b) a normal shutdown.

### Replan triggers

If forcing a single shutdown-hook call site requires reshaping `main.go`'s
control flow more invasively than expected, fall back to explicit calls at
each known exit point instead of one wrapper.

---

## Phase 3: Startup gate — don't accept connections until first profile generation loads

**EARS requirements**: R40, R41

**Carry-forward**: re-verify Phases 1–2 (`just test` on `internal/profile`;
the shutdown-hook test from Phase 2).

### Why this phase exists

Until a profile generation has loaded, the service has no configuration to
serve. Today it accepts connections immediately and serves
`NewDefaultProfiles()` (one hardcoded pipeline profile) in the meantime —
during a rolling deployment this looks healthy while silently answering
organization-profile requests with 404 and pipeline requests with an
unconfigured permission set. This is independent of app association and is
exactly what R40/R41 require.

### Locked decisions (non-negotiable)

- Not listening is the readiness signal; the healthcheck contract
  (`GET /healthcheck`, no auth/telemetry) is unchanged.
- The gate is a latch on the *first* load only — a service that has loaded a
  generation and later loses access to its source keeps serving what it has.
- `PeriodicRefresh` already performs its first load synchronously before its
  first interval-based refresh; the gate consumes that signal rather than
  issuing a second fetch.
- No timeout governs the gate — a hung upstream blocks startup, and the
  platform's own startup grace period is the backstop. R41's per-attempt log
  is the diagnostic.
- Applies only where an organization profile location is configured;
  deployments without one are unaffected.

### Flex zone (implementation choice allowed)

- Mechanism: synchronous first load followed by a refresh loop with a delayed
  start (preferred in the design notes) vs. a readiness channel — either is
  acceptable provided it is testable with synthetic time, matching how the
  refresh daemon is already tested.
- Exact insertion point in `main.go`/`configureServerRoutes`/`launchServer`.

### Open questions / risk burn-down

This couples startup to profile-source availability for existing deployments
using an organization profile location — a real behavior change. Confirmed
intentional per the PRD; Phase 8's documentation should call it out so it
isn't mistaken for a regression during rollout.

### End-to-end behaviour to implement

A service configured with an organization profile location does not accept
connections until the first profile generation has loaded; each failed load
attempt while waiting is logged. A service with no organization profile
location is unaffected.

### Acceptance criteria

- [ ] `[observable]` With a reachable profile source, the service does not
      open its listening port until the first generation loads (gate
      extracted as a function, exercised with synthetic time).
- [ ] `[observable]` While waiting, each failed load attempt is logged.
- [ ] `[observable]` A service with no organization profile location starts
      and serves immediately, with no gate-related delay or log lines.
- [ ] `[structural]` The gate reads only the refresh daemon's first-load
      signal; no duplicate fetch is issued at boot.
- [ ] `[observable]` Once a generation has loaded, later loss of access to the
      profile source does not stop the service serving the generation it has.

### Verification

`just test` on `internal/profile` (gate function tested with synthetic time);
since the integration harness constructs routes directly rather than booting
the server, the extracted-function unit test is the primary coverage for this
phase — call this out explicitly rather than relying on integration coverage
that doesn't reach it.

### Regression watchpoints

Healthcheck must remain reachable and unaffected by gate semantics; existing
refresh tests must keep passing.

### Replan triggers

If the harness's route-construction-without-booting approach means the gate
genuinely cannot be exercised even via the extracted function, flag this
before considering the phase done — an untested gate is a defect, not a
completed phase.

---

## Phase 4: Split configuration validation from route construction; fix transport ordering

**EARS requirements**: none directly — structural prerequisite for Phase 5's
registry construction.

**Carry-forward**: re-verify Phases 1–3 (`just test`, `just integration`).

### Why this phase exists

Pure prerequisite plumbing with no user-visible behavior change today — with a
single app, there is no observable difference yet. It exists as its own phase
because the registry (Phase 5) needs it to be correct: the registry must be
constructed *after* `http.DefaultTransport` is replaced with the instrumented,
pool-tuned transport, or registry traffic (installation-verification queries)
is silently untraced and untuned. All offline validation should complete
before any GitHub network call, so a configuration error is reported
immediately rather than behind a network phase that hasn't run yet.

### Locked decisions (non-negotiable)

- Offline configuration validation completes fully before any GitHub network
  call is attempted.
- `http.DefaultTransport` is replaced with the tuned/instrumented transport
  before any GitHub client (including the future registry's clients) is
  constructed.
- Routes are built only after all upstream clients exist, so no handler
  captures a client that is later mutated.

### Flex zone (implementation choice allowed)

- Exact function boundaries inside `main.go`/`configureServerRoutes`/
  `launchServer` used to express the ordering.

### End-to-end behaviour to implement

No externally observable change for single-app deployments; this phase is
verified structurally and by absence of regressions, and unblocks Phase 5.

### Acceptance criteria

- [ ] `[structural]` All offline configuration validation completes before any
      function that could make a GitHub network call is invoked.
- [ ] `[structural]` `http.DefaultTransport` is replaced before any GitHub
      client is constructed (verified by reading call order).
- [ ] `[observable]` Existing single-app startup and request-serving behavior
      is unchanged — full existing test suite passes unmodified.

### Verification

`just test`, `just integration`, `just docker` — full existing suite passes
with zero behavior change.

### Regression watchpoints

Any configuration currently validated lazily (on first use) must keep the
same error semantics if moved earlier — same error, just sooner, never a new
failure mode.

### Replan triggers

If current validation is more deeply interleaved with route construction than
expected, scope the split down rather than forcing an artificial separation
that risks destabilizing unrelated startup code.

---

## Phase 5: Registry — config parsing, fail-fast validation, concurrent org verification, redacted startup logging

**EARS requirements**: R1–R19, R48–R50

**Carry-forward**: re-verify Phase 4 (`just test`, `just integration`) — this
phase builds directly on its ordering guarantees.

### Why this phase exists

This is where `GITHUB_APPS` first exists. An operator declares named GitHub
Apps in deployment configuration; the service builds a client per entry,
verifies each shares the default app's organization, and disables (rather than
crashes on) an app whose installation can't be reached — while a failure to
verify the default app itself is fatal, since the service can't authenticate
as itself.

### Locked decisions (non-negotiable)

- `GITHUB_APPS` is the only new env var (R1); default app config is unchanged.
- Registry entries: name, application ID, installation ID, exactly one of
  private key or private key ARN (R4, R6, R7).
- Fail-fast (deploy-blocking, deterministic) on: malformed JSON or an
  unrecognised field (R5); missing or duplicate key source (R6, R7); duplicate
  name (R8); name `default` (R9); name failing
  `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$` or exceeding 64 characters (R10);
  non-positive application/installation ID (R11); unparseable private key or
  unconstructable GitHub client (R15).
- Verification: default app's installation account ID is the reference; every
  registry app's account ID is queried concurrently alongside it (R12, R13),
  compared by account ID, not login.
- An app on a different account is disabled, not fatal (R14). An app whose
  installation query fails is disabled; the service continues starting (R16).
  The default app's installation query failing is fatal — non-zero exit (R17).
- Disabled is terminal until process restart (R18).
- No registry configured → zero installation queries at startup (R19).
- Registry is built once, immutable thereafter (value receivers over an
  unexported map). Lookup by name returns not-found for a disabled app.
- Two entry types: a configuration entry (`slog.LogValuer` exposing only name,
  application ID, installation ID, key source — no key material) and a
  resolved entry (verification results, no key material) — this is how R48/R49
  hold by construction, not by vigilance.
- Configuration/verification error messages identify the faulty entry by name
  or index and never contain a substring of its private key or ARN (R50). This
  requires a deliberate, documented exception to the project's `%w`-wrapping
  convention on the key-parsing path, since a third-party library's error
  message is outside our control and may change on any dependency bump.
- The signing key must not capture a short-lived context: registry
  construction takes the long-lived server context; `createKMSSigningKey`
  takes a shared `aws.Config` (one credential resolution for all apps), and
  the signing call carries its own per-call context. Otherwise every mint
  using `privateKeyArn` fails with `context canceled` once the
  construction/verification-scoped context expires — a failure mode that only
  reproduces with ARN-based keys, never PEM, so it needs its own test.
- KMS key handling contacts nothing at construction; the first network call is
  the signing operation. So R15's scope is offline, deterministic failures
  only — every network-shaped failure (bad ARN, IAM denial, KMS outage) arrives
  on the verification path and is disabled under R16.
- No sensitive data in any log, error, or span this phase touches.

### Flex zone (implementation choice allowed)

- Internal registry data structure; exact function signatures for entry
  construction and verification.
- Worker-pool vs. unbounded-goroutine-with-`WaitGroup` for concurrent
  verification (realistic app counts make this a minor choice).

### Open questions / risk burn-down

The GitHub mock server (`testhelpers.MockGitHubServer`) currently exposes one
route that ignores the installation-ID path segment and returns one shared
status/token/counter. It must be extended to per-installation responses and
per-installation counters before any verification scenario (matching org,
different org, query failure) can be tested. This is infrastructure work
internal to this phase and blocks every acceptance criterion below — budget
for it explicitly rather than discovering it mid-phase.

### End-to-end behaviour to implement

An operator sets `GITHUB_APPS` with one or more named entries. On startup, the
service builds a client per entry, queries each installation's account
concurrently alongside the default app's, disables any entry on a different
account or with an unreachable installation, exits non-zero only if the
default app itself can't be verified, and logs each entry's name, application
ID, installation ID, verified organization, and enabled state — with no key
material. Malformed configuration fails startup before any network call.

### Acceptance criteria

- [ ] `[observable]` A well-formed `GITHUB_APPS` with all apps on the default
      app's account: service starts, all apps logged enabled.
- [ ] `[observable]` A registry app whose mocked installation resolves to a
      different account: service starts, that app logged disabled, others
      unaffected.
- [ ] `[observable]` A registry app whose mocked installation query fails:
      service starts, that app disabled, others unaffected.
- [ ] `[observable]` The default app's installation query failing: service
      exits non-zero.
- [ ] `[observable]` Each fail-fast configuration case (malformed JSON, unknown
      field, duplicate name, name `default`, name failing the pattern,
      both/neither key source, non-positive ID, unparseable key)
      independently prevents startup.
- [ ] `[structural]` No log line or error message emitted in this phase
      contains private key material or a private key ARN — asserted against
      the exact field set logged.
- [ ] `[observable]` With `GITHUB_APPS` unset, zero installation-endpoint calls
      are made at startup (assert on the mock's call counter).
- [ ] `[observable]` A registry constructed under a context that is later
      cancelled still mints tokens successfully afterward (ARN-based keys
      only — the signing-key-outlives-verification regression test).

### Verification

`just test` on `internal/github` — table-driven construction/validation
tests, then verification-outcome tests against the extended mock; the
context-cancellation mint test; `just integration` once the harness supports
multi-app config injection.

### Regression watchpoints

Existing single-app `internal/github` tests and the mock server's existing
single-route behavior must keep working unchanged for the no-`GITHUB_APPS`
path.

### Replan triggers

If extending the mock server for per-installation behavior needs a
significantly larger harness rework than expected, treat that as an explicit
sub-step with its own estimate before continuing into verification tests.

---

## Phase 6: Profile schema (`app`), resolution, cache-safe vending, response/audit attribution

**EARS requirements**: R20–R27, R29–R39, R43, R45, R46

**Carry-forward**: re-verify Phase 5 in full (`just test` on `internal/github`,
`just integration`) — this phase is the registry's first consumer.

### Why this phase exists

This is where the registry becomes usable: profiles can name an app, requests
resolve that name to an identity at the handler boundary, tokens mint through
the resolved installation, and every downstream surface — cache, response,
audit — reflects which app served the request. Resolution and the cache key
are inseparable: a resolved identity that isn't part of the cache key means a
cache hit can serve a token minted through an app that has since been
disabled, which is exactly what R36 forbids. Splitting this into two phases
would let one land in a state where that guarantee doesn't hold.

### Locked decisions (non-negotiable)

- Profile attributes stay pure data: `OrganizationProfileAttr`/
  `PipelineProfileAttr` gain the app *name* (string), never a live client
  (R20, R21).
- Normalize in compilation, not at the request boundary: an omitted `app` and
  an explicit `app: default` compile to the same attribute value, so they are
  indistinguishable downstream and produce identical audit attribution (R22,
  R23).
- The default pipeline profile always mints through the default app and has no
  `app` property (R24).
- Empty `app` string is invalid; a name absent from the registry is invalid; a
  name naming a disabled app is invalid (R25, R26, R27). Compilation asks the
  registry for its set of usable names — the same function the request path
  uses to resolve — so both share one enforcement point.
- The name resolves to an app identity (name, application ID, installation ID)
  at the handler boundary, in the profile resolver — never inside the
  `Vending` stage. The chain is Audit → Authorized → Cached → Vending, and
  `Cached` short-circuits on a hit before `Vending` runs, so a check inside
  `Vending` would never run on a cache hit. Resolving in the resolver makes
  that lookup the guard that runs on every request (R31; satisfies R36's
  final clause).
- A profile resolved but whose app cannot be resolved in the registry is a
  500, not a 403/404: reaching that state means compilation should already
  have invalidated the profile — the service's defect, not GitHub's denial,
  matching the shape of existing unresolved-scope guards (R36).
- The resolved identity is data (name, application ID, installation ID), not a
  closure — no credential is captured in a value that flows into a cache
  payload (R32).
- Compilation threads the registry's usable-names set through
  `FetchOrganizationProfile` → `load` → `compile`, *and* through
  `PeriodicRefresh` for the background refresh path — missing the background
  path is the specific failure Req 30 exists to prevent (profiles valid for
  one refresh interval, invalid after, unchanged digest, generation swap
  logging only at debug level).
- The organization profile configuration file is always retrieved through the
  default app, never a per-profile app (R34).
- The service does not check a requested repository's owner against the
  resolved app's organization — GitHub's installation boundary is the
  enforcement point (R35).
- Cache key becomes `digest:applicationID:installationID:profileURN` (R37).
  Two requests resolving the same profile/digest through different app
  identities must not share a cache entry (R38). The app an entry was minted
  through is recorded in the entry itself, so a cache hit and a cache miss
  return the same response shape (R39).
- No consistency check between the app recorded in a cache entry and the app
  implied by its key — a deliberate scope exclusion, covered by the cache-key
  test rather than a runtime check.
- Token response includes the minting app's name (R45); the audit entry
  records the resolved app's name at resolution time, so every downstream
  outcome — including failures — carries it (R43); the token cache outcome
  metric is attributed with the app name (R46).
- A profile invalid because its named app is disabled fails *before* an app is
  resolved, so its audit entry carries the invalidity reason from Phase 1
  (R44) rather than an app name — now load-bearing, since Phase 1's
  edge-triggered logging means the audit entry is the only timely record.
- Deploying this orphans every existing cache entry once (key format changes
  for the default app too) — accepted as a one-time cold cache.
- No sensitive data in any surface this phase touches.

### Flex zone (implementation choice allowed)

- Exact plumbing of the registry's usable-names set through the compilation
  call chain.
- Internal shape of the resolved identity value and where in the resolver it
  attaches to the resolved request value.

### Open questions / risk burn-down

Highest blast radius in this plan: it changes the cache key for every existing
deployment, touches the request-serving hot path, and a subtle placement
mistake (resolving inside `Vending` instead of the resolver) would silently
reintroduce the cache-bypass hazard. The single most important test in the
whole plan is: prime a cache entry, disable the app, repeat the request,
assert 500 and that the cached token was not served. This is the test that
fails if resolution is ever moved into the vendor chain — treat it as a gate
on this phase, not just one acceptance criterion among many.

### End-to-end behaviour to implement

An organization or named pipeline profile may declare `app: <name>`. A
request against such a profile resolves the name to an app identity, mints
its token through that app's installation, includes the app's name in the
response and audit entry, and caches the result under a key that includes the
app's identity. A profile naming a disabled or unknown app is invalid and
returns 404 with the reason on the audit entry. A previously cached token is
never served once its app becomes unresolvable.

### Acceptance criteria

- [ ] `[observable]` A request against a profile bound to a non-default
      registered app returns a token minted via that app's installation, with
      the app's name in the response body and the audit entry.
- [ ] `[observable]` A request against the default pipeline profile, and one
      against a profile with no `app` property, both mint through the default
      app.
- [ ] `[observable]` Two configurations differing only in the presence of
      `app: default` compile to equal profile attributes.
- [ ] `[observable]` A profile naming an unknown or disabled app is invalid;
      the request returns 404 with the reason on the audit entry; other
      profiles in the same configuration remain valid.
- [ ] `[observable]` Priming a cache entry, then making the registry unable to
      resolve that profile's app, then repeating the request: returns 500,
      and the previously cached token is not served.
- [ ] `[observable]` Two requests resolving the same profile/digest through two
      different app identities do not share a cache entry.
- [ ] `[observable]` A profile naming an enabled app remains valid across a
      background profile refresh.
- [ ] `[structural]` Resolution occurs in the profile resolver, not inside
      `Vending` (verified by the cache-bypass test above).

### Verification

`just test` on `internal/profile` and `internal/vendor`; `just integration`
for the end-to-end cases (request via second app, disabled-app 404,
cache-bypass 500); an integration test issuing parallel requests across two
apps under `go test -race`, guarding against future lazily-populated registry
state.

### Regression watchpoints

Single-app deployments (no `GITHUB_APPS`, no `app` properties) must behave
exactly as before — same cache behavior modulo the one-time cold cache, same
response shape, same audit shape (app name now always present, naming
"default"). Existing profile-compilation and vendor-chain tests must keep
passing.

### Replan triggers

If threading the registry's usable-names set through both the synchronous
load path and `PeriodicRefresh`'s background path needs a broader interface
change than expected, pause before Req 30's guarantee ends up only
half-implemented.

---

## Phase 7: Span attributes for valid/invalid profile counts

**EARS requirements**: R47

**Carry-forward**: re-verify Phase 6 (`just test` on `internal/profile`).

### Why this phase exists

Profile generation changes are already traced. Rather than a new metric that
would duplicate the trace, this adds valid/invalid counts (by profile type) to
the existing update span — the counts are the only part of profile state not
already observable, and they're what makes a partly-invalid generation
visible without scraping logs.

### Locked decisions (non-negotiable)

- Counts land on the existing profile-generation-update span, not a new metric
  or new span.
- Counts are broken down by profile type (organization vs. pipeline).

### Flex zone (implementation choice allowed)

- Attribute naming; exact point in the update path where counts are computed.

### End-to-end behaviour to implement

When the service updates the profile generation, the trace span for that
update carries the count of valid and invalid profiles, by type.

### Acceptance criteria

- [ ] `[observable]` A refresh producing a mix of valid/invalid organization
      and pipeline profiles produces a span with attributes reflecting the
      correct counts, by type.
- [ ] `[observable]` A refresh with everything valid shows zero on the invalid
      counts, not an absent attribute.
- [ ] `[structural]` No new metric series or new span is introduced.

### Verification

`just test` on `internal/profile`, asserting span attributes via the existing
tracing test utilities.

### Replan triggers

None expected — small, low-risk addition once Phase 6's compilation changes
exist.

---

## Phase 8: Documentation

**EARS requirements**: R51 (only requirement in scope for this repository)

**Carry-forward**: none — documentation-only phase.

### Why this phase exists

Reqs 52–57 describe operator-facing documentation published from the separate
`chinmina.github.io` documentation repository and are out of scope for a PR
here. Only R51 — the `.envrc` reference block — lives in this repository.

### Locked decisions (non-negotiable)

- `.envrc` (and `.development/.envrc`) document `GITHUB_APPS` with a commented
  example alongside the existing `GITHUB_APP_*` variables, following the
  existing `# required (one of)` / `# required` comment convention.
- R52–R57 are explicitly out of scope for this repository's PRs — tracked as
  follow-up work in the documentation site repository, not silently dropped.

### Flex zone (implementation choice allowed)

- Wording of the `.envrc` comment/example.

### End-to-end behaviour to implement

An operator reading `.envrc` sees a commented `GITHUB_APPS` example next to
the existing app variables.

### Acceptance criteria

- [ ] `[observable]` `.envrc` contains a commented `GITHUB_APPS` example
      matching the PRD's configuration shape.
- [ ] `[structural]` The example is valid JSON matching the registry entry
      schema from Phase 5 (name, appId, installationId, exactly one of
      privateKey/privateKeyArn).
- [ ] `[structural]` No change in this repository purports to satisfy
      R52–R57 — those are called out as external follow-ups.

### Verification

Manual review of `.envrc`; optionally, a small test parsing the commented
example (with the leading `#` stripped) against the registry's JSON schema so
it can't silently drift from Phase 5's actual accepted shape.

### Replan triggers

None.

---

## Requirements coverage matrix

| Requirement ID | Phase(s) | Notes |
|---|---|---|
| R1–R11 | Phase 5 | App registry configuration |
| R12–R19 | Phase 5 | Organization verification |
| R20–R27 | Phase 6 | Profile schema and compilation |
| R28 | Phase 1 | Edge-triggered invalid-profile logging |
| R29–R30 | Phase 6 | Invalid-profile request handling; refresh-path validity |
| R31–R36 | Phase 6 | Token vending, resolution and the cache-bypass guard |
| R37–R39 | Phase 6 | Caching |
| R40–R41 | Phase 3 | Startup gate |
| R42 | Phase 2 | Shutdown hooks on every exit path |
| R43 | Phase 6 | Audit entry records resolved app name |
| R44 | Phase 1, Phase 6 | Cause captured in Phase 1; wired into audit entry in Phase 6 |
| R45–R46 | Phase 6 | Response and cache-metric attribution |
| R47 | Phase 7 | Span attributes for profile counts |
| R48–R50 | Phase 5 | Registry logging and redaction |
| R51 | Phase 8 | `.envrc` documentation (this repository) |
| R52–R57 | *(out of scope)* | Published from the separate documentation repository |
