# AGENTS.md

Repository-specific guidance for coding agents. Keep this file focused on constraints and workflows that are not reliably inferred from the code or standard Go practice.

If `~/.agents/local/chinmina-bridge.md` exists, load it as additional local guidance. Do not fail if it is absent.

## Project

Chinmina Bridge is a Go HTTP service that exchanges Buildkite OIDC identity for short-lived, least-privilege GitHub App tokens. It supports pipeline and organization profiles, multiple GitHub Apps, optional distributed caching, and OpenTelemetry instrumentation.

User and operator documentation: <https://docs.chinmina.dev>

## Source of truth

Before changing behavior, inspect the implementation and adjacent tests. Prefer these sources over descriptions in this file:

- `justfile`: supported development and CI commands
- `mise.toml`: development and CI toolchain versions
- `go.mod`: Go version requirement and dependencies
- `.envrc`: local configuration variables
- `cmd/chinmina-bridge/main.go`: process entry, final error reporting, and exit
- `internal/cli`: command parsing and dispatch
- `internal/bridge`: service wiring, lifecycle, middleware, and HTTP routes
- `internal/config`: environment configuration
- `internal/profile`: profile loading, compilation, matching, and reloads
- `internal/vendor`: authorization, token vending, auditing, and caching
- `internal/github`, `internal/buildkite`, `internal/jwt`: external-service boundaries
- `internal/cache`: memory and Valkey cache implementations
- `internal/observe`: telemetry and profiling
- `internal/server`: shutdown behavior

Do not copy changing configuration or architecture details into this file when they are already clear in those sources.

## Workflow

Use the toolchain pinned in `mise.toml` and the `just` recipes. JSON v2 no longer needs an experiment flag.

```bash
just test                         # unit tests across ./...
just test -run TestName           # narrow by test name
just integration                  # integration-tagged TestIntegration* tests
just integration -run TestName    # narrow integration tests by name
just lint
just format
just build
just ensure-deps                  # after dependency changes
just agent                        # format, lint, unit tests, and build
```

`just test` and `just integration` always include `./...`; appended package paths do not narrow them. To test one package, run `go test ./path/to/package`.

Run the smallest relevant test while iterating, then run `just agent` before declaring the change complete. Run `just integration` when behavior crosses HTTP handlers, profiles, caches, or external-service adapters. Integration tests can require Docker/testcontainers.

Local runtime configuration belongs in the gitignored `.envrc.private`; never commit credentials. Use `direnv allow .` to load `.envrc`.

For the local Compose stack, use `just docker ...` rather than invoking Compose directly. It resolves the host Docker endpoint into `integration/.docker-endpoint.env`. Use `just docker-up` to build and start the stack.

## Required conventions

### JSON v2

All Go code, including tests, must use `encoding/json/v2` and, where needed, `encoding/json/jsontext`. The `depguard` linter prohibits `encoding/json` (v1), including in integration- and fuzz-tagged tests.

When decoding requests or configuration:

- reject unknown object members with `json.RejectUnknownMembers(true)`;
- explicitly reject `null` where it must differ from an absent value; and
- preserve JSON v2's strict handling of duplicate members and trailing data.

Use `omitzero` to omit zero-valued numeric or boolean fields; v2's `omitempty` omits empty JSON values, not Go zero values.

### Errors, logging, and safety

- Wrap returned errors with useful context using `fmt.Errorf(... %w ...)`.
- Do not log an error and return it; log only where the error is handled.
- Do not introduce `panic` unless the task or an approved plan explicitly calls for it.
- Preserve middleware order and audit behavior when changing request handling.
- Do not expose tokens, private keys, OIDC assertions, or other credentials in logs, errors, tests, or fixtures.

### CLI boundaries

- Keep configuration, logging, and telemetry initialization out of the root command so help and usage errors work without credentials. Each command loads only its own configuration.
- `serve` is the default for bare-binary image entrypoints. Preserve rejection of positional arguments so unknown command names cannot silently start the service.
- `internal/bridge` must not import the CLI framework.
- The process entry point owns error reporting and `os.Exit`; commands return errors. Preserve `cli.ServiceError` and `cli.UnhealthyError` reporting semantics and keep the library's exit handler and usage printing disabled.
- `healthcheck` must not load service configuration or require credentials. Its HTTP client is uninstrumented, bypasses proxies, and never follows redirects.

### Concurrency

Keep lock-protected regions in small functions and `defer` the unlock. Return the protected state, then perform I/O, slow work, and callbacks after releasing the lock. See `internal/server/shutdown.go` for the established pattern.

### Tests

- Test observable behavior and failure modes, not compiler-enforced structure.
- Use table-driven tests when cases share setup and assertions; keep materially different workflows separate.
- Keep success and failure tables separate when that improves clarity.
- Use `testify/assert` for non-fatal checks and `testify/require` for prerequisites.
- Prefer equality on complete expected structs over field-by-field assertions. HTTP status and header assertions are a reasonable exception.
- Name integration tests `TestIntegration...` and compile them with the `integration` build tag.
- Follow the package style of adjacent tests (`package x` versus `package x_test`).

### Naming and dependencies

- Go filenames are lowercase without separators except the required `_test.go` suffix.
- Non-Go filenames use lowercase words separated by hyphens where practical.
- After dependency changes, run `go mod tidy` and `just ensure-deps`.

## Change discipline

- Keep changes scoped; do not refactor unrelated code or update generated artifacts without need.
- Preserve public behavior unless the task explicitly changes it.
- Update tests and relevant documentation with behavior or configuration changes.
- If committing, use a conventional commit prefix such as `feat`, `fix`, `test`, `docs`, or `ci`. Keep implementation and its tests in the same commit, and explain why the change is needed.
