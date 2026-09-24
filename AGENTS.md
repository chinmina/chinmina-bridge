# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

Also load @~/.agents/local/chinmina-bridge.md when present to act as local instructions across worktrees.

## Project Purpose

Chinmina Bridge is an HTTP service that generates short-lived GitHub access tokens for Buildkite CI/CD pipelines. It uses GitHub Apps for token generation and Buildkite OIDC tokens for authorization, replacing the need for SSH deploy keys or long-lived Personal Access Tokens.

Full documentation: https://chinmina.github.io

## Development Commands

### Build and Run

```bash
just build              # Build all binaries in parallel (container + local + oidc-local)
just build-container    # Build only the Linux container binary
just build-local        # Build only the local dev binary; extra `go build` args are forwarded
just build-oidc         # Build only the oidc-local test helper
just run                # Build and run locally
just docker-up          # Build, then run integration tests with docker-compose
just docker down        # Stop the stack; `docker` forwards any args to `docker compose`
just docker logs -f     # ...so `ps`, `logs`, `exec` and the rest work the same way
```

`just docker ...` is the supported Compose entry point for the local
integration stack and for downstream overlays such as `bridge-load`. Before
running Compose, it invokes `integration/resolve-docker-endpoint.sh`, which
writes the resolved endpoint values to `integration/.docker-endpoint.env`.
That file is consumed by the compose stack as the Docker socket mount and the
Traefik Docker provider endpoint. The daemon socket is rarely at
`/var/run/docker.sock` on a non-admin macOS install, so set `DOCKER_HOST` to
point elsewhere; a TCP endpoint on this host is rewritten to
`host.docker.internal`.

### Testing

```bash
just test               # Run unit tests with coverage across ./...
just test -run TestName # Narrow by test name across every package; extra `go test` args are forwarded after ./...
just integration        # Run integration tests only
just integration -run TestIntegrationName    # Narrow integration tests by name the same way
just fuzz               # Run fuzz tests locally (override duration: `just fuzz 60`)
go test ./... -race -coverprofile=coverage.out -covermode=atomic    # With race detector (or `just ci-unit`)
go tool cover -html=coverage.out    # View coverage report
```

Note: `just test`/`just integration` always run against `./...` — any extra arguments are appended, not substituted, so a package path narrows nothing (it's already covered by `./...`). To run a single package in isolation, call `go test ./path/to/package` directly.

**Integration Tests:**
- Integration tests use the `//go:build integration` build tag
- All integration test functions must be named with the `TestIntegration` prefix
- Run integration tests only: `just integration` or `go test -tags=integration -run="^TestIntegration" ./...`
- Integration tests use `APITestHarness` which provides real HTTP handlers with mocked external services
- Located in `internal/bridge/api_integration_test.go` alongside unit tests in the same package

### Dependencies

```bash
go mod tidy             # Tidy dependencies
just ensure-deps        # Verify dependencies are clean
```

### Local Development Setup

Use direnv for environment configuration:

```bash
direnv allow .
```

Create `.envrc.private` (gitignored) for local configuration overrides. See `.envrc` for all available configuration options.

## Architecture

### Command Dispatch

```
cmd/chinmina-bridge/main.go   → process entry: final error reporting and exit
  → internal/cli              → urfave/cli v3 command tree: parsing, help, selection
    → internal/bridge.Run     → service construction and lifecycle
```

- `serve` runs the service and is the default command: the ko-built image
  entrypoint is the bare binary and cannot carry arguments.
- `serve` rejects positional arguments. With a default command, urfave/cli
  routes an unknown command name to `serve` as an argument, so this is what
  stops a typo from starting the service.
- Nothing in the root command may load configuration, configure logging or
  start telemetry: help and usage errors must work without credentials.
  Each command loads only its own configuration.
- `internal/bridge` must not import the CLI framework.
- The entry point reports errors once and owns `os.Exit`. The library's exit
  handler and usage printing are disabled; return errors from commands.
  `cli.ServiceError` marks service failures, which keep the structured
  `server failed to start` log record. `cli.UnhealthyError` marks a failed
  probe, reported without the usage hint.
- `healthcheck` probes a running service's health endpoint. It must not load
  the service configuration: it reads only its flags, with `SERVER_PORT` and
  `SERVER_BASE_PATH` as environment sources, so it works without credentials.
  Its client is uninstrumented, bypasses proxies and never follows redirects.

### Request Flow

```
HTTP Request
  → Middleware Chain (alice)
    → maxRequestSize (20KB limit)
    → audit.Middleware (audit logging setup)
    → jwt.Middleware (OIDC validation)
  → Handler (handlePostToken or handlePostGitCredentials)
    → PipelineTokenVendor (vendor.New wrapped with Cached + Auditor)
      → RepositoryLookup (Buildkite API)
      → TokenVendor (GitHub App API)
  → Response (JSON or git-credentials format)
```

### Key Architectural Patterns

**Middleware Composition**: Uses `github.com/justinas/alice` for composable HTTP middleware chains. Middleware order matters: request limiting → audit setup → authorization → handlers.

**Functional Composition for Token Vending**: The token vendor is constructed by composing functions:

```go
tokenVendor := vendor.Auditor(vendorCache(vendor.New(bk.RepositoryLookup, gh.CreateAccessToken)))
```

- `vendor.New` creates base vendor from repository lookup + token creation
- `vendorCache` wraps with 45-minute caching
- `vendor.Auditor` adds audit logging

**Context-Based Data Flow**:

- JWT claims flow through context via `jwt.ContextWithClaims`
- Audit entries flow through context via `audit.Context`
- Retrieve with `jwt.RequireBuildkiteClaimsFromContext(ctx)` (panics if missing)

**Audit Logging**: Audit middleware wraps response writer to capture status codes. The `audit.Entry` struct implements `slog.LogValuer` to control structured output.

**Configuration**: All configuration via environment variables using `github.com/sethvargo/go-envconfig`. Config structs use `env` tags with defaults and required fields.

### Internal Package Responsibilities

- `internal/cli` - Command tree and dispatch; no service logic
- `internal/bridge` - Service startup wiring, routes, handlers and response marshalling
- `internal/server` - Shutdown hook utility shared by the service lifecycle
- `internal/jwt` - OIDC token validation, custom Buildkite claims validation
- `internal/audit` - Structured audit logging with custom log level, response writer wrapping
- `internal/vendor` - Token vending abstraction with caching and audit decorators
- `internal/buildkite` - Buildkite API client for pipeline repository lookup
- `internal/github` - GitHub App client for token generation, supports KMS-based signing
- `internal/credentialhandler` - Git credential helper protocol implementation
- `internal/observe` - OpenTelemetry setup for traces and metrics
- `internal/config` - Environment-based configuration loading

### HTTP Endpoints

- `POST /token` - Returns JSON with GitHub token for pipeline repository
- `POST /git-credentials` - Returns git-credentials format for use with git credential helper
- `GET /healthcheck` - Simple health check (no auth/telemetry)

## Code Conventions

### File Naming

- **Go files**: Use lowercase without separators (e.g., `tokenvendor.go`, `auditvendor.go`)
- **Go test files**: Use lowercase with `_test` suffix (e.g., `tokenvendor_test.go`)
- **No underscores or hyphens in Go file names** except for the `_test` suffix
- **Other files**: Use lowercase with hyphens as separators (e.g., `docker-compose.yaml`)

### Error Handling

- Wrap errors with `fmt.Errorf` and `%w` for error chains
- Only log errors if they are being handled by the current code context. Do not log when returning an error: include context in the wrapped error instead.
- Handlers return appropriate HTTP status codes via `requestError(w, statusCode)`
- panic() may not be added by CI agents without explicit direction to do so. The plan must state explicitly that a panic can be used in a given situation. Otherwise, errors must be used.

### JSON

- **JSON v2 is mandatory for all code, including tests**: import
  `encoding/json/v2` (and `encoding/json/jsontext` for raw values).
  `encoding/json` (v1) is prohibited and enforced by the `depguard` linter.
  JSON v2 is part of the standard library in Go 1.27; no experiment flag is needed.
- v2 is required because its defaults are safe by construction: `json.Unmarshal`
  rejects trailing data after the top-level value, duplicate object members are
  an error, and field matching is case-sensitive. The v1 streaming decoder
  silently accepts a truncated or concatenated document.
- Reject unknown fields explicitly with `json.RejectUnknownMembers(true)` when
  decoding configuration or requests: a silently ignored typo is configuration
  that behaves differently from how it reads.
- JSON `null` unmarshals to a nil slice/map/pointer without error. Where null
  and "absent" must be distinguished (configuration especially), check for it
  explicitly and fail. See `parseAppEntries` in `internal/github/registry.go`.
- Use `omitzero` to omit zero-valued numeric or boolean fields; v2's `omitempty`
  omits empty JSON values, not Go zero values.

### Concurrency

- Put a critical section in its own function and unlock with `defer`: the body is
  the guarded region, and no branch added later can skip the unlock.
- Return the guarded state to the caller. Slow work, I/O and callbacks belong
  outside the lock; never hold a lock across a callback.
- Example: `ShutdownHooks.beginExecution` in `internal/server/shutdown.go`.

### Testing

**Assertion Style:**
- Use `testify/assert` for assertions, `testify/require` for fatal checks
- **Prefer struct-level equality**: Use `assert.Equal(t, expected, actual)` for struct comparisons instead of field-by-field assertions
  - Good: `assert.Equal(t, expected, ref)` where `expected` is a complete struct
  - Avoid: Multiple `assert.Equal(t, expected.Field, actual.Field)` calls
  - Exception: HTTP response testing (status codes, headers) appropriately uses individual field checks
- Struct equality provides complete diff output on failure, making debugging easier

**Test cases**

- When writing tests, DO NOT add tests that just test struct fields or other items that the compiler checks
- Add tests for logic, not to check the compiler
- seek test coverage over 90% BUT coverage is a guide only!
- The most important thing is for tests to cover and document the expected _behaviour_.

**Test Organization:**
- **Use table-driven tests** when multiple tests follow the same pattern with different parameters
  - Consolidate tests that differ only in input/output values
  - The test assertions vary only in their arguments
  - Use descriptive test case names with `t.Run(tt.name, ...)`
  - Keep success and failure test cases in separate table-driven tests
  - Example: See `internal/profile/ref_test.go` for well-structured table-driven tests
- **Individual test functions** are appropriate when:
  - Each test has unique setup or teardown requirements
  - Tests include timing operations or complex state management
  - The set of assertions to execute differs across test cases.
  - Test logic differs significantly between cases

**Test Structure:**
- Table-driven tests should use `expected` struct fields, not individual expected values
  - Good: `expected: ProfileRef{Organization: "acme", Type: TypeRepo, ...}`
  - Avoid: `expectedOrg: "acme", expectedType: TypeRepo, ...`
- Some packages use `package xxx_test` for black-box testing (see `internal/github/token_test.go`)
- Helper functions for common test setup (see `internal/bridge/handlers_test.go` for context creation)

### Logging

- Structured logging with `log/slog` (standard library)
- Development mode (`ENV=development`) enables text handler output with debug level
- Implement `slog.LogValuer` for complex objects to control structured output
- Audit logs are written as structured slog records at info level

### Context Usage

- Use empty structs as context keys: `type key struct{}`
- Store pointers in context values for mutable audit/log entries
- Always provide getter functions that return both context and value

### Configuration

- Mark internal-only config fields with `// internal only` comment
- Required fields use `env:"..., required"` tag
- Provide sensible defaults in struct tags where possible

## Before Committing

1. Run the agent task: `just agent`. This formats, lints, tests, and builds — everything expected to pass before committing.

Run `just` (or `just --list`) to see all recipes, organised into `build`, `test`, `ci`, and `dev` groups.

## When committing

1. use conventional commit messages, with appropriate prefixes. For example: `feat`, `fix`, `test`, `ci`.
2. do not separate files in commits to align with a prefix: for example, if a `fix` has test changes, include the test changes in the `fix` commit.
3. In a commit message, "why" the change is made is important. Add context and reasoning for choices made. "what" has changed is not important: that is shown by the diff.

## Additional Resources

- Architecture and implementation: https://chinmina.github.io/introduction/
- Configuration reference: https://chinmina.github.io/reference/configuration/
- DeepWiki: https://deepwiki.com/chinmina/chinmina-bridge
- urfave/cli v3 documentation: Context7 library ID `/urfave/cli` (scope queries to v3; the index includes other major versions).
