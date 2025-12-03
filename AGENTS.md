# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Project Purpose

Chinmina Bridge is an HTTP service that generates short-lived GitHub access tokens for Buildkite CI/CD pipelines. It uses GitHub Apps for token generation and Buildkite OIDC tokens for authorization, replacing the need for SSH deploy keys or long-lived Personal Access Tokens.

Full documentation: https://chinmina.github.io

## Development Commands

### Build and Run

```bash
make build              # Build binaries (Linux + local platform)
make run                # Build and run locally
make docker             # Run integration tests with docker-compose
make docker-down        # Stop docker-compose
```

### Testing

```bash
make test               # Run all tests with coverage
go test ./...           # Run all tests
go test -v -run TestName ./path/to/package    # Run specific test
go test ./... -race -coverprofile=coverage.out -covermode=atomic    # With race detector
go tool cover -html=coverage.out    # View coverage report
```

### Dependencies

```bash
go mod tidy             # Tidy dependencies
make ensure-deps        # Verify dependencies are clean
```

### Local Development Setup

Use direnv for environment configuration:

```bash
direnv allow .
```

Create `.envrc.private` (gitignored) for local configuration overrides. See `.envrc` for all available configuration options.

## Architecture

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

**Audit Logging**: Custom zerolog level (20) for audit events. Audit middleware wraps response writer to capture status codes. The `audit.Entry` struct implements `zerolog.LogObjectMarshaler` to avoid reflection overhead.

**Configuration**: All configuration via environment variables using `github.com/sethvargo/go-envconfig`. Config structs use `env` tags with defaults and required fields.

### Internal Package Responsibilities

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
- Panics are only used when absolutely necessary for issues that can only occur
  when well outside standard operating parameters: i.e. the environment is
  unrecoverable or a programming error is detected.

### Testing

**Assertion Style:**
- Use `testify/assert` for assertions, `testify/require` for fatal checks
- **Prefer struct-level equality**: Use `assert.Equal(t, expected, actual)` for struct comparisons instead of field-by-field assertions
  - Good: `assert.Equal(t, expected, ref)` where `expected` is a complete struct
  - Avoid: Multiple `assert.Equal(t, expected.Field, actual.Field)` calls
  - Exception: HTTP response testing (status codes, headers) appropriately uses individual field checks
- Struct equality provides complete diff output on failure, making debugging easier

**Test Organization:**
- **Use table-driven tests** when multiple tests follow the same pattern with different parameters
  - Consolidate tests that differ only in input/output values
  - Use descriptive test case names with `t.Run(tt.name, ...)`
  - Keep success and failure test cases in separate table-driven tests
  - Example: See `internal/profile/ref_test.go` for well-structured table-driven tests
- **Individual test functions** are appropriate when:
  - Each test has unique setup or teardown requirements
  - Tests include timing operations or complex state management
  - Test logic differs significantly between cases

**Test Structure:**
- Table-driven tests should use `expected` struct fields, not individual expected values
  - Good: `expected: ProfileRef{Organization: "acme", Type: TypeRepo, ...}`
  - Avoid: `expectedOrg: "acme", expectedType: TypeRepo, ...`
- Some packages use `package xxx_test` for black-box testing (see `internal/github/token_test.go`)
- Helper functions for common test setup (see `handlers_test.go` for context creation)

### Logging

- Structured logging with `github.com/rs/zerolog`
- Development mode (`ENV=development`) enables console output with debug level
- Implement `zerolog.LogObjectMarshaler` for complex objects to avoid reflection
- Audit logs use custom level 20, formatted as "audit" in output

### Context Usage

- Use empty structs as context keys: `type key struct{}`
- Store pointers in context values for mutable audit/log entries
- Always provide getter functions that return both context and value

### Configuration

- Mark internal-only config fields with `// internal only` comment
- Required fields use `env:"..., required"` tag
- Provide sensible defaults in struct tags where possible

## Before Committing

1. Run tests: `make test`
2. Ensure dependencies are clean: `go mod tidy`
3. Format code: `go fmt ./...` (usually automatic)
4. Check for issues: `go vet ./...`
5. Verify build: `make build`

## Additional Resources

- Architecture and implementation: https://chinmina.github.io/introduction/
- Configuration reference: https://chinmina.github.io/reference/configuration/
- DeepWiki: https://deepwiki.com/chinmina/chinmina-bridge
