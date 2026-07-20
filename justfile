export GOEXPERIMENT := "jsonv2"

# Build flags shared across build targets
GO_BUILD_FLAGS := "-trimpath"
GO_LD_FLAGS := "-w"

# Fuzz test durations
FUZZING_LOCAL_SECS := env_var_or_default("FUZZING_LOCAL_SECS", "30")
FUZZING_CI_SECS := env_var_or_default("FUZZING_CI_SECS", "10")

# List available recipes
default:
    @just --list

# Download Go module dependencies
mod:
    go mod download

# Format all Go source files
format:
    go fmt ./...

# Run the linter
lint: mod
    golangci-lint run

# Run unit tests; extra go test arguments narrow the target, e.g. `just test ./internal/jwt -run TestFoo`
test *args='./...': mod
    go test -cover -covermode=atomic {{args}}

# Run integration tests; extra go test arguments narrow the target
integration *args='./...': mod
    go test -tags=integration -run='^TestIntegration' -cover -covermode=atomic {{args}}

# Run fuzz tests locally (FUZZING_LOCAL_SECS per target, default 30s)
fuzz: mod
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in internal/credentialhandler internal/jwt internal/profile internal/vendor .; do
        echo "Fuzzing ${pkg}..."
        go test -tags=fuzz -fuzz=Fuzz -run='^$' -fuzztime={{FUZZING_LOCAL_SECS}}s "./${pkg}"
    done

# CI: run unit tests with race detection, coverage output for codecov
ci-unit: mod
    go test -race -coverprofile=coverage.out -covermode=atomic ./...

# CI: run integration tests with race detection, coverage output for codecov
ci-integration: mod
    go test -tags=integration -run='^TestIntegration' -race -coverprofile=coverage.out -covermode=atomic ./...

# CI: run fuzz tests (FUZZING_CI_SECS per target, default 10s)
ci-fuzz: mod
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in internal/credentialhandler internal/jwt internal/profile internal/vendor .; do
        echo "Fuzzing ${pkg}..."
        go test -tags=fuzz -fuzz=Fuzz -run='^$' -fuzztime={{FUZZING_CI_SECS}}s "./${pkg}"
    done

# Ensure the dist/ output directory exists
dist:
    mkdir -p dist

# Build the container, local, and oidc-local binaries
build: dist mod
    #!/usr/bin/env bash
    set -euo pipefail
    export CGO_ENABLED=0
    # build for container use: in future we will need to either use "ko" or
    # "goreleaser" (or both) to create executables and images in the required
    # architectures.
    GOOS=linux go build {{GO_BUILD_FLAGS}} -ldflags="{{GO_LD_FLAGS}}" -o dist/chinmina-bridge .
    # build for local use, whatever the local platform is
    go build {{GO_BUILD_FLAGS}} -ldflags="{{GO_LD_FLAGS}}" -o dist/chinmina-bridge-local .
    go build -ldflags="{{GO_LD_FLAGS}}" -o dist/oidc-local cmd/create/main.go

# Build only the local dev binary; extra go build arguments are forwarded, e.g. `just build-local -v`
build-local *args: dist mod
    CGO_ENABLED=0 go build {{args}} {{GO_BUILD_FLAGS}} -ldflags="{{GO_LD_FLAGS}}" -o dist/chinmina-bridge-local .

# Build and run the local binary
run: build-local
    dist/chinmina-bridge-local

# Everything expected to pass before committing
agent: build format test lint

# Run integration tests against docker-compose
docker: build
    cd integration && docker compose up --abort-on-container-exit

# Stop the docker-compose stack
docker-down:
    cd integration && docker compose down

# Ensure `go mod tidy` has been run after any dependency changes
ensure-deps: mod
    @go mod tidy
    @git diff --exit-code

# Generate a JWKS key pair for local testing
keygen:
    #!/usr/bin/env bash
    set -euo pipefail
    go install github.com/go-jose/go-jose/v4/jose-util@latest
    cd .development/keys
    rm -f *.json
    jose-util generate-key --use sig --alg RS256 --kid testing
    chmod +w *.json
    jq '. | { keys: [ . ] }' < jwk-sig-testing-pub.json > tmp.json
    mv tmp.json jwk-sig-testing-pub.json
