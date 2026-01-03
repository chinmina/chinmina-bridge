.DEFAULT_GOAL := build

.PHONY: mod
mod:
	go mod download

.PHONY: format
format:
	go fmt ./...

.PHONY: lint
lint: mod
	golangci-lint run

.PHONY: test
test: mod
	go test -cover ./...

.PHONY: test-ci
test-ci: mod
	mkdir artifacts
	go test ./... -covermode=atomic -coverprofile=artifacts/count.out
	go tool cover -func=artifacts/count.out | tee artifacts/coverage.out

dist:
	mkdir -p dist

.PHONY: build
build: dist mod
	# build for container use: in future we will need to either use "ko" or
	# "goreleaser" (or both) to create executables and images in the required
	# architectures.
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-w" -trimpath -o dist/chinmina-bridge .
	# build for local use, whatever the local platform is
	CGO_ENABLED=0 go build -ldflags="-w" -trimpath -o dist/chinmina-bridge-local .
	CGO_ENABLED=0 go build -o dist/oidc-local cmd/create/main.go

.PHONY: run
run: build
	dist/chinmina-bridge-local

.PHONY: agent
agent: build format test lint

.PHONY: docker
docker: build
	docker compose -f integration/docker-compose.yaml up --abort-on-container-exit

.PHONY: docker-down
docker-down:
	docker compose -f integration/docker-compose.yaml down

# ensures that `go mod tidy` has been run after any dependency changes
.PHONY: ensure-deps
ensure-deps: mod
	@go mod tidy
	@git diff --exit-code

# use generation tool to create a JWKS key pair that can be used for local
# testing.
keygen:
	go install github.com/go-jose/go-jose/v4/jose-util@latest
	cd .development/keys \
		&& rm -f *.json \
		&& jose-util generate-key --use sig --alg RS256 --kid testing \
		&& chmod +w *.json \
		&& jq '. | { keys: [ . ] }' < jwk-sig-testing-pub.json > tmp.json \
		&& mv tmp.json jwk-sig-testing-pub.json
