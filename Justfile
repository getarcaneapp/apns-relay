set working-directory := './'

_default:
    @just --list

# Run the relay locally in APNs log mode (no Apple credentials needed)
[group('dev')]
dev:
    RELAY_ENCRYPTION_KEY=${RELAY_ENCRYPTION_KEY:-0000000000000000000000000000000000000000000000000000000000000000} \
    APNS_MODE=${APNS_MODE:-log} \
    RELAY_LOG_FORMAT=text RELAY_LOG_LEVEL=debug \
    go run ./cmd

# Run with a YAML config file
[group('dev')]
run config='relay.yaml':
    go run ./cmd -config {{ config }}

# Generate a 32-byte encryption key
[group('dev')]
gen-key:
    @openssl rand -hex 32

[group('build')]
build:
    CGO_ENABLED=0 go build -trimpath -ldflags "-w -s" -o dist/apns-relay ./cmd

# Build a release snapshot with goreleaser (no publish)
[group('build')]
snapshot:
    goreleaser release --snapshot --clean --skip=sign,docker,publish

[group('quality')]
test:
    go test -race -coverprofile=coverage.txt -covermode=atomic ./...

[group('quality')]
format: _build-golangci-lint
    ./.bin/golangci-lint-custom fmt -c .github/.golangci.yml ./...
    go mod tidy

# Build golangci-lint with the custom linters enabled by the shared Arcane config
[group('quality')]
_build-golangci-lint:
    golangci-lint custom

# Lint with the same golangci-lint config as Arcane
[group('quality')]
lint: _build-golangci-lint
    ./.bin/golangci-lint-custom run -c .github/.golangci.yml ./...

[group('quality')]
deadcode:
    go run golang.org/x/tools/cmd/deadcode@latest -test ./...
