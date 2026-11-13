BIN     := mcp-scanner
API_BIN := mcp-scanner-api
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.scanVersion=$(VERSION)

.PHONY: all build build-yara check-version test test-yara race vet fmt fmt-check lint vuln vuln-dist fuzz cover check clean dist sync-rules

all: check build

build:
	go build -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/mcp-scanner
	go build -ldflags '$(LDFLAGS)' -o bin/$(API_BIN) ./cmd/mcp-scanner-api

# -X only stamps a symbol the linker can find; a typo'd path fails silently
# and every report keeps reading "dev". Scan a small fixture and read the
# version out of the report itself, not just --version, which reads the same
# variable and could go stale the same way. Parsed rather than grepped: the
# report is written by an indenting encoder, so matching raw bytes depends on
# spacing the writer is free to change, and a guard that is always red gets
# deleted along with the check it was protecting.
check-version: build
	@out=$$(./bin/$(BIN) source testdata/source/discovery/go --analyzers source --format json); \
	echo "$$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); v=d.get("scanner_version"); sys.exit(0 if v=="$(VERSION)" else (print("report carried scanner_version %r, want %r" % (v, "$(VERSION)")) or 1))' || exit 1
	@echo "scanner_version $(VERSION) confirmed in report output"

# Signature matching needs a CGO-linked YARA library.
# Needs libyara and pkg-config installed, or this stops at
# "Package yara was not found in the pkg-config search path" before the Go
# compiler runs. See the README, and
# https://yara.readthedocs.io/en/stable/gettingstarted.html
build-yara:
	go build -tags yara -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/mcp-scanner

# TESTPAR bounds how many packages run at once. The docker-backed sandbox
# and runtime tests, and taint's concurrency test, all assert an outcome
# that depends on work finishing inside a wall-clock deadline, so running
# every package at once on a busy machine makes them fail for reasons that
# have nothing to do with the code. A gate that fails at random is a gate
# people re-run instead of trusting, which is worse than a slower one.
TESTPAR ?= 2

test:
	go test -p $(TESTPAR) ./...

race:
	go test -race -p $(TESTPAR) ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	@command -v staticcheck >/dev/null || { echo "staticcheck not installed: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1; }
	staticcheck ./...

# Use the same govulncheck release locally and in CI; go run caches the build
GOVULNCHECK_VERSION := v1.9.0
GOVULNCHECK         := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

vuln:
	$(GOVULNCHECK) ./...

# Scan the Go and module versions embedded in each dist/ binary, covering the release's
# GOOS/GOARCH and build tags. A source scan covers only the host configuration.
# With no matching binaries, the unexpanded glob causes the scan to fail.
vuln-dist:
	@set -e; for f in dist/$(BIN)_*; do echo "govulncheck -mode=binary $$f"; $(GOVULNCHECK) -mode=binary "$$f"; done

# A short CI run. Crashes fail the target; longer campaigns are manual
fuzz:
	go test -run xxx -fuzz FuzzExtract -fuzztime 30s ./internal/supplychain/archive/

# Run the signature engine and eval corpus with YARA enabled. Requires libyara; see build-yara
test-yara:
	go test -tags yara ./internal/analyzers/yara/ ./internal/evals/

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# lint is deliberately not in here. staticcheck refuses to analyze a module
# whose Go version is newer than the Go it was itself built with, so wiring
# it into the gate makes `make check` fail on a clean tree whenever a
# developer's staticcheck lags the go directive. Run it directly; vuln is in
# the gate because govulncheck has no such constraint and a dependency
# advisory is the thing worth catching on every run.
check: fmt-check vet vuln test race check-version
	@if pkg-config --exists yara 2>/dev/null; then $(MAKE) --no-print-directory test-yara; \
	else echo "libyara not installed; skipping YARA tests (install it, then run make test-yara)"; fi

# dist builds a release binary for GOOS/GOARCH, the host by default. The tree-sitter parsers are
# C, so the build needs cgo and a C compiler for the target. To build for another platform, name
# a cross compiler:
#
#   make dist GOOS=windows CC=x86_64-w64-mingw32-gcc
#   make dist GOARCH=amd64 CC="clang -arch x86_64"     # on an arm64 Mac
#
# A macOS binary needs a macOS host. Linux builds use musl-gcc (musl-tools) on a host matching
# the target architecture. Static musl linking avoids a dependency on the distribution's libc
# and requires its license notice; static glibc linking would require relinkable objects.
# musl defaults to a 128 KiB thread stack, below the 8 MiB used by glibc on the release runners.
# -z stack-size requests 8 MiB for tree-sitter's C code when parsing hostile input.
# netgo and osusergo keep DNS and user lookups in Go. Windows builds link the MinGW runtime
# statically, so they need no extra runtime DLLs.
DIST_OS       := $(or $(GOOS),$(shell go env GOOS))
DIST_ARCH     := $(or $(GOARCH),$(shell go env GOARCH))
DIST_EXT      := $(if $(filter windows,$(DIST_OS)),.exe)
DIST_TAGS     := $(if $(filter linux,$(DIST_OS)),netgo osusergo)
DIST_CC       := $(if $(filter linux,$(DIST_OS)),CC=musl-gcc)
LINUX_LDFLAGS := -linkmode external -extldflags "-static -Wl,-z,stack-size=8388608"
DIST_LDFLAGS  := $(if $(filter linux,$(DIST_OS)),$(LINUX_LDFLAGS))$(if $(filter windows,$(DIST_OS)),-extldflags -static)
SHA256       := $(if $(shell command -v sha256sum 2>/dev/null),sha256sum,shasum -a 256)

dist:
	@mkdir -p dist
	$(DIST_CC) GOOS=$(DIST_OS) GOARCH=$(DIST_ARCH) CGO_ENABLED=1 go build -tags '$(DIST_TAGS)' \
		-ldflags '$(LDFLAGS) $(DIST_LDFLAGS)' -o dist/$(BIN)_$(DIST_OS)_$(DIST_ARCH)$(DIST_EXT) ./cmd/mcp-scanner
	cp -f LICENSE THIRD_PARTY_NOTICES dist/
	cd dist && $(SHA256) $(BIN)_* > SHA256SUMS

# The rule files under rules/ are the source of truth. Each analyzer embeds a
# copy so an installed binary carries its rules; a drift test fails if the two
# diverge, and this puts them back in step.
sync-rules:
	rm -rf internal/analyzers/promptdefense/rulesdata internal/analyzers/yara/rulesdata
	mkdir -p internal/analyzers/promptdefense/rulesdata internal/analyzers/yara/rulesdata
	cp rules/prompt-defense/*.yaml internal/analyzers/promptdefense/rulesdata/
	cp rules/yara/*.yar internal/analyzers/yara/rulesdata/

clean:
	rm -rf bin dist coverage.out
