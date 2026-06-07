# Makefile for sb — the SSH bastion / jump host.
#
# Common developer entry points: build the binary locally, cross-compile the
# linux release targets, run the unit tests, and run the local end-to-end suite.
# Run `make` (or `make help`) to see the available targets.

# --- Build metadata -----------------------------------------------------------
#
# These mirror what goreleaser injects at release time (see .goreleaser.yml) so a
# locally cross-compiled binary reports the same version/commit as a released
# one. VERSION comes from the nearest git tag (falling back to the short commit
# when no tag is reachable); COMMIT is the short hash. Both tolerate a shallow or
# tag-less checkout without failing the build.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)

# Package path that holds the VERSION/COMMIT vars the ldflags below populate.
CONFIG_PKG := github.com/golgeek/sb/internal/config

# -s -w strip the symbol table and DWARF info to shrink the binary; the two -X
# flags stamp the build metadata into the config package at link time.
LDFLAGS := -s -w -X $(CONFIG_PKG).VERSION=$(VERSION) -X $(CONFIG_PKG).COMMIT=$(COMMIT)

# Where build artifacts land: the host-platform binary and the cross-compiled
# release binaries all go under bin/ (gitignored) so a single `make clean` clears
# everything and the repo root stays tidy.
BIN_DIR := bin

# Cross builds are static (CGO disabled) and reproducible (-trimpath strips local
# filesystem paths), matching the goreleaser configuration.
GO_BUILD_FLAGS := -trimpath -ldflags '$(LDFLAGS)'

.DEFAULT_GOAL := help

# --- Help ---------------------------------------------------------------------

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Build --------------------------------------------------------------------

.PHONY: build
build: ## Build the sb binary for the host platform (bin/sb).
	go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/sb .

.PHONY: build-linux
build-linux: build-linux-amd64 build-linux-arm64 ## Cross-compile for linux/amd64 and linux/arm64.

.PHONY: build-linux-amd64
build-linux-amd64: ## Cross-compile for linux/amd64 (bin/sb_linux_amd64).
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/sb_linux_amd64 .

.PHONY: build-linux-arm64
build-linux-arm64: ## Cross-compile for linux/arm64 (bin/sb_linux_arm64).
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/sb_linux_arm64 .

# --- Test ---------------------------------------------------------------------

.PHONY: test
test: ## Run the unit tests.
	go test ./...

.PHONY: e2e
e2e: ## Run the local end-to-end suite (brings up the demo stack via docker compose).
	./tests/e2e-local.sh

# --- Housekeeping -------------------------------------------------------------

.PHONY: clean
clean: ## Remove built binaries.
	rm -rf $(BIN_DIR)
	rm -f sb
