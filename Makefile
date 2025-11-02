# ZASK Makefile
# Build targets for the Zero-trust AI-Secured Kernel daemon.

BINARY   := zaskd
CMD_DIR  := ./cmd/zaskd
BPF_DIR  := ./bpf

# Go tooling
GOFLAGS  ?=
GOTEST   := go test $(GOFLAGS)
GOBUILD  := go build $(GOFLAGS)
GOBIN    := $(shell go env GOPATH)/bin

# eBPF toolchain — auto-detect Homebrew LLVM on macOS, fall back to system clang.
HOMEBREW_LLVM := /opt/homebrew/opt/llvm/bin
ifneq ($(wildcard $(HOMEBREW_LLVM)/clang),)
  BPF_CLANG  ?= $(HOMEBREW_LLVM)/clang
  BPF_STRIP  ?= $(HOMEBREW_LLVM)/llvm-strip
else
  BPF_CLANG  ?= clang
  BPF_STRIP  ?= llvm-strip
endif
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -I../../bpf -I../../bpf/headers
export BPF_CLANG BPF_STRIP BPF_CFLAGS

# Linting
LINT     := $(GOBIN)/golangci-lint

.PHONY: all generate build test lint clean vuln

all: generate build lint test

## generate: Run bpf2go to produce Go bindings from eBPF C source.
##   Requires: clang with BPF backend (Homebrew LLVM on macOS, system clang on Linux).
generate:
	go generate ./internal/ebpf/...

## build: Compile the zaskd Go binary.
build:
	$(GOBUILD) -o $(BINARY) $(CMD_DIR)

## test: Run all Go tests.
test:
	$(GOTEST) ./...

## lint: Run golangci-lint with project configuration.
lint:
	$(LINT) run ./...

## clean: Remove build artifacts and generated files.
clean:
	rm -f $(BINARY)
	rm -f internal/ebpf/zask_*.go internal/ebpf/zask_*.o

## clean-vm: (macOS only) Delete the Lima VM and prune downloaded images.
clean-vm:
	limactl delete -f zask || true
	limactl prune

## start-vm: (macOS only) Create the host mount directory and start the Lima VM.
start-vm:
	mkdir -p /tmp/lima
	limactl start lima/zask.yaml

## vuln: Run govulncheck for dependency vulnerability detection.
vuln:
	@if [ ! -x "$(GOBIN)/govulncheck" ]; then \
		echo "Installing govulncheck..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi
	$(GOBIN)/govulncheck ./...

## tidy: Run go mod tidy and verify no unnecessary dependencies.
tidy:
	go mod tidy

## help: Show this help message.
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //'
