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

# Lima VM name
LIMA_VM  := zask
# Writable build directory inside the VM (host mount is read-only)
VM_BUILD := /tmp/zask-build
# Shared writable mount between host and VM
LIMA_SHARED := /tmp/lima

## vm-build: (macOS only) Copy project to the Lima VM, run generate + build,
##   and sync generated files back to the host.
vm-build:
	@echo "==> Copying project to VM..." && \
	limactl shell $(LIMA_VM) -- bash -c '\
		set -e && \
		rm -rf $(VM_BUILD) && \
		cp -a /Users/$$(whoami)/src/zask $(VM_BUILD) && \
		cd $(VM_BUILD) && \
		echo "==> Running make generate..." && \
		make generate && \
		echo "==> Running make build..." && \
		make build && \
		echo "==> Copying generated files to shared mount..." && \
		cp internal/ebpf/zask_bpfel.go $(LIMA_SHARED)/ && \
		cp internal/ebpf/zask_bpfel.o $(LIMA_SHARED)/ && \
		cp $(BINARY) $(LIMA_SHARED)/ && \
		echo "==> VM build complete."' && \
	cp $(LIMA_SHARED)/zask_bpfel.go internal/ebpf/zask_bpfel.go && \
	cp $(LIMA_SHARED)/zask_bpfel.o internal/ebpf/zask_bpfel.o && \
	echo "==> Generated files synced to host."

## vm-test: (macOS only) Run the Phase 1 kernel-level test suite in the Lima VM.
vm-test:
	@limactl shell $(LIMA_VM) -- bash -c '\
		set -e && \
		cd $(VM_BUILD) && \
		sudo bash scripts/test-phase1.sh'

## vm-run: (macOS only) Run zaskd in the Lima VM (requires vm-build first).
vm-run:
	@limactl shell $(LIMA_VM) -- bash -c '\
		cd $(VM_BUILD) && \
		sudo ./$(BINARY)'

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
