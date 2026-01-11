# ZASK — Zero-trust AI-Secured Kernel

Autonomous Linux Kernel Hardening via eBPF LSM and AI.

ZASK (Zero-trust AI-Secured Kernel) is a security engine that implements an LLM-as-a-judge framework to evaluate the semantic intent of Linux processes. By bridging the gap between raw eBPF LSM telemetry and high-reasoning AI, ZASK identifies obfuscated threats — like reverse shells and fileless malware — and pushes "judgments" back into the kernel to block malicious behavior.

## How It Works

ZASK operates a multi-tiered enforcement model:

| Tier | Layer | Mechanism | Latency | Purpose |
|------|-------|-----------|---------|---------|
| **1** | Kernel | eBPF LSM + Inode Map | < 1μs | Instant blocking of known-malicious binaries |
| **2** | User-space | Deterministic Engine | < 10ms | CEL policy matching, script-aware interpreter detection |
| **3** | Intelligence | LLM Semantic Loop | 1–5s | AI analysis of process intent and judge |


How the LLM-as-a-Judge Framework Works:
- The Telemetry: The kernel provides the raw "facts" (syscalls, inodes, arguments).
- The Referral: When Tier 2 sees something it can't definitively call "good" or "bad," it refers the case to the Judge.
- The Verdict: The LLM issues an Enforcement Verdict (Block vs. Allow) based on its understanding of exploit patterns.

### Enforcement Modes

- **Lockdown** (default) — enforces verdicts by killing processes and updating the kernel block map.
- **Monitor** — evaluates all tiers and emits audit events but never enforces, useful for dry-run deployments.

### CEL Policy Rules

Tier 2 rules support [CEL (Common Expression Language)](https://github.com/google/cel-go) expressions that can combine multiple event attributes — `argv`, `script_path`, `pid`, `uid`, `cgroup_id`, and more — in a single condition:

```yaml
- name: tmp-root-script
  condition: 'script_path.startsWith("/tmp/") && uid == 0'
  action: BLOCK
  severity: critical
```

### Script-Aware Interpreter Detection

When an interpreter executes a script, ZASK extracts `argv[1]` directly in eBPF and resolves the script's inode. If `argv[1]` is a flag (e.g., `-u`), the engine falls back to `/proc/[pid]/cmdline` to find the actual script path. Rules can then match on `script_path` in addition to the binary path, catching threats like `python3 -u /tmp/payload.py`.

Interpreters are detected by matching `basename(argv)` against a configurable set (default: `python3`, `python`, `bash`, `sh`, `zsh`, `dash`, `fish`, `node`, `nodejs`, `ruby`, `perl`, `php`, `lua`). The list can be customised via `spec.interpreters` in the config file, accepting both bare names and full paths. Non-interpreter binaries follow the standard execution path — all binaries are evaluated through every tier regardless. See [Configuration](docs/configuration.md) and [Architecture](docs/architecture.md) for details.

### Multi-Format Audit Logging

Security events are written to one or more audit outputs simultaneously:

- **JSON** (NDJSON) — for log pipelines and SIEM ingestion
- **Parquet** — columnar format for analytics and long-term storage
- **Text** — human-readable console output

## Prerequisites

### Kernel Requirements

ZASK requires Linux kernel **≥ 5.8** with:

- `CONFIG_BPF_LSM=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_SYSCALL=y`
- Boot parameter: `lsm=lockdown,capability,bpf`

See [docs/kernel-requirements.md](docs/kernel-requirements.md) for full details.

### Runtime Capabilities

The ZASK daemon requires: `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_KILL`.

## Quickstart

### macOS Toolchain

The eBPF compiler requires a clang with the BPF backend. macOS's system clang does not include it, so install LLVM via Homebrew:

```bash
brew install llvm
```

The Makefile auto-detects Homebrew LLVM at `/opt/homebrew/opt/llvm/bin/clang`. On Linux, system clang is used by default. You can override with:

```bash
BPF_CLANG=/path/to/clang BPF_STRIP=/path/to/llvm-strip make generate
```

### macOS Development (Lima VM)

For macOS, we use Lima to run an isolated Linux VM with the required kernel features. This safely separates your development environment from the execution environment.

```bash
brew install lima
make start-vm
limactl shell zask
```

See [docs/lima-dev-guide.md](docs/lima-dev-guide.md) for detailed setup.

### Linux Development

> **Note:** The maintainer primarily uses macOS with Lima for development. The following native Linux workflow is provided for reference but has **not been tested**, comments are welcome.

ZASK interacts directly with the Linux kernel via eBPF LSM hooks. A bug or misconfiguration could cause kernel panics or system instability. **Never run or test the ZASK daemon on your primary workstation.** Always use a dedicated VM or an isolated test machine.


```bash
# Install toolchain on your isolated test VM
sudo apt install clang llvm libbpf-dev bpftool

# Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

### Building and Testing

Once your isolated execution environment is set up (either via Lima or a dedicated Linux VM), verify it and run the build commands from within that environment:

```bash
# Verify your kernel meets requirements (Run inside the VM)
./scripts/check-env.sh

# Build and test
make generate   # Generate eBPF Go bindings
make build      # Compile the daemon
make test       # Run tests
make lint       # Run linter
make vuln       # Run vulnerability detection
```

### CI / Docker

```bash
docker build -f deploy/Dockerfile.ci -t zask-ci .
docker run --rm -v $(pwd):/workspace -w /workspace zask-ci make build
```

## Project Structure

```
cmd/zaskd/          — Main daemon entry point
internal/ebpf/      — eBPF loader and map management
internal/engine/    — Tiered Policy Engine logic
internal/ai/        — AI provider client and prompt engineering
internal/audit/     — Structured logging and observability
internal/config/    — Configuration loading and validation
bpf/                — C source files for eBPF programs
deploy/             — Dockerfiles, Kubernetes manifests, systemd units
rules/              — Default rules.yaml and example rule sets
scripts/            — Utility scripts (environment checks, etc.)
docs/               — Documentation
```

## Build Commands

| Command | Description |
|---------|-------------|
| `make generate` | Run bpf2go to generate Go bindings from eBPF C source |
| `make build` | Compile the zaskd binary |
| `make test` | Run all Go tests |
| `make lint` | Run golangci-lint |
| `make clean` | Remove build artifacts |
| `make vuln` | Run govulncheck for vulnerability detection |

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration Reference](docs/configuration.md)
- [Kernel Requirements](docs/kernel-requirements.md)
- [Lima Development Guide](docs/lima-dev-guide.md)
- [Kubernetes Node Preparation](docs/k8s-node-preparation.md)


