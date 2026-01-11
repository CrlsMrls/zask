# Configuration Reference

ZASK uses a declarative YAML configuration file following a kube-apiserver-style manifest format. The daemon reads this file at startup from the path specified by the `--config` CLI flag (default: `/etc/zask/config.yaml`).

## Top-Level Structure

```yaml
apiVersion: zask.io/v1alpha1
kind: ZaskConfig
spec:
  # ... configuration fields ...
```

| Field        | Type   | Required | Description                              |
|--------------|--------|----------|------------------------------------------|
| `apiVersion` | string | Yes      | Must be `zask.io/v1alpha1`               |
| `kind`       | string | Yes      | Must be `ZaskConfig`                     |
| `spec`       | object | Yes      | Main configuration body (see below)      |

## `spec` Fields

### `spec.mode`

Configures the enforcement mode for the policy engine.

| Field  | Type   | Default     | Description                                                                 |
|--------|--------|-------------|-----------------------------------------------------------------------------|
| `mode` | string | `lockdown`  | `lockdown` — enforce verdicts (kill + block). `monitor` — log only, never enforce. |

In **monitor mode**, ZASK still evaluates every execution event through all tiers and emits audit events, but never sends `SIGKILL` or writes block entries to the verdict map. This is useful for dry-run deployments and baseline tuning.

### `spec.selfProtection`

Controls whether the daemon registers its PID in the eBPF `protected_pids` map. When enabled, the `lsm/task_kill` hook blocks external `SIGKILL` and `SIGTERM` signals to the daemon, preventing unauthorized termination.

| Field            | Type | Default | Description                                       |
|------------------|------|---------|---------------------------------------------------|
| `selfProtection` | bool | `true`  | Enable eBPF-based self-protection for the daemon. |

Set to `false` in e2e test environments where the test harness needs to send signals to the daemon. In production, leave at the default (`true`).

### `spec.interpreters`

Configures the list of known script interpreters. When the engine detects an interpreter executing a script, it resolves the script's identity and evaluates rules against `script_path` instead of the interpreter binary.

Entries can be bare names (`python3`) or full paths (`/usr/bin/python3`). The engine normalises each entry to its basename via `filepath.Base()`, so `/usr/bin/python3` and `python3` are equivalent.

| Field          | Type       | Default            | Description                     |
|----------------|------------|--------------------|---------------------------------|
| `interpreters` | []string   | see below          | List of interpreter names/paths |

**Default list** (used when unset):

```yaml
interpreters:
  - python3
  - python
  - python2
  - bash
  - sh
  - zsh
  - dash
  - fish
  - node
  - nodejs
  - ruby
  - perl
  - php
  - lua
```

**Custom example:**

```yaml
spec:
  interpreters:
    - /usr/bin/python3
    - /usr/local/bin/node
    - ruby
```

### `spec.audit`

Configures multi-format audit output for security events.

| Field     | Type             | Default | Description                              |
|-----------|------------------|---------|------------------------------------------|
| `outputs` | []AuditOutput    | see below | List of audit output destinations     |

Each `AuditOutput` entry:

| Field    | Type   | Required | Description                                                             |
|----------|--------|----------|-------------------------------------------------------------------------|
| `format` | string | Yes      | Output format: `json` (NDJSON), `parquet` (columnar), or `text` (human-readable) |
| `path`   | string | Yes      | File path to write to. Use `stdout` or `stderr` for standard streams (JSON and text only). |

**Default:** If omitted, a single JSON output writing to `/var/log/zask/audit.json` is configured.

**Example:**

```yaml
spec:
  audit:
    outputs:
      - format: json
        path: /var/log/zask/audit.json
      - format: parquet
        path: /var/log/zask/audit.parquet
      - format: text
        path: stdout
```

### `spec.mapPaths`

Configures BPF map pin locations on the BPF filesystem.

| Field        | Type   | Default                       | Description                           |
|--------------|--------|-------------------------------|---------------------------------------|
| `verdictMap` | string | `/sys/fs/bpf/zask_verdicts`   | Pin path for the verdict hash map     |

### `spec.logging`

Configures structured logging output.

| Field    | Type   | Default  | Description                                                        |
|----------|--------|----------|--------------------------------------------------------------------|
| `level`  | string | `info`   | Log level: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`, `disabled` |
| `format` | string | `json`   | Output format: `json` or `console`                                 |
| `output` | string | `stdout` | Output destination (reserved for future use)                       |

### `spec.health`

Configures the HTTP health endpoint server.

| Field           | Type   | Default  | Description                                    |
|-----------------|--------|----------|------------------------------------------------|
| `listenAddress` | string | `:7453`  | Address and port for the health HTTP server     |


**Endpoints:**

- `GET /healthz` — Always returns `200 OK` with JSON status (liveness probe).
- `GET /readyz` — Returns `200 OK` only when eBPF is loaded and ring buffer reader is active (readiness probe).

### `spec.rateLimiter`

Configures the Token Bucket rate limiter for Tier 3 AI queue routing.

| Field   | Type    | Default | Description                                       |
|---------|---------|---------|---------------------------------------------------|
| `rate`  | float64 | `10`    | Events per second allowed to pass to Tier 3        |
| `burst` | int     | `20`    | Maximum burst size (token bucket capacity)         |

### `spec.rules`

Configures the Tier 2 static rule engine.

| Field  | Type   | Default               | Description                               |
|--------|--------|-----------------------|-------------------------------------------|
| `path` | string | `/etc/zask/rules.yaml`| Path to the rules YAML file               |

The rules file is watched for changes using `fsnotify`. Modifying the file or sending `SIGHUP` to the daemon triggers a hot-reload without restart. When rules are reloaded, the Tier 1 inode cache is automatically cleared so that previously-cached "known-good" inodes are re-evaluated against the new rule set.

### `spec.ai`

Configures the Tier 3 AI provider integration (consumed by Phase 3).

| Field           | Type     | Default | Description                                          |
|-----------------|----------|---------|------------------------------------------------------|
| `providerUrl`   | string   | —       | URL of the AI inference endpoint                     |
| `model`         | string   | —       | Model name/identifier                                |
| `apiKeyFile`    | string   | —       | Path to file containing the API key                  |
| `riskThreshold` | float64  | `0.8`   | Risk score threshold (0.0–1.0) for blocking          |
| `timeout`       | duration | `5s`    | HTTP timeout for AI provider requests                |

## Full Example

```yaml
apiVersion: zask.io/v1alpha1
kind: ZaskConfig
spec:
  mode: lockdown

  interpreters:
    - python3
    - python
    - bash
    - sh
    - node
    - ruby
    - perl

  audit:
    outputs:
      - format: json
        path: /var/log/zask/audit.json
      - format: parquet
        path: /var/log/zask/audit.parquet
      - format: text
        path: stdout

  mapPaths:
    verdictMap: /sys/fs/bpf/zask_verdicts

  logging:
    level: info
    format: json
    output: stdout

  health:
    listenAddress: ":7453"

  rateLimiter:
    rate: 10
    burst: 20

  rules:
    path: /etc/zask/rules.yaml

  ai:
    providerUrl: http://localhost:11434/api/generate
    model: llama3
    apiKeyFile: /etc/zask/ai-api-key
    riskThreshold: 0.8
    timeout: 5s
```

## Validation

All configuration fields are validated at startup. Invalid configuration causes an immediate exit with a descriptive error message. Validated constraints include:

- `apiVersion` must be exactly `zask.io/v1alpha1`
- `kind` must be exactly `ZaskConfig`
- `spec.mode` must be `lockdown` or `monitor`
- `spec.audit.outputs[].format` must be `json`, `parquet`, or `text`
- `spec.audit.outputs[].path` must not be empty
- `spec.mapPaths.verdictMap` must not be empty
- `spec.logging.level` must be a valid zerolog level
- `spec.logging.format` must be `json` or `console`
- `spec.health.listenAddress` must not be empty
- `spec.rateLimiter.rate` must be positive
- `spec.rateLimiter.burst` must be positive
- `spec.ai.riskThreshold` must be between 0.0 and 1.0
- `spec.ai.timeout` must be non-negative

## CLI Flags

| Flag       | Default                 | Description                |
|------------|-------------------------|----------------------------|
| `--config` | `/etc/zask/config.yaml` | Path to the config file    |

## Rules File Syntax

Rules use [CEL (Common Expression Language)](https://github.com/google/cel-go) conditions evaluated against structured event attributes.

### Rule Actions

| Action  | Behavior                                                                                      |
|---------|-----------------------------------------------------------------------------------------------|
| `BLOCK` | Terminate the process (`SIGKILL`) and write its inode to the verdict map for eBPF-level blocking on subsequent runs. |
| `ALLOW` | Explicitly whitelist the binary. The inode is added to the Tier 1 cache immediately and the event **skips Tier 3 AI analysis**. Use this to reduce noise from trusted system binaries. |
| `ALERT` | Log a warning at the configured severity but allow the execution to proceed.                  |

### Rule Ordering (First Match Wins)

Rules are evaluated **top-to-bottom**. The first matching rule determines the action — remaining rules are skipped.

This has critical implications when BLOCK and ALLOW rules overlap:

```yaml
# CORRECT — BLOCK evaluated first, catches /usr/bin/nc before the ALLOW catchall.
rules:
  - name: block-netcat-root
    condition: 'argv.contains("nc") && uid == 0'
    action: BLOCK
    severity: critical

  - name: block-tmp-scripts
    condition: 'script_path.startsWith("/tmp/") && uid == 0'
    action: BLOCK
    severity: high

  - name: allow-system-bins
    condition: 'argv.startsWith("/usr/bin/")'
    action: ALLOW
    severity: low
```

```yaml
# WRONG — ALLOW matches /usr/bin/nc first, so block-netcat-root is never reached.
rules:
  - name: allow-system-bins          # <-- matches /usr/bin/nc!
    condition: 'argv.startsWith("/usr/bin/")'
    action: ALLOW
  - name: block-netcat-root           # <-- never evaluated for /usr/bin/nc
    condition: 'argv.contains("nc") && uid == 0'
    action: BLOCK
```

**Best practice:** Place all BLOCK/ALERT rules before ALLOW rules. Use ALLOW as a catchall at the end.

### CEL Conditions

CEL (Common Expression Language) rules evaluate against structured event attributes:

| Variable      | Type   | Description                                             |
|---------------|--------|---------------------------------------------------------|
| `argv`        | string | Executable binary path (e.g., `/usr/bin/python3`)       |
| `script_path` | string | Resolved script path when an interpreter is detected (via eBPF argv[1] or procfs fallback) |
| `pid`         | int    | Process ID                                              |
| `ppid`        | int    | Parent process ID                                       |
| `uid`         | int    | User ID                                                 |
| `cgroup_id`   | int    | cgroup ID (useful for host vs. container distinction)   |
| `inode`       | int    | Binary inode number                                     |

**Example CEL rules:**

```yaml
# Block root running scripts from /tmp
- name: tmp-root-script
  condition: 'script_path.startsWith("/tmp/") && uid == 0'
  action: BLOCK
  severity: critical

# Alert on reconnaissance tools inside containers
- name: container-recon
  condition: 'cgroup_id > 1 && (argv.contains("nmap") || argv.contains("masscan"))'
  action: ALERT
  severity: high

# Allow a specific binary by exact path
- name: allow-containerd
  condition: 'argv == "/usr/bin/containerd"'
  action: ALLOW
  severity: low

# Allow all standard system binaries (broad catchall — place last)
- name: allow-system-bins
  condition: 'argv.startsWith("/usr/bin/") || argv.startsWith("/usr/sbin/")'
  action: ALLOW
  severity: low
```

> **Audit note:** ALLOW verdicts generate audit events just like BLOCK and ALERT. In high-throughput environments, broad ALLOW rules can produce significant audit volume. Monitor audit file sizes and consider narrowing ALLOW conditions or increasing log rotation frequency if needed.

## Environment

Configuration is loaded exclusively from the YAML file. Environment variable overrides are reserved for future implementation (Phase 5).
