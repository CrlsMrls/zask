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

The rules file is watched for changes using `fsnotify`. Modifying the file or sending `SIGHUP` to the daemon triggers a hot-reload without restart.

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

## Environment

Configuration is loaded exclusively from the YAML file. Environment variable overrides are reserved for future implementation (Phase 5).
