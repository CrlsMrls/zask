# Configuration

ZASK is designed to block malicious process executions, if the configuration is wrongly set, it can block legitimate processes and cause system instability. The recommendation approach is to start with a monitor mode, where all events are evaluated and logged but never blocked.

> The project follows [semantic versioning](https://semver.org/). It is still in early development (major version zero), and the configuration schema is expected to evolve. This public configuration **SHOULD NOT** be considered stable. Feedback is very welcome.

The principles of the configuration is to be **declarative, self-contained, and human-friendly**. It is stored in a YAML file, which can be hot-reloaded on change without restarting the daemon. The file path is specified by the `--config` flag. Without the flag, it defaults to `./config.yaml`, which allows for easy local testing. 

Currently, only a few environment variables are supported, to allow storing sensitive information (like API keys) outside of the config file. 

## Overview

The configuration file is organized into the following logical sections:

- **General settings** monitoring mode, self-protection mechanism
- **Deterministic rules** for blocking, allowing, or sending to the AI
- **Audit/logging configuration** for output format and destination
- **AI integration settings** for provider configuration, risk threshold, and feedback loop behavior

## General Settings

### Enforcer switch

The `mode` section is a high-level switch that controls the overall behavior of the daemon. The deamon can operate in two modes:

- **Monitor mode**: all processes continue running.
- **Lockdown mode (default)**: processes can be blocked.

 It is meant to be used first as an obvserve mechanism for testing (`monitor` mode) with a gradual rollout (`lockdown` mode).

### Self-protection

The `selfProtection` section configures the daemon's self-protection mechanism against termination to prevent attackers from terminating it. This setting can disable this behaviour.

The [shutdown.md](../01-setup/shutdown.md) file provides detailed instructions on how this mechanism works.

## Deterministic enforcement

### List of Rules

The `rules` section allows operators to define deterministic rules for blocking, allowing, or sending to the AI based on collected metrics. This is the first line of defense for known bad behaviors.

Considered the rules can be a big list of patterns, they are loaded from a separate file. Future plans include support for dynamic updates to the rules without restarting the daemon.

These rules use [CEL (Common Expression Language)](https://github.com/google/cel-go) syntax, which allows for flexible and powerful expressions.

Rules Actions can be:
- `ALLOW`: Execution permitted. Whitelisting the process.
- `BLOCK`: Process is killed immediately (`SIGKILL`) and the inode is written to the kernel verdict map, blocking all future executions.
- `ALERT`: Suspicious activity logged but execution is not blocked.


An example rule to block any execution of `nc` (netcat) as root would look like this:
```yaml
  - name: block-netcat-root
    condition: 'argv.contains("nc") && uid == 0'
    action: BLOCK
    severity: critical
```

The following example allows any process executed from `/usr/bin/`:
```yaml
  - name: allow-system-bins
    condition: 'argv.startsWith("/usr/bin/")'
    action: ALLOW
    severity: low
```

### List of Interpreters

The optional `interpreters` section allows operators to specify a list of interpreter paths to monitor (e.g., `/usr/bin/python`, `/usr/bin/bash`). By default, the daemon includes a list of common interpreters, but this can be customized here.

This allows to define rules that only apply to processes executed through these interpreters, which are common vectors for attacks.

The following example blocks any script executed as root from the `/tmp` directory:
```yaml
  - name: block-tmp-scripts
    condition: 'script_path.startsWith("/tmp/") && uid == 0'
    action: BLOCK
    severity: high
```

### Default Action

> **TODO:** This section is still missing.

The `defaultAction` setting defines the default behavior for any process that does not match any of the defined rules. This is a catch-all mechanism to ensure that all processes are evaluated, even if they don't match specific patterns.

The goal is to have a default of `AI_QUEUE`, which means that any process that doesn't match a deterministic rule will be sent to the AI for analysis. 

## AI Integration

The `ai` section configures the AI integration, including provider settings, risk threshold, and feedback loop behavior. This is where you specify the details of how the daemon interacts with the AI for semantic analysis.

**TODO:** Currently, all AI-related settings are under this section, but in the future it should be split into tier-specific settigs (e.g., `ai.onnx` for the fast path and `ai.llm` for the deep arbiter).

## Observability

### Monitoring the deamon

The `health` section configures the health check endpoints. The daemon exposes standard Kubernetes probe endpoints — `GET /healthz` (liveness) and `GET /readyz` (readiness, gated on eBPF load and ring buffer active).

This is very convenient for Kubernetes deployments, a DaemonSet can manage rollout and traffic routing.

### Logging and Auditing

- **audit**: Configuration for audit event emission (e.g., output format, destination).
- **logging**: Log level and format settings for the daemon's internal logs.

**TODO:** Currently, this is configured under two seeparate sections, but the goal is to unify them under a single `observability` section with two subsections.


## What's next

| Document | Description |
|---|---|
| [rules-examples.md](rules-examples.md) | Verified CEL rule patterns for blocking, alerting, and allowlisting. |
| [e2e-examples.md](e2e-examples.md) | Verified, ready-to-use configurations for dev/test and production scenarios. |
| [ai-integration.md](ai-integration.md) | AI provider setup, prompt engineering, circuit breaker, and feedback loop. |
| [configuration.md](configuration.md) | Full configuration reference — every field, type, default, and validation rule. |
