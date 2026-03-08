# Configuration Examples — LLM Integration

Verified configurations for running ZASK with an LLM provider. Validated end-to-end in a Lima VM against a real eBPF kernel.

---

## Local Ollama (dev / testing)

This setup was used for development and testing in a Lima VM with Ollama running on the macOS host. The AI provider URL is set to `http://host.lima.internal:11434/v1/chat/completions` to allow the daemon inside the VM to reach the Ollama server on the host. Replace it with an IP when running outside Lima.

`riskThreshold: 0.1` is intentionally aggressive for tests. Raise it to `0.7–0.9` in production to reduce false positives.

`timeout: 300s` accommodates thinking-mode models (`qwen3:8b`) which can take 60–120 s per request (in a 8GB GeForce RTX 3060).

```yaml
apiVersion: zask.io/v1alpha1
kind: ZaskConfig
spec:
  mode: lockdown
  selfProtection: false   # allow test harness to SIGKILL the daemon

  logging:
    level: debug
    format: json
    output: stdout

  mapPaths:
    verdictMap: /sys/fs/bpf/zask_verdict_map

  health:
    listenAddress: ":8082"

  rules:
    path: /etc/zask/rules.yaml

  rateLimiter:
    rate: 100
    burst: 200

  ai:
    providerUrl: "http://host.lima.internal:11434/v1/chat/completions"
    model: "qwen3:8b"
    timeout: 300s
    riskThreshold: 0.1
    maxRetries: 2
    workers: 2
    queueSize: 100
    failOpen: true

  audit:
    outputs:
      - format: json
        path: /tmp/zask-audit.log
```

---

## OpenAI (production)

The API key is read from the environment at startup — do not put the key in the config file.

```yaml
apiVersion: zask.io/v1alpha1
kind: ZaskConfig
spec:
  mode: lockdown
  selfProtection: true

  logging:
    level: info
    format: json
    output: stdout

  mapPaths:
    verdictMap: /sys/fs/bpf/zask_verdicts

  health:
    listenAddress: ":7453"

  rules:
    path: /etc/zask/rules.yaml

  rateLimiter:
    rate: 10
    burst: 20

  ai:
    providerUrl: "https://api.openai.com/v1/chat/completions"
    model: "gpt-4o"
    apiKeyEnv: "ZASK_AI_API_KEY"
    riskThreshold: 0.85
    timeout: 30s
    maxRetries: 3
    workers: 4
    queueSize: 256
    failOpen: true
    circuitBreaker:
      maxFailures: 5
      cooldownTime: 30s
      halfOpenMaxReqs: 1

  audit:
    outputs:
      - format: json
        path: /var/log/zask/audit.json
      - format: parquet
        path: /var/log/zask/audit.parquet
```

> Any OpenAI-compatible endpoint works — swap `providerUrl` and `model` for Anthropic, Azure OpenAI, or a self-hosted vLLM instance. See [ai-integration.md](ai-integration.md) for authentication details.
