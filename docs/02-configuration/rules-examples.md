# Rules Examples

Practical CEL rule patterns for Deterministic engine. All these rules were executed and validated.

The rule engine short-circuits on the first match, so order matters. Rules are evaluated **top-to-bottom, first match wins**. Put BLOCK rules before ALLOW rules. 

---

## Blocking threats

```yaml
rules:
  # Netcat reverse shell: nc -e /bin/sh <ip> <port>
  - name: reverse-shell-netcat
    condition: 'argv.contains("nc") && argv.contains("-e") && (argv.contains("/bin/sh") || argv.contains("/bin/bash"))'
    action: BLOCK
    severity: critical

  # Bash /dev/tcp reverse shell
  - name: reverse-shell-bash-tcp
    condition: 'argv.contains("/dev/tcp/")'
    action: BLOCK
    severity: critical

  # Scripts dropped into /tmp and run as root — common post-exploitation pattern
  - name: tmp-script-root
    condition: 'script_path.startsWith("/tmp/") && uid == 0'
    action: BLOCK
    severity: high
```

## Alerting (log, don't kill)

```yaml
  # curl/wget piped to shell — suspicious but may be legitimate in some setups
  - name: curl-pipe-shell
    condition: '(argv.contains("curl") || argv.contains("wget")) && argv.contains("|") && (argv.contains("sh") || argv.contains("bash"))'
    action: ALERT
    severity: high

  # base64 decode piped to shell — obfuscated execution
  - name: base64-decode-exec
    condition: 'argv.contains("base64") && (argv.contains("-d") || argv.contains("--decode")) && argv.contains("sh")'
    action: ALERT
    severity: high
```

## Allowlisting trusted binaries

ALLOW rules short-circuit Tier 3: once matched, the exec-chain key `(parent_hash, child_hash)` is added to the Tier 1 cache, written to the kernel `verdict_map` as `VERDICT_ALLOW`, and AI analysis is skipped on every future run. On the **second and subsequent executions** the eBPF hook handles the binary entirely in-kernel (single map lookup, no ring buffer event, < 1 μs). Place these **after** all BLOCK/ALERT rules.

```yaml
  # Specific binary by exact path
  - name: allow-containerd
    condition: 'argv == "/usr/bin/containerd"'
    action: ALLOW
    severity: low

  # Broad catchall for standard system paths — place last
  - name: allow-system-bins
    condition: 'argv.startsWith("/usr/bin/") || argv.startsWith("/usr/sbin/") || argv.startsWith("/bin/") || argv.startsWith("/sbin/")'
    action: ALLOW
    severity: low
```

> Without ALLOW rules, every system binary (`ls`, `curl`, `id`, ...) is routed to AI on its first execution. In a busy environment this floods the Tier 3 queue and can delay real verdicts by seconds.

---

## CEL variables

| Variable | Type | Description |
|---|---|---|
| `argv` | string | Full binary path as passed to `execve` |
| `script_path` | string | Resolved script path when an interpreter is detected (e.g. `python3 /tmp/evil.py` → `/tmp/evil.py`) |
| `uid` | int | User ID of the calling process |
| `pid` / `ppid` | int | Process and parent process IDs |
| `cgroup_id` | int | cgroup ID — useful for distinguishing host vs. container |
| `inode` | int | Binary inode number |

For the full field reference and validation rules see [configuration.md](configuration.md#specrules).
