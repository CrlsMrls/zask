# Shutting Down zaskd Safely

This document explains how to stop the ZASK daemon (`zaskd`) safely, considering the eBPF self-protection mechanism.

## Background: Self-Protection

When `selfProtection: true` (the default), `zaskd` registers its PID in the eBPF `protected_pids` map. The `lsm/task_kill` hook then **blocks** `SIGKILL` (9) and `SIGTERM` (15) from any external process. This prevents attackers or compromised software from terminating the security daemon.

The hook only blocks those two signals. All other signals (including `SIGINT` = 2) pass through normally. The daemon can also send `SIGKILL`/`SIGTERM` to itself (the hook checks `sender_pid == target_pid`).

## Safe Shutdown Methods

### Foreground: Ctrl+C

If `zaskd` is running in the foreground (e.g., during development), press **Ctrl+C**. This sends `SIGINT`, which is not blocked by the self-protection hook.

```bash
sudo ./zaskd --config /etc/zask/config.yaml
# Press Ctrl+C to stop
```

### Remote: `kill -INT`

To stop `zaskd` from another terminal or script, send `SIGINT` explicitly:

```bash
kill -INT $(pidof zaskd)
# or equivalently:
kill -2 $(pidof zaskd)
```

> **Warning:** The default `kill <pid>` sends `SIGTERM`, which **will be blocked** when self-protection is enabled. Always use `kill -INT`.

### systemd

When running under systemd, configure the unit to send `SIGINT` instead of the default `SIGTERM`:

```ini
[Service]
ExecStart=/usr/local/bin/zaskd --config /etc/zask/config.yaml
KillSignal=SIGINT
```

Then `systemctl stop zaskd` will send `SIGINT`, which passes through the eBPF hook and triggers the daemon's graceful shutdown.

### With Self-Protection Disabled

If self-protection is disabled in the configuration, all signals work normally:

```yaml
spec:
  selfProtection: false
```

In this case, `kill <pid>` (SIGTERM), `kill -9 <pid>` (SIGKILL), and `kill -INT <pid>` all work. This is appropriate for test environments, not production.

## What Happens During Graceful Shutdown

When `zaskd` receives `SIGINT` or `SIGTERM` (if delivered), the following sequence occurs:

1. **Context cancelled** — `signal.NotifyContext` catches the signal and cancels the root context.
2. **Ring buffer reader stops** — context cancellation causes the eBPF ring buffer reader to stop consuming events.
3. **Event channel drained** — the event processing goroutine reads all remaining events from the channel until it's closed.
4. **AI worker pool stops** — any in-flight AI analysis requests complete, and the worker pool drains its queue.
5. **Health server shuts down** — the HTTP server gets a 5-second grace period to finish in-flight requests.
6. **All goroutines join** — the main goroutine waits for all background goroutines to finish.
7. **eBPF resources released** — deferred `loader.Close()` detaches programs and closes maps.
8. **Process exits** — the daemon logs "zaskd shutdown complete" and exits with code 0.

## Commands That Do NOT Work (with self-protection)

These will be silently denied by the eBPF hook:

```bash
kill <pid>        # SIGTERM — blocked
kill -TERM <pid>  # SIGTERM — blocked
kill -9 <pid>     # SIGKILL — blocked
kill -KILL <pid>  # SIGKILL — blocked
```

