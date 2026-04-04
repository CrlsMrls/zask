// Package ebpf provides eBPF program loading, map management, and kernel interaction.
//
// The loader handles the full eBPF lifecycle: loading programs into the kernel,
// attaching LSM hooks, managing pinned maps for persistence, and providing a
// ring buffer reader for event ingestion.
package ebpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/rs/zerolog"
)

// oldInodeKeySize is the verdict map key size from Phase 1–3b (inode_key).
// Used to detect pinned maps from older daemon versions during migration.
const oldInodeKeySize = 16

// oldHashKeySize is the verdict map key size from Phase 3c (hash_key: 32-byte
// flat SHA-256). Detect and migrate pinned maps from this version too.
const oldHashKeySize = 32

// Loader manages the lifecycle of eBPF programs and maps.
type Loader struct {
	objs     ZaskObjects
	bprmLink link.Link
	killLink link.Link
	exitLink link.Link
	log      zerolog.Logger
	pinPath  string
}

// LoaderOptions configures the eBPF loader.
type LoaderOptions struct {
	// VerdictMapPinPath is the BPF filesystem path where the verdict map
	// is pinned for persistence across daemon restarts. The parent
	// directory must exist and be on a BPF filesystem.
	VerdictMapPinPath string
}

// NewLoader loads eBPF programs and maps into the kernel, attaches LSM
// hooks, and optionally pins/recovers the verdict map. Callers must call
// Close to detach programs and release resources.
func NewLoader(opts LoaderOptions, log zerolog.Logger) (*Loader, error) {
	l := &Loader{
		log:     log.With().Str("component", "ebpf-loader").Logger(),
		pinPath: opts.VerdictMapPinPath,
	}

	collOpts := &ebpf.CollectionOptions{}

	// If a pin path is specified, try to recover the existing pinned map
	// (daemon restart scenario). We use MapReplacements to inject the
	// recovered map so the loaded programs reference the same FD.
	//
	// Phase 3c migration: detect pinned maps from older daemon versions
	// (inode-based key, 16 bytes) and replace with hash-based key (32 bytes).
	var pinRecovered bool
	if l.pinPath != "" {
		if _, err := os.Stat(l.pinPath); err == nil {
			existing, err := ebpf.LoadPinnedMap(l.pinPath, nil)
			if err != nil {
				l.log.Warn().Err(err).Str("path", l.pinPath).
					Msg("failed to recover pinned verdict map, starting fresh")
			} else {
				info, infoErr := existing.Info()
				if infoErr == nil && (info.KeySize == oldInodeKeySize || info.KeySize == oldHashKeySize) {
					// Old map detected (inode-based 16-byte or flat-hash 32-byte key).
					// Unpin and discard; the new exec-chain key is 64 bytes.
					existing.Close()
					if unpinErr := os.Remove(l.pinPath); unpinErr != nil {
						l.log.Warn().Err(unpinErr).Str("path", l.pinPath).
							Msg("failed to remove old verdict map pin")
					}
					l.log.Warn().Str("path", l.pinPath).
						Msg("migrating verdict map to exec-chain identity, existing verdicts will be re-learned")
				} else {
					l.log.Info().Str("path", l.pinPath).
						Msg("recovered existing pinned verdict map")
					collOpts.MapReplacements = map[string]*ebpf.Map{
						"verdict_map": existing,
					}
					pinRecovered = true
				}
			}
		}
	}

	if err := LoadZaskObjects(&l.objs, collOpts); err != nil {
		return nil, fmt.Errorf("load ebpf objects: %w", err)
	}

	// Pin the verdict map only if it wasn't already pinned.
	if l.pinPath != "" && !pinRecovered {
		if err := l.objs.VerdictMap.Pin(l.pinPath); err != nil {
			l.objs.Close()
			return nil, fmt.Errorf("pin verdict map to %s: %w", l.pinPath, err)
		}
	}

	// Attach LSM hooks.
	var err error
	l.bprmLink, err = link.AttachLSM(link.LSMOptions{
		Program: l.objs.ZaskBprmCheck,
	})
	if err != nil {
		l.objs.Close()
		return nil, fmt.Errorf("attach lsm/bprm_check_security: %w", err)
	}

	l.killLink, err = link.AttachLSM(link.LSMOptions{
		Program: l.objs.ZaskTaskKill,
	})
	if err != nil {
		l.bprmLink.Close()
		l.objs.Close()
		return nil, fmt.Errorf("attach lsm/task_kill: %w", err)
	}

	// Attach the sched_process_exit tracepoint to evict dead PIDs from
	// pid_hash_map, preventing PID reuse from contaminating parent hash lookups.
	l.exitLink, err = link.Tracepoint("sched", "sched_process_exit", l.objs.ZaskProcessExit, nil)
	if err != nil {
		l.killLink.Close()
		l.bprmLink.Close()
		l.objs.Close()
		return nil, fmt.Errorf("attach tp/sched/sched_process_exit: %w", err)
	}

	l.log.Info().Msg("ebpf programs loaded and LSM hooks attached")
	return l, nil
}

// RegisterProtectedPID writes the given PID into the protected_pids map
// so the lsm/task_kill hook can prevent unauthorized termination.
func (l *Loader) RegisterProtectedPID(pid uint32) error {
	val := uint32(1)
	if err := l.objs.ProtectedPids.Put(pid, val); err != nil {
		return fmt.Errorf("register protected pid %d: %w", pid, err)
	}
	l.log.Info().Uint32("pid", pid).Msg("pid registered for self-protection")
	return nil
}

// Objects returns the loaded eBPF objects for direct map access.
func (l *Loader) Objects() *ZaskObjects {
	return &l.objs
}

// Close detaches eBPF programs and closes map file descriptors.
// Pinned maps remain on the BPF filesystem for future recovery.
func (l *Loader) Close() error {
	var firstErr error

	if l.exitLink != nil {
		if err := l.exitLink.Close(); err != nil {
			firstErr = fmt.Errorf("detach tp/sched/sched_process_exit: %w", err)
		}
	}

	if l.killLink != nil {
		if err := l.killLink.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("detach lsm/task_kill: %w", err)
		}
	}

	if l.bprmLink != nil {
		if err := l.bprmLink.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("detach lsm/bprm_check_security: %w", err)
		}
	}

	if err := l.objs.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("close ebpf objects: %w", err)
	}

	l.log.Info().Msg("ebpf programs detached, pinned maps preserved")
	return firstErr
}

// AllowExec writes an ALLOW verdict (value=0) for the exec-chain key into
// the kernel verdict map. The kernel eBPF hook fast-paths subsequent
// executions of the same (parent, child) binary pair: no ring buffer event
// is emitted and execution proceeds immediately.
//
// Writes are logged at Debug level only — ALLOW writes are high-frequency
// and logging them at Info would overwhelm the audit log.
func (l *Loader) AllowExec(key ZaskExecKey) error {
	verdict := uint32(0) // VERDICT_ALLOW
	if err := l.objs.VerdictMap.Put(key, verdict); err != nil {
		return fmt.Errorf("write verdict map: %w", err)
	}
	l.log.Debug().
		Str("parent_hash", fmt.Sprintf("%x", key.ParentHash)).
		Str("child_hash", fmt.Sprintf("%x", key.ChildHash)).
		Msg("exec chain allowed in verdict map")
	return nil
}

// BlockExec writes a BLOCK verdict (value=1) for the exec-chain key into
// the kernel verdict map. Any execution of the same (parent, child) binary
// pair will be denied at the kernel level.
func (l *Loader) BlockExec(key ZaskExecKey) error {
	verdict := uint32(1) // VERDICT_BLOCK
	if err := l.objs.VerdictMap.Put(key, verdict); err != nil {
		return fmt.Errorf("write verdict map: %w", err)
	}
	l.log.Info().
		Str("parent_hash", fmt.Sprintf("%x", key.ParentHash)).
		Str("child_hash", fmt.Sprintf("%x", key.ChildHash)).
		Msg("exec chain blocked in verdict map")
	return nil
}

// ReadBaselineAllowCounter reads the per-CPU baseline_allow_counter and
// returns the total number of kernel ALLOW fast-path hits (sum across all CPUs).
// Phase 4 calls this periodically to expose the value as a Prometheus gauge.
func (l *Loader) ReadBaselineAllowCounter() (uint64, error) {
	var idx uint32
	var values []uint64
	if err := l.objs.BaselineAllowCounter.Lookup(idx, &values); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read baseline allow counter: %w", err)
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

// ReadDropCounter reads the per-CPU drop counter from the kernel and
// returns the total number of dropped events (sum across all CPUs).
func (l *Loader) ReadDropCounter() (uint64, error) {
	var idx uint32
	var values []uint64
	if err := l.objs.DropCounter.Lookup(idx, &values); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read drop counter: %w", err)
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}
