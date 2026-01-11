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

// Loader manages the lifecycle of eBPF programs and maps.
type Loader struct {
	objs     ZaskObjects
	bprmLink link.Link
	killLink link.Link
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
	// NOTE: We intentionally do NOT use collOpts.Maps.PinPath because
	// that mechanism looks for files named after the C map identifier
	// ("verdict_map"), whereas we pin at a custom path ("zask_verdicts").
	var pinRecovered bool
	if l.pinPath != "" {
		if _, err := os.Stat(l.pinPath); err == nil {
			existing, err := ebpf.LoadPinnedMap(l.pinPath, nil)
			if err != nil {
				l.log.Warn().Err(err).Str("path", l.pinPath).
					Msg("failed to recover pinned verdict map, starting fresh")
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

	if l.killLink != nil {
		if err := l.killLink.Close(); err != nil {
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
