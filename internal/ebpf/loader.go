// Package ebpf provides eBPF program loading, map management, and kernel interaction.
//
// The loader handles the full eBPF lifecycle: loading programs into the kernel,
// attaching LSM hooks, managing pinned maps for persistence, and providing a
// ring buffer reader for event ingestion.
package ebpf

import (
	"fmt"
	"os"
	"path/filepath"

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
	// If a pin path is specified, try to recover existing pinned maps
	// (daemon restart scenario). Set the pin path on the collection so
	// LoadAndAssign reuses existing maps from the BPF filesystem.
	if l.pinPath != "" {
		pinDir := filepath.Dir(l.pinPath)
		collOpts.Maps.PinPath = pinDir

		// Check if pinned map already exists — if so, we're reattaching.
		if _, err := os.Stat(l.pinPath); err == nil {
			l.log.Info().Str("path", l.pinPath).Msg("found existing pinned verdict map, recovering")
		}
	}

	if err := LoadZaskObjects(&l.objs, collOpts); err != nil {
		return nil, fmt.Errorf("load ebpf objects: %w", err)
	}

	// Pin the verdict map if a path is specified and it's not already pinned.
	if l.pinPath != "" {
		if err := l.objs.VerdictMap.Pin(l.pinPath); err != nil {
			// EEXIST is OK — map was already pinned (recovered).
			if !os.IsExist(err) {
				l.objs.Close()
				return nil, fmt.Errorf("pin verdict map to %s: %w", l.pinPath, err)
			}
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
