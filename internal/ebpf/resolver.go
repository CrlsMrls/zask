package ebpf

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// ResolvePathToInode translates an absolute file path to its underlying
// inode_number and device_id. Symlinks are resolved to their target.
func ResolvePathToInode(path string) (ZaskInodeKey, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return ZaskInodeKey{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return ZaskInodeKey{
		InodeNumber: stat.Ino,
		DeviceId:    uint32(stat.Dev),
	}, nil
}

// FindScriptPath reads /proc/[pid]/cmdline and returns the first argument
// that looks like a file path (starts with '/' or './'). This handles
// interpreters invoked with flags before the script path, e.g.:
//
//	python3 -u /tmp/evil.py  → "/tmp/evil.py"
//	bash -c "rm -rf /"      → "" (no path-like arg)
//	node ./app.js            → "./app.js"
//
// Returns "" if the process has exited or no path-like argument is found.
// The pid 0 is never read (kernel idle).
func FindScriptPath(pid uint32) string {
	if pid == 0 {
		return ""
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "" // process already exited — non-fatal
	}
	// cmdline is NUL-separated: ["python3", "-u", "/tmp/evil.py", ""]
	args := bytes.Split(data, []byte{0})
	// Skip argv[0] (the interpreter itself), scan remaining args.
	if len(args) > 1 {
		return findScriptInArgs(args[1:])
	}
	return ""
}

// findScriptInArgs scans a list of command-line arguments (already split)
// and returns the first that looks like a script path, skipping flags.
func findScriptInArgs(args [][]byte) string {
	for _, arg := range args {
		s := string(arg)
		if s == "" {
			continue
		}
		// Skip flags (args starting with '-').
		if strings.HasPrefix(s, "-") {
			continue
		}
		// Accept arguments that look like file paths.
		if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
			return s
		}
		// Also accept bare filenames (e.g., "script.py") — the first
		// non-flag argument is likely the script in most interpreter
		// invocations. Stop at the first candidate.
		return s
	}
	return ""
}

// BlockPath resolves a file path to its inode key and writes a BLOCK
// entry into the verdict map. This is the primary API for the AI feedback
// loop to block a binary after analysis.
func (l *Loader) BlockPath(path string) error {
	key, err := ResolvePathToInode(path)
	if err != nil {
		return fmt.Errorf("resolve path %s: %w", path, err)
	}
	return l.BlockInode(key)
}

// BlockInode writes a BLOCK verdict (value=1) into the kernel verdict map
// for the given inode key.
func (l *Loader) BlockInode(key ZaskInodeKey) error {
	verdict := uint32(1) // VERDICT_BLOCK
	if err := l.objs.VerdictMap.Put(key, verdict); err != nil {
		return fmt.Errorf("write verdict map: %w", err)
	}
	l.log.Info().
		Uint64("inode", key.InodeNumber).
		Uint32("device", key.DeviceId).
		Msg("inode blocked in verdict map")
	return nil
}

// ReadDropCounter reads the per-CPU drop counter from the kernel and
// returns the total number of dropped events (sum across all CPUs).
func (l *Loader) ReadDropCounter() (uint64, error) {
	var idx uint32
	var values []uint64
	if err := l.objs.DropCounter.Lookup(idx, &values); err != nil {
		// If the map isn't populated yet, return 0.
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
