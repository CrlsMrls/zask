package ebpf

import (
	"fmt"
	"os"
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
