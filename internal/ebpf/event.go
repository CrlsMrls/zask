package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// DecodeEvent deserializes a raw byte buffer from the ring buffer into
// a ZaskEvent struct. The byte layout must match the C struct defined
// in bpf/zask.c, which bpf2go generates as ZaskEvent.
func DecodeEvent(raw []byte) (ZaskEvent, error) {
	var ev ZaskEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return ZaskEvent{}, fmt.Errorf("decode event: %w", err)
	}
	return ev, nil
}

// GetArgv returns the argv field as a Go string, trimming at the first NUL byte.
func (e *ZaskEvent) GetArgv() string {
	return nullTerminatedInt8ToString(e.Argv[:])
}

// GetScriptArgv returns the script_argv field as a Go string, trimming
// at the first NUL byte. Initially populated with raw argv[1] from eBPF;
// the engine may overwrite this with the resolved script path (via procfs
// fallback) when argv[1] is a flag rather than a file path.
func (e *ZaskEvent) GetScriptArgv() string {
	return nullTerminatedInt8ToString(e.ScriptArgv[:])
}

// nullTerminatedInt8ToString converts a NUL-terminated int8 slice (C char
// array) into a Go string.
func nullTerminatedInt8ToString(data []int8) string {
	n := len(data)
	for i, b := range data {
		if b == 0 {
			n = i
			break
		}
	}
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = byte(data[i])
	}
	return string(buf)
}

// HashKey returns the child binary's content hash.
// Useful for single-binary identity (script hashing, ComputeFileHash results).
// For verdict map operations, use ExecKey() which includes the parent hash.
// Returns the zero key if HashAvailable == 0 (IMA not configured).
func (e *ZaskEvent) HashKey() ZaskHashKey {
	var k ZaskHashKey
	copy(k.Hash[:], e.Hash[:])
	return k
}

// ExecKey returns the compound exec-chain identity key for verdict map lookups.
// Key is (parent_hash, child_hash): encodes WHO invokes WHAT.
//
// When ParentHashAvailable == 0, parent_hash is all-zeros (unknown-parent
// sentinel). This correctly mismatches any verdict stored with a real parent
// hash, so unknown-parent events fall through to userspace on first encounter.
func (e *ZaskEvent) ExecKey() ZaskExecKey {
	var k ZaskExecKey
	copy(k.ParentHash[:], e.ParentHash[:])
	copy(k.ChildHash[:], e.Hash[:])
	return k
}

// InodeKey returns the inode-based key for informational/debugging purposes.
// NOTE: InodeKey is no longer used as the verdict map identity (§3c.3.5).
// It is retained for debug logging only. Use HashKey() for enforcement.
func (e *ZaskEvent) InodeKey() ZaskInodeKey {
	return ZaskInodeKey{
		InodeNumber: e.InodeNumber,
		DeviceId:    e.DeviceId,
	}
}
