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

// InodeKey extracts the inode key from the event for map lookups.
func (e *ZaskEvent) InodeKey() ZaskInodeKey {
	return ZaskInodeKey{
		InodeNumber: e.InodeNumber,
		DeviceId:    e.DeviceId,
	}
}
