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

// Argv returns the argv field as a Go string, trimming at the first NUL byte.
func (e *ZaskEvent) GetArgv() string {
	// Find the first NUL byte to determine string length.
	n := len(e.Argv)
	for i, b := range e.Argv {
		if b == 0 {
			n = i
			break
		}
	}
	// Convert from int8 (C char) to byte slice.
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = byte(e.Argv[i])
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
