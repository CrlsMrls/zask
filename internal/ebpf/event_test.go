package ebpf

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestDecodeEvent_ValidBuffer(t *testing.T) {
	size := int(unsafe.Sizeof(ZaskEvent{}))
	buf := make([]byte, size)

	binary.LittleEndian.PutUint64(buf[0:], 12345) // inode_number
	binary.LittleEndian.PutUint64(buf[8:], 67890) // cgroup_id
	binary.LittleEndian.PutUint32(buf[16:], 1001) // pid
	binary.LittleEndian.PutUint32(buf[20:], 999)  // ppid
	binary.LittleEndian.PutUint32(buf[24:], 0)    // uid
	binary.LittleEndian.PutUint32(buf[28:], 8)    // device_id
	buf[32] = 1                                   // is_map_hit
	copy(buf[33:], "/usr/bin/python3")            // argv

	ev, err := DecodeEvent(buf)
	if err != nil {
		t.Fatalf("DecodeEvent() error = %v", err)
	}

	if ev.InodeNumber != 12345 {
		t.Errorf("InodeNumber = %d, want 12345", ev.InodeNumber)
	}
	if ev.CgroupId != 67890 {
		t.Errorf("CgroupId = %d, want 67890", ev.CgroupId)
	}
	if ev.Pid != 1001 {
		t.Errorf("Pid = %d, want 1001", ev.Pid)
	}
	if ev.Ppid != 999 {
		t.Errorf("Ppid = %d, want 999", ev.Ppid)
	}
	if ev.Uid != 0 {
		t.Errorf("Uid = %d, want 0", ev.Uid)
	}
	if ev.DeviceId != 8 {
		t.Errorf("DeviceId = %d, want 8", ev.DeviceId)
	}
	if ev.IsMapHit != 1 {
		t.Errorf("IsMapHit = %d, want 1", ev.IsMapHit)
	}

	argv := ev.GetArgv()
	if argv != "/usr/bin/python3" {
		t.Errorf("GetArgv() = %q, want %q", argv, "/usr/bin/python3")
	}
}

func TestDecodeEvent_ShortBuffer(t *testing.T) {
	buf := make([]byte, 10)
	_, err := DecodeEvent(buf)
	if err == nil {
		t.Fatal("DecodeEvent() expected error for short buffer")
	}
}

func TestGetArgv_EmptyString(t *testing.T) {
	ev := ZaskEvent{}
	if argv := ev.GetArgv(); argv != "" {
		t.Errorf("GetArgv() = %q, want empty", argv)
	}
}

func TestInodeKey_Extraction(t *testing.T) {
	ev := ZaskEvent{
		InodeNumber: 42,
		DeviceId:    7,
	}
	key := ev.InodeKey()
	if key.InodeNumber != 42 {
		t.Errorf("InodeKey().InodeNumber = %d, want 42", key.InodeNumber)
	}
	if key.DeviceId != 7 {
		t.Errorf("InodeKey().DeviceId = %d, want 7", key.DeviceId)
	}
}
