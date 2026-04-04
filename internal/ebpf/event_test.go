package ebpf

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestDecodeEvent_ValidBuffer(t *testing.T) {
	size := int(unsafe.Sizeof(ZaskEvent{}))
	buf := make([]byte, size)

	// Use unsafe.Offsetof so the test stays correct if the struct is reordered.
	isMapHitOff := int(unsafe.Offsetof(ZaskEvent{}.IsMapHit))
	hashAvailOff := int(unsafe.Offsetof(ZaskEvent{}.HashAvailable))
	hashOff := int(unsafe.Offsetof(ZaskEvent{}.Hash))
	parentHashAvailOff := int(unsafe.Offsetof(ZaskEvent{}.ParentHashAvailable))
	parentHashOff := int(unsafe.Offsetof(ZaskEvent{}.ParentHash))
	argvOff := int(unsafe.Offsetof(ZaskEvent{}.Argv))
	scriptArgvOff := int(unsafe.Offsetof(ZaskEvent{}.ScriptArgv))

	binary.LittleEndian.PutUint64(buf[0:], 12345) // inode_number
	binary.LittleEndian.PutUint64(buf[8:], 67890) // cgroup_id
	binary.LittleEndian.PutUint32(buf[16:], 1001) // pid
	binary.LittleEndian.PutUint32(buf[20:], 999)  // ppid
	binary.LittleEndian.PutUint32(buf[24:], 0)    // uid
	binary.LittleEndian.PutUint32(buf[28:], 8)    // device_id
	buf[isMapHitOff] = 1                          // is_map_hit
	buf[hashAvailOff] = 1                         // hash_available
	buf[hashOff] = 0xAB                           // hash[0]
	buf[hashOff+1] = 0xCD                         // hash[1]
	buf[parentHashAvailOff] = 1                   // parent_hash_available
	buf[parentHashOff] = 0xDE                     // parent_hash[0]
	buf[parentHashOff+1] = 0xAD                   // parent_hash[1]
	copy(buf[argvOff:], "/usr/bin/python3")       // argv
	copy(buf[scriptArgvOff:], "/tmp/test.py")     // script_argv

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
	if ev.HashAvailable != 1 {
		t.Errorf("HashAvailable = %d, want 1", ev.HashAvailable)
	}
	if ev.Hash[0] != 0xAB || ev.Hash[1] != 0xCD {
		t.Errorf("Hash[0:2] = %x %x, want ab cd", ev.Hash[0], ev.Hash[1])
	}
	if ev.ParentHashAvailable != 1 {
		t.Errorf("ParentHashAvailable = %d, want 1", ev.ParentHashAvailable)
	}
	if ev.ParentHash[0] != 0xDE || ev.ParentHash[1] != 0xAD {
		t.Errorf("ParentHash[0:2] = %x %x, want de ad", ev.ParentHash[0], ev.ParentHash[1])
	}
	key := ev.HashKey()
	if key.Hash[0] != 0xAB || key.Hash[1] != 0xCD {
		t.Errorf("HashKey().Hash[0:2] = %x %x, want ab cd", key.Hash[0], key.Hash[1])
	}

	argv := ev.GetArgv()
	if argv != "/usr/bin/python3" {
		t.Errorf("GetArgv() = %q, want %q", argv, "/usr/bin/python3")
	}

	scriptArgv := ev.GetScriptArgv()
	if scriptArgv != "/tmp/test.py" {
		t.Errorf("GetScriptArgv() = %q, want %q", scriptArgv, "/tmp/test.py")
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

func TestGetScriptArgv_EmptyString(t *testing.T) {
	ev := ZaskEvent{}
	if s := ev.GetScriptArgv(); s != "" {
		t.Errorf("GetScriptArgv() = %q, want empty", s)
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

func TestHashKey_Extraction(t *testing.T) {
	ev := ZaskEvent{HashAvailable: 1}
	ev.Hash[0] = 0x11
	ev.Hash[31] = 0xFF

	key := ev.HashKey()
	if key.Hash[0] != 0x11 {
		t.Errorf("HashKey().Hash[0] = %x, want 0x11", key.Hash[0])
	}
	if key.Hash[31] != 0xFF {
		t.Errorf("HashKey().Hash[31] = %x, want 0xff", key.Hash[31])
	}
}

func TestExecKey_Extraction(t *testing.T) {
	ev := ZaskEvent{HashAvailable: 1, ParentHashAvailable: 1}
	ev.ParentHash[0] = 0xAA
	ev.ParentHash[31] = 0xBB
	ev.Hash[0] = 0xCC
	ev.Hash[31] = 0xDD

	key := ev.ExecKey()
	if key.ParentHash[0] != 0xAA {
		t.Errorf("ExecKey().ParentHash[0] = %x, want 0xaa", key.ParentHash[0])
	}
	if key.ParentHash[31] != 0xBB {
		t.Errorf("ExecKey().ParentHash[31] = %x, want 0xbb", key.ParentHash[31])
	}
	if key.ChildHash[0] != 0xCC {
		t.Errorf("ExecKey().ChildHash[0] = %x, want 0xcc", key.ChildHash[0])
	}
	if key.ChildHash[31] != 0xDD {
		t.Errorf("ExecKey().ChildHash[31] = %x, want 0xdd", key.ChildHash[31])
	}
}

func TestExecKey_UnknownParentSentinel(t *testing.T) {
	// When ParentHashAvailable == 0, ParentHash should be all-zeros sentinel.
	ev := ZaskEvent{HashAvailable: 1, ParentHashAvailable: 0}
	ev.Hash[0] = 0x42
	// ParentHash is zero-initialized (default Go value).

	key := ev.ExecKey()
	var zeroHash [32]uint8
	if key.ParentHash != zeroHash {
		t.Errorf("ExecKey().ParentHash should be all-zeros for unknown parent, got %x", key.ParentHash)
	}
	if key.ChildHash[0] != 0x42 {
		t.Errorf("ExecKey().ChildHash[0] = %x, want 0x42", key.ChildHash[0])
	}
}
