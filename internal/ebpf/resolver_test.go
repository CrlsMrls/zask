package ebpf

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestResolvePathToInode_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testbin")
	if err := os.WriteFile(path, []byte("test"), 0o755); err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	key, err := ResolvePathToInode(path)
	if err != nil {
		t.Fatalf("ResolvePathToInode() error = %v", err)
	}

	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		t.Fatalf("stat: %v", err)
	}

	if key.InodeNumber != stat.Ino {
		t.Errorf("InodeNumber = %d, want %d (from stat)", key.InodeNumber, stat.Ino)
	}
	if key.DeviceId != uint32(stat.Dev) {
		t.Errorf("DeviceId = %d, want %d (from stat)", key.DeviceId, uint32(stat.Dev))
	}
}

func TestResolvePathToInode_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	lnk := filepath.Join(dir, "link")

	if err := os.WriteFile(target, []byte("target"), 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := os.Symlink(target, lnk); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	targetKey, err := ResolvePathToInode(target)
	if err != nil {
		t.Fatalf("ResolvePathToInode(target) error = %v", err)
	}

	linkKey, err := ResolvePathToInode(lnk)
	if err != nil {
		t.Fatalf("ResolvePathToInode(link) error = %v", err)
	}

	if targetKey.InodeNumber != linkKey.InodeNumber {
		t.Errorf("symlink inode %d != target inode %d", linkKey.InodeNumber, targetKey.InodeNumber)
	}
	if targetKey.DeviceId != linkKey.DeviceId {
		t.Errorf("symlink device %d != target device %d", linkKey.DeviceId, targetKey.DeviceId)
	}
}

func TestResolvePathToInode_MissingFile(t *testing.T) {
	_, err := ResolvePathToInode("/nonexistent/path/to/file")
	if err == nil {
		t.Fatal("ResolvePathToInode() expected error for missing file, got nil")
	}
}
