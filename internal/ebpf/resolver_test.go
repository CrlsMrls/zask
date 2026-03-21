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

func TestFindScriptPath_PidZero(t *testing.T) {
	result := FindScriptPath(0)
	if result != "" {
		t.Errorf("FindScriptPath(0) = %q, want empty", result)
	}
}

func TestFindScriptPath_NonExistentPid(t *testing.T) {
	// PID that almost certainly doesn't exist.
	result := FindScriptPath(4294967)
	if result != "" {
		t.Errorf("FindScriptPath(nonexistent) = %q, want empty", result)
	}
}

func TestFindScriptInArgs(t *testing.T) {
	tests := []struct {
		name string
		want string
		args [][]byte
	}{
		{
			name: "absolute path as first arg",
			args: [][]byte{[]byte("/tmp/evil.py")},
			want: "/tmp/evil.py",
		},
		{
			name: "flags then absolute path",
			args: [][]byte{[]byte("-u"), []byte("/tmp/evil.py")},
			want: "/tmp/evil.py",
		},
		{
			name: "multiple flags then path",
			args: [][]byte{[]byte("-B"), []byte("-u"), []byte("/opt/app/main.py")},
			want: "/opt/app/main.py",
		},
		{
			name: "relative path with dot-slash",
			args: [][]byte{[]byte("./app.js")},
			want: "./app.js",
		},
		{
			name: "relative path with double-dot",
			args: [][]byte{[]byte("../scripts/run.sh")},
			want: "../scripts/run.sh",
		},
		{
			name: "bare filename (no path prefix)",
			args: [][]byte{[]byte("script.py")},
			want: "script.py",
		},
		{
			name: "flag only, no script",
			args: [][]byte{[]byte("-c"), []byte("-e")},
			want: "",
		},
		{
			name: "empty args",
			args: [][]byte{},
			want: "",
		},
		{
			name: "empty strings in args",
			args: [][]byte{[]byte(""), []byte("")},
			want: "",
		},
		{
			name: "bash -c with inline command",
			args: [][]byte{[]byte("-c"), []byte("rm -rf /")},
			want: "rm -rf /",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findScriptInArgs(tt.args)
			if got != tt.want {
				t.Errorf("findScriptInArgs() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAllowPath_MissingFile verifies that AllowPath propagates a stat error
// when the target file does not exist (no BPF kernel map required).
func TestAllowPath_MissingFile(t *testing.T) {
	l := &Loader{} // no kernel objects loaded — tests only the path resolution step
	err := l.AllowPath("/nonexistent/path/to/binary")
	if err == nil {
		t.Fatal("AllowPath() expected error for missing file, got nil")
	}
}
