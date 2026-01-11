package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestJSONWriter_ValidNDJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")

	jw, err := NewJSONWriter(path)
	if err != nil {
		t.Fatalf("NewJSONWriter() error = %v", err)
	}

	ev := AuditEvent{
		Timestamp: time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
		Pid:       1234,
		Ppid:      100,
		Uid:       0,
		Argv:      "/usr/bin/nc",
		Inode:     5678,
		DeviceID:  8,
		CgroupID:  1,
		Tier:      2,
		Action:    "BLOCK",
		RuleName:  "reverse-shell-netcat",
		Mode:      "lockdown",
	}

	if writeErr := jw.Write(ev); writeErr != nil {
		t.Fatalf("Write() error = %v", writeErr)
	}
	if closeErr := jw.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var decoded AuditEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v, data = %q", err, string(data))
	}

	if decoded.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", decoded.Pid)
	}
	if decoded.Action != "BLOCK" {
		t.Errorf("Action = %q, want %q", decoded.Action, "BLOCK")
	}
	if decoded.RuleName != "reverse-shell-netcat" {
		t.Errorf("RuleName = %q, want %q", decoded.RuleName, "reverse-shell-netcat")
	}
}

func TestTextWriter_HumanReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.txt")

	tw, err := NewTextWriter(path)
	if err != nil {
		t.Fatalf("NewTextWriter() error = %v", err)
	}

	ev := AuditEvent{
		Timestamp:  time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
		Pid:        1234,
		Uid:        0,
		Argv:       "/usr/bin/python3",
		ScriptPath: "/tmp/evil.py",
		Tier:       2,
		Action:     "BLOCK",
		RuleName:   "tmp-script",
		Mode:       "lockdown",
	}

	if writeErr := tw.Write(ev); writeErr != nil {
		t.Fatalf("Write() error = %v", writeErr)
	}
	if closeErr := tw.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	line := string(data)
	if !strings.Contains(line, "BLOCK") {
		t.Errorf("text output missing action, got: %s", line)
	}
	if !strings.Contains(line, "script=/tmp/evil.py") {
		t.Errorf("text output missing script_path, got: %s", line)
	}
	if !strings.Contains(line, "rule=tmp-script") {
		t.Errorf("text output missing rule_name, got: %s", line)
	}
	if !strings.Contains(line, "pid=1234") {
		t.Errorf("text output missing pid, got: %s", line)
	}
}

func TestAuditLogger_FanOut(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "audit.json")
	textPath := filepath.Join(dir, "audit.txt")

	jw, err := NewJSONWriter(jsonPath)
	if err != nil {
		t.Fatalf("NewJSONWriter() error = %v", err)
	}
	tw, err := NewTextWriter(textPath)
	if err != nil {
		t.Fatalf("NewTextWriter() error = %v", err)
	}

	log := zerolog.Nop()
	al := NewAuditLogger([]Writer{jw, tw}, 100, log)

	ev := AuditEvent{
		Timestamp: time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
		Pid:       42,
		Argv:      "/usr/bin/ls",
		Tier:      1,
		Action:    "ALLOW",
		Mode:      "lockdown",
	}

	al.Emit(ev)

	if closeErr := al.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile(json) error = %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("JSON audit file is empty")
	}

	textData, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatalf("ReadFile(text) error = %v", err)
	}
	if len(textData) == 0 {
		t.Error("Text audit file is empty")
	}
}

func TestParquetWriter_WritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.parquet")

	pw, err := NewParquetWriter(path)
	if err != nil {
		t.Fatalf("NewParquetWriter() error = %v", err)
	}

	ev := AuditEvent{
		Timestamp: time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
		Pid:       1234,
		Argv:      "/usr/bin/nc",
		Tier:      2,
		Action:    "BLOCK",
		Mode:      "lockdown",
	}

	if writeErr := pw.Write(ev); writeErr != nil {
		t.Fatalf("Write() error = %v", writeErr)
	}
	if closeErr := pw.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Size() == 0 {
		t.Error("Parquet file is empty")
	}
}

func TestJSONWriter_Stdout(t *testing.T) {
	jw, err := NewJSONWriter("stdout")
	if err != nil {
		t.Fatalf("NewJSONWriter(stdout) error = %v", err)
	}
	if err := jw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
