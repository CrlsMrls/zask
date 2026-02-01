// Package audit provides multi-format structured audit logging for ZASK.
//
// All engine decisions (Tier 1 cache hits, Tier 2 rule matches, Tier 3
// AI verdicts) are streamed to one or more audit outputs. Supported formats:
//
//   - JSON (NDJSON): one JSON object per line, for SIEM integration.
//   - Parquet: columnar format for data lake analytics.
//   - Text: human-readable log lines for operator consoles.
//
// The AuditLogger fans out events to all configured writers via a buffered
// internal channel, ensuring non-blocking operation for the engine.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/parquet-go/parquet-go"
)

// AuditEvent captures the full context of an engine decision.
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"  parquet:"timestamp,timestamp"`
	Argv       string    `json:"argv"       parquet:"argv"`
	ScriptPath string    `json:"script_path,omitempty" parquet:"script_path,optional"`
	Action     string    `json:"action"     parquet:"action"`
	RuleName   string    `json:"rule_name,omitempty"  parquet:"rule_name,optional"`
	Mode       string    `json:"mode"       parquet:"mode"`
	Reasoning  string    `json:"reasoning,omitempty"  parquet:"reasoning,optional"`
	AIModel    string    `json:"ai_model,omitempty"   parquet:"ai_model,optional"`
	Inode      uint64    `json:"inode"      parquet:"inode"`
	CgroupID   uint64    `json:"cgroup_id"  parquet:"cgroup_id"`
	AIRisk     float64   `json:"ai_risk,omitempty"    parquet:"ai_risk,optional"`
	Pid        uint32    `json:"pid"        parquet:"pid"`
	Ppid       uint32    `json:"ppid"       parquet:"ppid"`
	Uid        uint32    `json:"uid"        parquet:"uid"`
	DeviceID   uint32    `json:"device_id"  parquet:"device_id"`
	Tier       int       `json:"tier"       parquet:"tier"`
}

// Writer is the interface implemented by all audit output formats.
type Writer interface {
	Write(event AuditEvent) error
	Close() error
}

// AuditLogger fans out AuditEvents to multiple Writers.
type AuditLogger struct {
	log     zerolog.Logger
	ch      chan AuditEvent
	writers []Writer
	wg      sync.WaitGroup
}

// NewAuditLogger creates a new AuditLogger with the given writers.
// Events are buffered in a channel of the given capacity.
func NewAuditLogger(writers []Writer, bufSize int, log zerolog.Logger) *AuditLogger {
	if bufSize <= 0 {
		bufSize = 1024
	}
	al := &AuditLogger{
		writers: writers,
		ch:      make(chan AuditEvent, bufSize),
		log:     log.With().Str("component", "audit").Logger(),
	}
	al.wg.Add(1)
	go al.run()
	return al
}

// Emit sends an audit event to all writers (non-blocking).
func (al *AuditLogger) Emit(event AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	select {
	case al.ch <- event:
	default:
		al.log.Warn().Msg("audit channel full, event dropped")
	}
}

// Close drains pending events and closes all writers.
func (al *AuditLogger) Close() error {
	close(al.ch)
	al.wg.Wait()

	var firstErr error
	for _, w := range al.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (al *AuditLogger) run() {
	defer al.wg.Done()
	for ev := range al.ch {
		for _, w := range al.writers {
			if err := w.Write(ev); err != nil {
				al.log.Error().Err(err).Msg("audit write error")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// JSON (NDJSON) Writer
// ---------------------------------------------------------------------------

// JSONWriter writes audit events as NDJSON (one JSON object per line).
type JSONWriter struct {
	w   io.WriteCloser
	enc *json.Encoder
	mu  sync.Mutex
}

// NewJSONWriter creates a JSON audit writer to the given path.
// Use "stdout" or "stderr" for standard streams.
func NewJSONWriter(path string) (*JSONWriter, error) {
	w, err := openOutput(path)
	if err != nil {
		return nil, fmt.Errorf("open json audit output %s: %w", path, err)
	}
	return &JSONWriter{
		w:   w,
		enc: json.NewEncoder(w),
	}, nil
}

// Write serializes the event as a single JSON line.
func (jw *JSONWriter) Write(ev AuditEvent) error {
	jw.mu.Lock()
	defer jw.mu.Unlock()
	return jw.enc.Encode(ev)
}

// Close closes the underlying writer.
func (jw *JSONWriter) Close() error {
	return jw.w.Close()
}

// ---------------------------------------------------------------------------
// Text Writer (Human-Readable)
// ---------------------------------------------------------------------------

// TextWriter writes audit events as human-readable text lines.
type TextWriter struct {
	w  io.WriteCloser
	mu sync.Mutex
}

// NewTextWriter creates a text audit writer to the given path.
func NewTextWriter(path string) (*TextWriter, error) {
	w, err := openOutput(path)
	if err != nil {
		return nil, fmt.Errorf("open text audit output %s: %w", path, err)
	}
	return &TextWriter{w: w}, nil
}

// Write formats the event as a human-readable line.
func (tw *TextWriter) Write(ev AuditEvent) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	script := ""
	if ev.ScriptPath != "" {
		script = fmt.Sprintf(" script=%s", ev.ScriptPath)
	}
	rule := ""
	if ev.RuleName != "" {
		rule = fmt.Sprintf(" rule=%s", ev.RuleName)
	}

	line := fmt.Sprintf("%s  %-8s  tier=%d  pid=%-6d  uid=%-5d  argv=%s%s%s  mode=%s\n",
		ev.Timestamp.Format(time.RFC3339),
		ev.Action,
		ev.Tier,
		ev.Pid,
		ev.Uid,
		ev.Argv,
		script,
		rule,
		ev.Mode,
	)
	_, err := tw.w.Write([]byte(line))
	return err
}

// Close closes the underlying writer.
func (tw *TextWriter) Close() error {
	return tw.w.Close()
}

// ---------------------------------------------------------------------------
// Parquet Writer
// ---------------------------------------------------------------------------

// ParquetWriter writes audit events in Apache Parquet columnar format.
type ParquetWriter struct {
	f  *os.File
	pw *parquet.GenericWriter[AuditEvent]
	mu sync.Mutex
}

// NewParquetWriter creates a Parquet audit writer to the given path.
func NewParquetWriter(path string) (*ParquetWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open parquet audit output %s: %w", path, err)
	}

	pw := parquet.NewGenericWriter[AuditEvent](f)

	return &ParquetWriter{f: f, pw: pw}, nil
}

// Write appends the event to the Parquet file.
func (pw *ParquetWriter) Write(ev AuditEvent) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	_, err := pw.pw.Write([]AuditEvent{ev})
	return err
}

// Close flushes and closes the Parquet writer and underlying file.
func (pw *ParquetWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if err := pw.pw.Close(); err != nil {
		pw.f.Close()
		return fmt.Errorf("close parquet writer: %w", err)
	}
	return pw.f.Close()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nopWriteCloser wraps an io.Writer with a no-op Close.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

// openOutput opens a file for writing or returns stdout/stderr.
func openOutput(path string) (io.WriteCloser, error) {
	switch path {
	case "stdout":
		return nopWriteCloser{os.Stdout}, nil
	case "stderr":
		return nopWriteCloser{os.Stderr}, nil
	default:
		return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
}
