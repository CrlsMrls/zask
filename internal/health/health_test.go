package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestHealthz_ReturnsOK(t *testing.T) {
	log := zerolog.Nop()
	srv := NewServer(":0", log)
	srv.SetEBPFReady(true)
	srv.SetRingBufReady(true)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var status Status
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if status.Status != "ok" {
		t.Errorf("status.Status = %q, want %q", status.Status, "ok")
	}
	if !status.EBPFLoaded {
		t.Error("status.EBPFLoaded = false, want true")
	}
}

func TestReadyz_NotReadyWithoutEBPF(t *testing.T) {
	log := zerolog.Nop()
	srv := NewServer(":0", log)
	// Neither eBPF nor ringbuf is ready.

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	srv.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}

	var status Status
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if status.Status != "not ready" {
		t.Errorf("status.Status = %q, want %q", status.Status, "not ready")
	}
}

func TestReadyz_ReadyWithBothComponents(t *testing.T) {
	log := zerolog.Nop()
	srv := NewServer(":0", log)
	srv.SetEBPFReady(true)
	srv.SetRingBufReady(true)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	srv.handleReadyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var status Status
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if status.Status != "ok" {
		t.Errorf("status.Status = %q, want %q", status.Status, "ok")
	}
}
