// Package health provides HTTP health and readiness endpoints for zaskd.
//
// /healthz reports whether the daemon is alive.
// /readyz reports whether the daemon is fully initialized and ready to
// process events (eBPF loaded, ring buffer reader active).
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// Status is the JSON body returned by health endpoints.
type Status struct {
	Status        string `json:"status"`
	Daemon        string `json:"daemon"`
	Uptime        string `json:"uptime"`
	EBPFLoaded    bool   `json:"ebpfLoaded"`
	RingBufActive bool   `json:"ringBufActive"`
}

// Server is the HTTP health endpoint server.
type Server struct {
	server    *http.Server
	log       zerolog.Logger
	startTime time.Time
	ebpfReady atomic.Bool
	rbReady   atomic.Bool
}

// NewServer creates a health server listening on the given address.
func NewServer(listenAddr string, log zerolog.Logger) *Server {
	s := &Server{
		log:       log.With().Str("component", "health").Logger(),
		startTime: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	s.server = &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}

// SetEBPFReady marks the eBPF subsystem as loaded and operational.
func (s *Server) SetEBPFReady(ready bool) {
	s.ebpfReady.Store(ready)
}

// SetRingBufReady marks the ring buffer reader as active.
func (s *Server) SetRingBufReady(ready bool) {
	s.rbReady.Store(ready)
}

// Start begins serving health endpoints. Blocks until the server stops.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.server.Addr, err)
	}
	s.log.Info().Str("addr", ln.Addr().String()).Msg("health server started")
	if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("health server: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the health server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	status := Status{
		Status:        "ok",
		Daemon:        "running",
		EBPFLoaded:    s.ebpfReady.Load(),
		RingBufActive: s.rbReady.Load(),
		Uptime:        time.Since(s.startTime).Round(time.Second).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	ebpfOK := s.ebpfReady.Load()
	rbOK := s.rbReady.Load()

	status := Status{
		Status:        "ok",
		Daemon:        "running",
		EBPFLoaded:    ebpfOK,
		RingBufActive: rbOK,
		Uptime:        time.Since(s.startTime).Round(time.Second).String(),
	}

	if !ebpfOK || !rbOK {
		status.Status = "not ready"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}
