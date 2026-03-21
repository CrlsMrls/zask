package ai

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	zaskebpf "github.com/CrlsMrls/zask/internal/ebpf"
)

// VerdictCallback is invoked by the worker pool when the AI returns a
// verdict. The caller (main.go) can use this to emit audit events.
type VerdictCallback func(ev zaskebpf.ZaskEvent, result AnalysisResult, action Action)

// breakerStateOpen is the string representation of an open circuit breaker.
const breakerStateOpen = "open"

// WorkerPoolConfig configures the asynchronous AI worker pool.
type WorkerPoolConfig struct {
	// Mode is the daemon operational mode ("lockdown" or "monitor").
	// In monitor mode, BLOCK verdicts are logged but not enforced
	// (no SIGKILL, no verdict map writes).
	Mode string
	// Workers is the number of concurrent goroutines processing AI requests.
	Workers int
	// QueueSize is the capacity of the internal event queue channel.
	QueueSize int
	// RiskThreshold is the score above which an event triggers BLOCK.
	RiskThreshold float64
	// FailOpen when true, allows execution on AI failure; when false, kills.
	FailOpen bool
}

// WorkerPool manages a pool of goroutines that consume events from the
// AI queue, send them to the AI provider, and execute the feedback loop
// (verdict map update + process kill) on BLOCK verdicts.
type WorkerPool struct {
	client         *Client
	loader         *zaskebpf.Loader
	log            zerolog.Logger
	onVerdict      VerdictCallback
	queue          chan zaskebpf.ZaskEvent
	config         WorkerPoolConfig
	queueDepth     atomic.Int64
	processedTotal atomic.Int64
	wg             sync.WaitGroup
}

// NewWorkerPool creates a new worker pool. The returned pool does not
// start processing until Start is called.
func NewWorkerPool(cfg WorkerPoolConfig, client *Client, loader *zaskebpf.Loader, log zerolog.Logger) *WorkerPool {
	wpLog := log.With().Str("component", "ai-worker-pool").Logger()

	queueSize := cfg.QueueSize
	if queueSize == 0 {
		queueSize = 256
	}
	return &WorkerPool{
		client: client,
		loader: loader,
		config: cfg,
		queue:  make(chan zaskebpf.ZaskEvent, queueSize),
		log:    wpLog,
	}
}

// SetVerdictCallback sets the function called after each AI verdict.
// Must be called before Start.
func (wp *WorkerPool) SetVerdictCallback(cb VerdictCallback) {
	wp.onVerdict = cb
}

// Start launches the worker goroutines. They process events until the
// context is canceled or Stop is called.
func (wp *WorkerPool) Start(ctx context.Context) {
	workers := wp.config.Workers
	if workers == 0 {
		workers = 4
	}

	wp.log.Info().
		Int("workers", workers).
		Int("queue_size", cap(wp.queue)).
		Float64("risk_threshold", wp.config.RiskThreshold).
		Bool("fail_open", wp.config.FailOpen).
		Msg("starting AI worker pool")

	for i := 0; i < workers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}
}

// Submit queues an event for AI analysis. Returns false if the queue is
// full (event is dropped).
func (wp *WorkerPool) Submit(ev zaskebpf.ZaskEvent) bool {
	select {
	case wp.queue <- ev:
		wp.queueDepth.Add(1)
		return true
	default:
		wp.log.Warn().
			Uint32("pid", ev.Pid).
			Str("argv", ev.GetArgv()).
			Msg("AI queue full, dropping event")
		return false
	}
}

// QueueCh returns the queue channel for direct use by the engine's
// AI queue routing. This allows the engine to write directly to the
// worker pool's queue channel.
func (wp *WorkerPool) QueueCh() chan<- zaskebpf.ZaskEvent {
	return wp.queue
}

// QueueDepth returns the current number of events waiting in the queue.
func (wp *WorkerPool) QueueDepth() int64 {
	return wp.queueDepth.Load()
}

// ProcessedTotal returns the total number of events processed.
func (wp *WorkerPool) ProcessedTotal() int64 {
	return wp.processedTotal.Load()
}

// Stop waits for all workers to finish processing. The caller should
// cancel the context first to signal workers to drain and exit.
func (wp *WorkerPool) Stop() {
	wp.wg.Wait()
	wp.log.Info().Int64("total_processed", wp.processedTotal.Load()).Msg("AI worker pool stopped")
}

// worker is the main loop for a single worker goroutine.
func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	wp.log.Debug().Int("worker_id", id).Msg("AI worker started")

	for {
		select {
		case <-ctx.Done():
			// Drain remaining events from the queue on shutdown.
			wp.drain(id)
			return
		case ev, ok := <-wp.queue:
			if !ok {
				return // Channel closed.
			}
			wp.queueDepth.Add(-1)
			wp.processEvent(ctx, ev, id)
		}
	}
}

// drain processes any remaining events in the queue after context cancellation.
func (wp *WorkerPool) drain(id int) {
	for {
		select {
		case ev, ok := <-wp.queue:
			if !ok {
				return
			}
			wp.queueDepth.Add(-1)
			// Use a short timeout for drain operations.
			drainCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			wp.processEvent(drainCtx, ev, id)
			cancel()
		default:
			return
		}
	}
}

// processEvent handles a single event: enriches context, calls the AI,
// parses the verdict, and executes the feedback loop.
func (wp *WorkerPool) processEvent(ctx context.Context, ev zaskebpf.ZaskEvent, workerID int) {
	wp.processedTotal.Add(1)

	evCtx := EventContext{
		PID:         ev.Pid,
		PPID:        ev.Ppid,
		UID:         ev.Uid,
		Argv:        ev.GetArgv(),
		ScriptPath:  ev.GetScriptArgv(),
		CgroupID:    ev.CgroupId,
		InodeNumber: ev.InodeNumber,
	}
	evCtx.EnrichContext()

	result, err := wp.client.Analyze(ctx, evCtx)
	if err != nil {
		wp.log.Error().
			Err(err).
			Int("worker_id", workerID).
			Uint32("pid", ev.Pid).
			Str("argv", ev.GetArgv()).
			Msg("AI analysis failed")

		// Graduated fail mode (§3.5.3): default ALLOW or SIGKILL.
		if !wp.config.FailOpen {
			wp.log.Warn().Uint32("pid", ev.Pid).Msg("fail-closed: killing process on AI failure")
			wp.killProcess(ev.Pid)
		}
		return
	}

	action := result.Verdict.Evaluate(wp.config.RiskThreshold)

	wp.log.Info().
		Int("worker_id", workerID).
		Uint32("pid", ev.Pid).
		Str("argv", ev.GetArgv()).
		Float64("risk", result.Verdict.Risk).
		Str("action", action.String()).
		Str("model", result.Model).
		Dur("latency", result.Duration).
		Str("reasoning", result.Verdict.Reasoning).
		Msg("AI verdict")

	if action == ActionBlock {
		wp.executeBlock(ev, result)
	} else if wp.loader != nil {
		// Promote the AI ALLOW verdict to the kernel map so subsequent
		// executions of this binary bypass the ring buffer entirely.
		key := ev.InodeKey()
		if err := wp.loader.AllowInode(key); err != nil {
			wp.log.Warn().
				Err(err).
				Uint64("inode", key.InodeNumber).
				Str("argv", ev.GetArgv()).
				Msg("failed to promote AI ALLOW to verdict map")
		}
	}

	// Invoke callback for audit logging.
	if wp.onVerdict != nil {
		wp.onVerdict(ev, result, action)
	}
}

// executeBlock performs the full BLOCK feedback loop:
//  1. Resolve the binary path to an inode key.
//  2. Write a BLOCK entry to the verdict map.
//  3. Send SIGKILL to the offending process.
//
// In monitor mode, the verdict is logged but not enforced (no map write,
// no SIGKILL). The verdict callback is still invoked for audit logging.
func (wp *WorkerPool) executeBlock(ev zaskebpf.ZaskEvent, result AnalysisResult) {
	argv := ev.GetArgv()

	if wp.config.Mode == "monitor" {
		wp.log.Warn().
			Uint32("pid", ev.Pid).
			Str("argv", argv).
			Float64("risk", result.Verdict.Risk).
			Msg("monitor mode: would have blocked (no enforcement)")
		return
	}

	// Write to verdict map using the event's inode key.
	// The binary path is already resolved to an inode in the event.
	key := ev.InodeKey()
	if wp.loader != nil {
		if err := wp.loader.BlockInode(key); err != nil {
			wp.log.Error().
				Err(err).
				Str("argv", argv).
				Uint64("inode", key.InodeNumber).
				Msg("failed to update verdict map from AI verdict")
		} else {
			wp.log.Info().
				Uint64("inode", key.InodeNumber).
				Uint32("device", key.DeviceId).
				Str("argv", argv).
				Msg("verdict map updated: BLOCK")
		}
	}

	// Send SIGKILL to terminate the process (§3.4.5).
	wp.killProcess(ev.Pid)
}

// killProcess sends SIGKILL to the given PID. Non-fatal if the process
// has already exited.
func (wp *WorkerPool) killProcess(pid uint32) {
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		// ESRCH (no such process) is expected if the process already exited.
		wp.log.Debug().
			Err(err).
			Uint32("pid", pid).
			Msg("kill process (may have already exited)")
	} else {
		wp.log.Info().
			Uint32("pid", pid).
			Msg("process killed by AI verdict")
	}
}

// Healthy returns true if the circuit breaker is not open.
func (wp *WorkerPool) Healthy() bool {
	return wp.client.BreakerState() != breakerStateOpen
}

// BreakerState returns the current circuit breaker state string.
func (wp *WorkerPool) BreakerState() string {
	return wp.client.BreakerState()
}

// Stats returns observable metrics for the worker pool.
func (wp *WorkerPool) Stats() WorkerPoolStats {
	return WorkerPoolStats{
		QueueDepth:     wp.QueueDepth(),
		ProcessedTotal: wp.ProcessedTotal(),
		BreakerState:   wp.BreakerState(),
	}
}

// WorkerPoolStats holds observable metrics for the worker pool.
type WorkerPoolStats struct {
	BreakerState   string
	QueueDepth     int64
	ProcessedTotal int64
}

// String returns a human-readable summary of worker pool stats.
func (s WorkerPoolStats) String() string {
	return fmt.Sprintf("queue=%d processed=%d breaker=%s", s.QueueDepth, s.ProcessedTotal, s.BreakerState)
}
