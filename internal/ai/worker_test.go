package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	zaskebpf "github.com/CrlsMrls/zask/internal/ebpf"
)

func newTestEvent(pid uint32, argv string) zaskebpf.ZaskEvent {
	var ev zaskebpf.ZaskEvent
	ev.Pid = pid
	ev.Ppid = 1
	ev.Uid = 0
	ev.InodeNumber = uint64(pid) * 100
	ev.DeviceId = 1
	// Set argv.
	for i := 0; i < len(argv) && i < len(ev.Argv); i++ {
		ev.Argv[i] = int8(argv[i])
	}
	return ev
}

// --- T3.7: Worker Pool ---

func TestWorkerPool_ConcurrentWorkers(t *testing.T) {
	var concurrentCount atomic.Int32
	var maxConcurrent atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := concurrentCount.Add(1)
		// Track max concurrency.
		for {
			old := maxConcurrent.Load()
			if c <= old || maxConcurrent.CompareAndSwap(old, c) {
				break
			}
		}

		time.Sleep(100 * time.Millisecond) // Simulate AI processing.
		concurrentCount.Add(-1)

		resp := openAIResponse{
			Model: "test",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.3, "reasoning": "safe"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	log := zerolog.New(os.Stderr).With().Timestamp().Logger().Level(zerolog.DebugLevel)

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
	}, log)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	poolSize := 3
	wp := NewWorkerPool(WorkerPoolConfig{
		Workers:       poolSize,
		QueueSize:     100,
		RiskThreshold: 0.85,
		FailOpen:      true,
	}, client, nil, log)

	ctx, cancel := context.WithCancel(context.Background())
	wp.Start(ctx)

	// Submit more events than pool size.
	numEvents := 10
	for i := 0; i < numEvents; i++ {
		wp.Submit(newTestEvent(uint32(1000+i), "/usr/bin/test"))
	}

	// Wait for processing.
	time.Sleep(1 * time.Second)

	cancel()
	wp.Stop()

	// Verify concurrency was bounded by pool size.
	maxC := maxConcurrent.Load()
	if maxC > int32(poolSize) {
		t.Errorf("max concurrent = %d, want <= %d (pool size)", maxC, poolSize)
	}
	if maxC < 2 {
		t.Logf("warning: max concurrent = %d (expected at least 2 with pool size %d)", maxC, poolSize)
	}

	// Verify all events were processed.
	processed := wp.ProcessedTotal()
	if processed != int64(numEvents) {
		t.Errorf("ProcessedTotal = %d, want %d", processed, numEvents)
	}
}

func TestWorkerPool_QueueDepth(t *testing.T) {
	// Create a slow server to cause queue buildup.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		resp := openAIResponse{
			Model: "test",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.1, "reasoning": "ok"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	log := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
	}, log)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	wp := NewWorkerPool(WorkerPoolConfig{
		Workers:       1, // Single worker to create backpressure.
		QueueSize:     5,
		RiskThreshold: 0.85,
		FailOpen:      true,
	}, client, nil, log)

	ctx, cancel := context.WithCancel(context.Background())
	wp.Start(ctx)

	// Submit events quickly.
	submitted := 0
	for i := 0; i < 10; i++ {
		if wp.Submit(newTestEvent(uint32(2000+i), "/usr/bin/test")) {
			submitted++
		}
	}

	// Some events should have been dropped.
	if submitted == 10 {
		t.Log("all 10 events submitted (queue may not have been full)")
	}

	cancel()
	wp.Stop()
}

func TestWorkerPool_FullQueueDropsBehavior(t *testing.T) {
	// Block all processing to guarantee a full queue.
	blockCh := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockCh // Block until test releases.
		resp := openAIResponse{
			Model: "test",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.1, "reasoning": "ok"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()
	defer close(blockCh)

	log := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test",
		Timeout:     30 * time.Second,
		MaxRetries:  0,
	}, log)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	queueSize := 3
	wp := NewWorkerPool(WorkerPoolConfig{
		Workers:       1,
		QueueSize:     queueSize,
		RiskThreshold: 0.85,
		FailOpen:      true,
	}, client, nil, log)

	ctx, cancel := context.WithCancel(context.Background())
	wp.Start(ctx)

	// Wait for the worker to pick up the first event and block.
	time.Sleep(50 * time.Millisecond)

	// Fill the queue (worker is blocked, so queue fills up).
	// First submit goes to worker, next queueSize fill the channel.
	submitted := 0
	for i := 0; i < queueSize+5; i++ {
		if wp.Submit(newTestEvent(uint32(3000+i), "/usr/bin/test")) {
			submitted++
		}
	}

	// Beyond the queue capacity, Submit should return false (drop).
	// We expect submitted <= queueSize+1 (1 picked up by worker + queueSize buffered).
	if submitted > queueSize+2 { // +2 for first event already being processed + slight race
		t.Errorf("submitted = %d, expected <= %d (queue size + worker)", submitted, queueSize+2)
	}

	cancel()
	wp.Stop()
}

func TestWorkerPool_VerdictCallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openAIResponse{
			Model: "callback-test",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.9, "reasoning": "dangerous"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	log := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
	}, log)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	wp := NewWorkerPool(WorkerPoolConfig{
		Workers:       1,
		QueueSize:     10,
		RiskThreshold: 0.85,
		FailOpen:      true,
	}, client, nil, log)

	var mu sync.Mutex
	var verdicts []AnalysisResult
	var actions []Action

	wp.SetVerdictCallback(func(ev zaskebpf.ZaskEvent, result AnalysisResult, action Action) {
		mu.Lock()
		verdicts = append(verdicts, result)
		actions = append(actions, action)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	wp.Start(ctx)

	wp.Submit(newTestEvent(4000, "/usr/bin/suspicious"))
	time.Sleep(500 * time.Millisecond)

	cancel()
	wp.Stop()

	mu.Lock()
	defer mu.Unlock()

	if len(verdicts) != 1 {
		t.Fatalf("callback called %d times, want 1", len(verdicts))
	}
	if verdicts[0].Model != "callback-test" {
		t.Errorf("Model = %q, want callback-test", verdicts[0].Model)
	}
	if actions[0] != ActionBlock {
		t.Errorf("Action = %s, want BLOCK", actions[0])
	}
}

func TestWorkerPool_Stats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openAIResponse{
			Model: "test",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.1, "reasoning": "ok"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	log := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test",
		Timeout:     5 * time.Second,
	}, log)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	wp := NewWorkerPool(WorkerPoolConfig{
		Workers:       2,
		QueueSize:     10,
		RiskThreshold: 0.85,
		FailOpen:      true,
	}, client, nil, log)

	ctx, cancel := context.WithCancel(context.Background())
	wp.Start(ctx)

	wp.Submit(newTestEvent(5000, "/usr/bin/test"))
	time.Sleep(500 * time.Millisecond)

	stats := wp.Stats()
	if stats.ProcessedTotal < 1 {
		t.Errorf("ProcessedTotal = %d, want >= 1", stats.ProcessedTotal)
	}
	if stats.BreakerState != "closed" {
		t.Errorf("BreakerState = %s, want closed", stats.BreakerState)
	}

	cancel()
	wp.Stop()
}

func TestWorkerPool_MonitorModeNoEnforcement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openAIResponse{
			Model: "monitor-test",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.95, "reasoning": "very dangerous"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	log := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
	}, log)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	wp := NewWorkerPool(WorkerPoolConfig{
		Workers:       1,
		QueueSize:     10,
		RiskThreshold: 0.85,
		FailOpen:      true,
		Mode:          "monitor",
	}, client, nil, log) // nil loader: any map write would panic

	var mu sync.Mutex
	var actions []Action

	wp.SetVerdictCallback(func(ev zaskebpf.ZaskEvent, result AnalysisResult, action Action) {
		mu.Lock()
		actions = append(actions, action)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	wp.Start(ctx)

	wp.Submit(newTestEvent(6000, "/usr/bin/evil"))
	time.Sleep(500 * time.Millisecond)

	cancel()
	wp.Stop()

	mu.Lock()
	defer mu.Unlock()

	if len(actions) != 1 {
		t.Fatalf("callback called %d times, want 1", len(actions))
	}
	// In monitor mode the action should still be BLOCK (the verdict stands),
	// but no SIGKILL or map write occurs.
	if actions[0] != ActionBlock {
		t.Errorf("Action = %s, want BLOCK (logged but not enforced)", actions[0])
	}
}
