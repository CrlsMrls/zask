package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// newTestLogger creates a zerolog logger for tests.
func newTestLogger() zerolog.Logger {
	return zerolog.New(os.Stderr).With().Timestamp().Logger().Level(zerolog.DebugLevel)
}

// --- T3.1: AI Client (Mock Provider) ---

func TestClient_SuccessfulRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers.
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", auth)
		}

		// Verify request body is valid OpenAI format.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		var req openAIRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.Model != "test-model" {
			t.Errorf("Model = %q, want test-model", req.Model)
		}
		if len(req.Messages) != 2 {
			t.Fatalf("Messages count = %d, want 2", len(req.Messages))
		}
		if req.Messages[0].Role != "system" {
			t.Errorf("Messages[0].Role = %q, want system", req.Messages[0].Role)
		}
		if req.Messages[1].Role != "user" {
			t.Errorf("Messages[1].Role = %q, want user", req.Messages[1].Role)
		}

		// Return valid response.
		resp := openAIResponse{
			Model: "test-model-v1",
			Choices: []openAIChoice{
				{Message: openAIMessage{Role: "assistant", Content: `{"risk": 0.85, "reasoning": "test verdict"}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Set API key via environment variable.
	t.Setenv("TEST_AI_KEY", "test-key")

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test-model",
		APIKeyEnv:   "TEST_AI_KEY",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := client.Analyze(context.Background(), EventContext{
		PID:        1234,
		PPID:       1,
		UID:        0,
		Argv:       "/usr/bin/test",
		ParentName: "systemd",
		Username:   "root",
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Verdict.Risk != 0.85 {
		t.Errorf("Risk = %f, want 0.85", result.Verdict.Risk)
	}
	if result.Verdict.Reasoning != "test verdict" {
		t.Errorf("Reasoning = %q, want %q", result.Verdict.Reasoning, "test verdict")
	}
	if result.Model != "test-model-v1" {
		t.Errorf("Model = %q, want test-model-v1", result.Model)
	}
}

func TestClient_ExponentialBackoff(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			// First two attempts: 500 error.
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "internal error")
			return
		}
		// Third attempt: success.
		resp := openAIResponse{
			Model: "test-model",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.3, "reasoning": "safe"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test-model",
		Timeout:     5 * time.Second,
		MaxRetries:  3,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	start := time.Now()
	result, err := client.Analyze(context.Background(), EventContext{
		PID: 1, PPID: 0, UID: 0, Argv: "test", ParentName: "kernel", Username: "root",
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if result.Verdict.Risk != 0.3 {
		t.Errorf("Risk = %f, want 0.3", result.Verdict.Risk)
	}

	totalAttempts := attempts.Load()
	if totalAttempts != 3 {
		t.Errorf("attempts = %d, want 3", totalAttempts)
	}

	// Backoff: attempt 1 (500ms) + attempt 2 (1s) ≈ 1.5s minimum.
	// Allow margin for test execution.
	if elapsed < 1*time.Second {
		t.Errorf("elapsed = %v, expected backoff delay (>1s)", elapsed)
	}
}

func TestClient_TimeoutEnforcement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow provider.
		time.Sleep(3 * time.Second)
		fmt.Fprint(w, "too late")
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test-model",
		Timeout:     500 * time.Millisecond,
		MaxRetries:  0,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	start := time.Now()
	_, err = client.Analyze(context.Background(), EventContext{
		PID: 1, PPID: 0, UID: 0, Argv: "test", ParentName: "kernel", Username: "root",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Analyze() expected timeout error")
	}

	// Should timeout around 500ms, not wait for the full 3s.
	if elapsed > 2*time.Second {
		t.Errorf("elapsed = %v, timeout should have triggered sooner", elapsed)
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test-model",
		Timeout:     30 * time.Second,
		MaxRetries:  3,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = client.Analyze(ctx, EventContext{
		PID: 1, PPID: 0, UID: 0, Argv: "test", ParentName: "kernel", Username: "root",
	})
	if err == nil {
		t.Fatal("Analyze() expected error on context cancellation")
	}
}

func TestClient_CodeFenceStripping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// LLM wraps JSON in markdown code fences.
		resp := openAIResponse{
			Model: "test-model",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: "```json\n{\"risk\": 0.7, \"reasoning\": \"wrapped in fences\"}\n```"}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "test-model",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := client.Analyze(context.Background(), EventContext{
		PID: 1, PPID: 0, UID: 0, Argv: "test", ParentName: "kernel", Username: "root",
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Verdict.Risk != 0.7 {
		t.Errorf("Risk = %f, want 0.7", result.Verdict.Risk)
	}
}

func TestClient_APIKeyFromFile(t *testing.T) {
	tmpFile := t.TempDir() + "/api-key"
	if err := os.WriteFile(tmpFile, []byte("file-based-key\n"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		resp := openAIResponse{
			Model: "m",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.1, "reasoning": "ok"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "m",
		APIKeyFile:  tmpFile,
		Timeout:     5 * time.Second,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.Analyze(context.Background(), EventContext{
		PID: 1, PPID: 0, UID: 0, Argv: "test", ParentName: "kernel", Username: "root",
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if receivedAuth != "Bearer file-based-key" {
		t.Errorf("Authorization = %q, want Bearer file-based-key", receivedAuth)
	}
}

func TestClient_NoAPIKey(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		resp := openAIResponse{
			Model: "m",
			Choices: []openAIChoice{
				{Message: openAIMessage{Content: `{"risk": 0.1, "reasoning": "ok"}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "m",
		Timeout:     5 * time.Second,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.Analyze(context.Background(), EventContext{
		PID: 1, PPID: 0, UID: 0, Argv: "test", ParentName: "kernel", Username: "root",
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if receivedAuth != "" {
		t.Errorf("Authorization should be empty for no-auth, got %q", receivedAuth)
	}
}

// --- T3.2: Circuit Breaker ---

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "m",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
		CircuitBreaker: CircuitBreakerConfig{
			MaxFailures:     3,
			CooldownTime:    1 * time.Hour,
			HalfOpenMaxReqs: 1,
		},
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	evCtx := EventContext{PID: 1, PPID: 0, UID: 0, Argv: "t", ParentName: "k", Username: "r"}

	// Fail 3 times to open circuit.
	for i := 0; i < 3; i++ {
		_, _ = client.Analyze(ctx, evCtx)
	}

	if state := client.BreakerState(); state != breakerStateOpen {
		t.Errorf("BreakerState = %s, want open", state)
	}

	// Next request should fail immediately (circuit open, no HTTP call).
	beforeCount := reqCount.Load()
	_, err = client.Analyze(ctx, evCtx)
	afterCount := reqCount.Load()

	if err == nil {
		t.Error("expected circuit breaker error")
	}
	if afterCount != beforeCount {
		t.Error("HTTP request was made despite open circuit")
	}
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "m",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
		CircuitBreaker: CircuitBreakerConfig{
			MaxFailures:     2,
			CooldownTime:    100 * time.Millisecond,
			HalfOpenMaxReqs: 1,
		},
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	evCtx := EventContext{PID: 1, Argv: "t", ParentName: "k", Username: "r"}

	// Open the circuit.
	for i := 0; i < 2; i++ {
		_, _ = client.Analyze(ctx, evCtx)
	}
	if state := client.BreakerState(); state != breakerStateOpen {
		t.Fatalf("BreakerState = %s, want open", state)
	}

	// Wait for cooldown.
	time.Sleep(150 * time.Millisecond)

	// Should transition to half-open.
	if state := client.BreakerState(); state != "half-open" {
		t.Errorf("BreakerState = %s, want half-open after cooldown", state)
	}
}

func TestCircuitBreaker_ClosesOnSuccess(t *testing.T) {
	var failCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failCount.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Probe request succeeds.
		w.Header().Set("Content-Type", "application/json")
		resp := openAIResponse{
			Model: "m",
			Choices: []openAIChoice{{Message: openAIMessage{
				Role:    "assistant",
				Content: `{"risk": 0.1, "reasoning": "safe"}`,
			}}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "m",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
		CircuitBreaker: CircuitBreakerConfig{
			MaxFailures:     2,
			CooldownTime:    100 * time.Millisecond,
			HalfOpenMaxReqs: 1,
		},
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	evCtx := EventContext{PID: 1, Argv: "t", ParentName: "k", Username: "r"}

	// Open the circuit.
	for i := 0; i < 2; i++ {
		_, _ = client.Analyze(ctx, evCtx)
	}

	// Wait for cooldown → half-open.
	time.Sleep(150 * time.Millisecond)

	// Successful probe → should close.
	_, err = client.Analyze(ctx, evCtx)
	if err != nil {
		t.Fatalf("Analyze() during probe = %v, want success", err)
	}

	if state := client.BreakerState(); state != "closed" {
		t.Errorf("BreakerState = %s, want closed after successful probe", state)
	}
}

func TestCircuitBreaker_ReopensOnHalfOpenFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "m",
		Timeout:     5 * time.Second,
		MaxRetries:  0,
		CircuitBreaker: CircuitBreakerConfig{
			MaxFailures:     2,
			CooldownTime:    100 * time.Millisecond,
			HalfOpenMaxReqs: 1,
		},
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	evCtx := EventContext{PID: 1, Argv: "t", ParentName: "k", Username: "r"}

	// Open the circuit.
	for i := 0; i < 2; i++ {
		_, _ = client.Analyze(ctx, evCtx)
	}

	// Wait for cooldown → half-open.
	time.Sleep(150 * time.Millisecond)

	// Probe fails → should reopen.
	_, _ = client.Analyze(ctx, evCtx)

	if state := client.BreakerState(); state != breakerStateOpen {
		t.Errorf("BreakerState = %s, want open after failed probe", state)
	}
}

func TestCircuitBreaker_IntegrationWithClient(t *testing.T) {
	var reqCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ProviderURL: server.URL,
		Model:       "m",
		Timeout:     5 * time.Second,
		MaxRetries:  3,
		CircuitBreaker: CircuitBreakerConfig{
			MaxFailures:     3,
			CooldownTime:    1 * time.Hour,
			HalfOpenMaxReqs: 1,
		},
	}, newTestLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	evCtx := EventContext{PID: 1, PPID: 0, UID: 0, Argv: "t", ParentName: "k", Username: "r"}

	// First Analyze call with MaxRetries=3 makes 4 attempts (0-3).
	// 3 failures trip the breaker, then the 4th attempt sees it open.
	_, err = client.Analyze(ctx, evCtx)
	if err == nil {
		t.Fatal("expected error from Analyze")
	}

	if state := client.BreakerState(); state != breakerStateOpen {
		t.Errorf("BreakerState = %s, want open", state)
	}

	// Next request should fail immediately (circuit open, no HTTP call).
	beforeCount := reqCount.Load()
	_, err = client.Analyze(ctx, evCtx)
	afterCount := reqCount.Load()

	if err == nil {
		t.Error("expected circuit breaker error")
	}
	if !strings.Contains(err.Error(), "circuit breaker") {
		t.Errorf("error should mention circuit breaker: %v", err)
	}
	if afterCount != beforeCount {
		t.Error("HTTP request was made despite open circuit")
	}
}

// --- Helper tests ---

func TestBackoffDelay(t *testing.T) {
	tests := []struct {
		attempt int
		minMs   int
		maxMs   int
	}{
		{1, 400, 600},   // ~500ms
		{2, 900, 1100},  // ~1s
		{3, 1900, 2100}, // ~2s
		{4, 3900, 4100}, // ~4s
	}

	for _, tt := range tests {
		delay := backoffDelay(tt.attempt)
		ms := int(delay.Milliseconds())
		if ms < tt.minMs || ms > tt.maxMs {
			t.Errorf("backoffDelay(%d) = %dms, want [%d, %d]ms", tt.attempt, ms, tt.minMs, tt.maxMs)
		}
	}
}

func TestStripCodeFences(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain json", `{"risk": 0.5}`, `{"risk": 0.5}`},
		{"with json fence", "```json\n{\"risk\": 0.5}\n```", `{"risk": 0.5}`},
		{"with plain fence", "```\n{\"risk\": 0.5}\n```", `{"risk": 0.5}`},
		{"whitespace", "  \n```json\n{\"risk\": 0.5}\n```\n  ", `{"risk": 0.5}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripCodeFences(tt.in)
			if got != tt.want {
				t.Errorf("stripCodeFences() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadAPIKey_EmptyKeyFile(t *testing.T) {
	tmpFile := t.TempDir() + "/empty-key"
	if err := os.WriteFile(tmpFile, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := loadAPIKey("", tmpFile)
	if err == nil {
		t.Error("expected error for empty key file")
	}
}
