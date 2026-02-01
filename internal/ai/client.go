package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sony/gobreaker/v2"
)

// ClientConfig configures the AI provider HTTP client.
type ClientConfig struct {
	ProviderURL    string
	Model          string
	APIKeyEnv      string
	APIKeyFile     string
	SystemPrompt   string
	Timeout        time.Duration
	CircuitBreaker CircuitBreakerConfig
	MaxRetries     int
}

// CircuitBreakerConfig configures the circuit breaker thresholds.
type CircuitBreakerConfig struct {
	MaxFailures     int
	CooldownTime    time.Duration
	HalfOpenMaxReqs int
}

// Client is the AI provider HTTP client. It implements retries with
// exponential backoff and a circuit breaker to protect against
// sustained provider failures.
type Client struct {
	log        zerolog.Logger
	breaker    *gobreaker.CircuitBreaker[AnalysisResult]
	httpClient *http.Client
	apiKey     string
	config     ClientConfig
}

// AnalysisResult is the outcome of an AI analysis request, including
// the parsed verdict and metadata about the provider invocation.
type AnalysisResult struct {
	Model    string
	Verdict  Verdict
	Duration time.Duration
}

// NewClient creates a new AI provider client. It loads the API key from
// the configured environment variable or key file at construction time.
func NewClient(cfg ClientConfig, log zerolog.Logger) (*Client, error) {
	clientLog := log.With().Str("component", "ai-client").Logger()

	apiKey, err := loadAPIKey(cfg.APIKeyEnv, cfg.APIKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load AI API key: %w", err)
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	maxReqs := uint32(cfg.CircuitBreaker.HalfOpenMaxReqs)
	if maxReqs == 0 {
		maxReqs = 1
	}
	cooldown := cfg.CircuitBreaker.CooldownTime
	if cooldown == 0 {
		cooldown = 30 * time.Second
	}
	maxFail := cfg.CircuitBreaker.MaxFailures
	if maxFail == 0 {
		maxFail = 5
	}

	breaker := gobreaker.NewCircuitBreaker[AnalysisResult](gobreaker.Settings{
		Name:        "ai-provider",
		MaxRequests: maxReqs,
		Timeout:     cooldown,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return int(counts.ConsecutiveFailures) >= maxFail
		},
		IsSuccessful: func(err error) bool {
			// 4xx client errors are not provider failures.
			return err == nil || isClientError(err)
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			clientLog.Info().
				Str("from", from.String()).
				Str("to", to.String()).
				Msg("circuit breaker state change")
		},
	})

	return &Client{
		httpClient: &http.Client{Timeout: cfg.Timeout},
		config:     cfg,
		apiKey:     apiKey,
		breaker:    breaker,
		log:        clientLog,
	}, nil
}

// Analyze sends an event context to the AI provider and returns the
// parsed verdict. It retries on transient errors (5xx, timeouts) with
// exponential backoff, and respects the circuit breaker state.
func (c *Client) Analyze(ctx context.Context, evCtx EventContext) (AnalysisResult, error) {
	systemPrompt, userMsg := BuildPrompt(evCtx, c.config.SystemPrompt)

	reqBody := openAIRequest{
		Model: c.config.Model,
		Messages: []openAIMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMsg},
		},
		Temperature: floatPtr(0.1), // Low temperature for deterministic security analysis.
	}

	var lastErr error
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt)
			c.log.Debug().
				Int("attempt", attempt).
				Dur("delay", delay).
				Msg("retrying AI request")
			select {
			case <-ctx.Done():
				return AnalysisResult{}, ctx.Err()
			case <-time.After(delay):
			}
		}

		result, err := c.doRequest(ctx, reqBody)
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Don't retry on context cancellation or circuit breaker open.
		if ctx.Err() != nil {
			return AnalysisResult{}, ctx.Err()
		}
		if isCircuitOpen(err) {
			return AnalysisResult{}, err
		}

		c.log.Warn().
			Err(err).
			Int("attempt", attempt).
			Int("max_retries", c.config.MaxRetries).
			Msg("AI request failed")
	}

	return AnalysisResult{}, fmt.Errorf("AI request failed after %d attempts: %w", c.config.MaxRetries+1, lastErr)
}

// doRequest performs a single HTTP request to the AI provider, wrapped
// in the circuit breaker. The breaker automatically records success/failure.
func (c *Client) doRequest(ctx context.Context, reqBody openAIRequest) (AnalysisResult, error) {
	return c.breaker.Execute(func() (AnalysisResult, error) {
		return c.doHTTPRequest(ctx, reqBody)
	})
}

// doHTTPRequest performs the raw HTTP call and response parsing.
// Errors returned here are recorded as failures by the circuit breaker,
// except for 4xx client errors which are considered successful from
// the breaker's perspective (provider is healthy, request was bad).
func (c *Client) doHTTPRequest(ctx context.Context, reqBody openAIRequest) (AnalysisResult, error) {

	start := time.Now()

	body, err := json.Marshal(reqBody)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("marshal AI request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.ProviderURL, bytes.NewReader(body))
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("create AI request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("AI HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("read AI response body: %w", err)
	}

	// 5xx errors are transient — returned as error so breaker records failure.
	if resp.StatusCode >= 500 {
		return AnalysisResult{}, fmt.Errorf("AI provider returned %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	// 4xx errors are client errors — not a provider failure, so we return
	// a successful result to the breaker but still report the error to the caller.
	if resp.StatusCode >= 400 {
		return AnalysisResult{}, &clientError{
			msg: fmt.Sprintf("AI provider returned %d: %s", resp.StatusCode, truncate(string(respBody), 200)),
		}
	}

	// Parse OpenAI-compatible response.
	var aiResp openAIResponse
	if unmarshalErr := json.Unmarshal(respBody, &aiResp); unmarshalErr != nil {
		return AnalysisResult{}, fmt.Errorf("parse AI response envelope: %w", unmarshalErr)
	}

	if len(aiResp.Choices) == 0 {
		return AnalysisResult{}, fmt.Errorf("AI response contains no choices")
	}

	content := aiResp.Choices[0].Message.Content

	// Strip markdown code fences if the LLM wraps JSON in them.
	content = stripCodeFences(content)

	verdict, err := ParseVerdict([]byte(content))
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("parse AI verdict: %w", err)
	}

	model := aiResp.Model
	if model == "" {
		model = c.config.Model
	}

	return AnalysisResult{
		Verdict:  verdict,
		Model:    model,
		Duration: time.Since(start),
	}, nil
}

// BreakerState returns the current circuit breaker state as a string
// for observability (e.g., Prometheus gauge).
func (c *Client) BreakerState() string {
	return c.breaker.State().String()
}

// ---------------------------------------------------------------------------
// OpenAI-Compatible API types
// ---------------------------------------------------------------------------

type openAIRequest struct {
	Temperature *float64        `json:"temperature,omitempty"`
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

// ---------------------------------------------------------------------------
// Circuit Breaker Helpers
// ---------------------------------------------------------------------------

// isCircuitOpen checks if an error is a circuit breaker open/too-many-requests error.
func isCircuitOpen(err error) bool {
	return errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests)
}

// clientError represents a client-side error (e.g., 4xx) that should not
// count as a provider failure for the circuit breaker.
type clientError struct {
	msg string
}

func (e *clientError) Error() string { return e.msg }

// isClientError returns true if the error is a non-provider client error.
func isClientError(err error) bool {
	var ce *clientError
	return errors.As(err, &ce)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// loadAPIKey loads the API key from either an environment variable or a file.
// Environment variable takes precedence. Both empty means no auth.
func loadAPIKey(envVar, filePath string) (string, error) {
	// Try environment variable first.
	if envVar != "" {
		if key := os.Getenv(envVar); key != "" {
			return key, nil
		}
	}

	// Fall back to key file.
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read API key file %s: %w", filePath, err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return "", fmt.Errorf("API key file %s is empty", filePath)
		}
		return key, nil
	}

	return "", nil
}

// backoffDelay calculates exponential backoff delay for the given attempt.
// Base delay is 500ms, doubling each attempt: 500ms, 1s, 2s, 4s, ...
// Capped at 30 seconds.
func backoffDelay(attempt int) time.Duration {
	base := 500 * time.Millisecond
	delay := time.Duration(float64(base) * math.Pow(2, float64(attempt-1)))
	const maxDelay = 30 * time.Second
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}

// stripCodeFences removes markdown code fences from LLM responses.
// Some models wrap JSON in ```json ... ``` despite instructions not to.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Remove opening fence (may include language tag like ```json).
		if idx := strings.Index(s, "\n"); idx != -1 {
			s = s[idx+1:]
		}
		// Remove closing fence.
		if idx := strings.LastIndex(s, "```"); idx != -1 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}
	return s
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// floatPtr returns a pointer to a float64 value.
func floatPtr(f float64) *float64 {
	return &f
}
