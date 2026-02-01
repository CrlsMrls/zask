// Package ai provides the AI provider client and prompt engineering
// for ZASK's semantic reasoning layer (Tier 3).
//
// The AI layer performs asynchronous analysis of execution events
// that pass through Tiers 1 and 2, providing deep semantic threat
// detection for unknown or suspicious binaries.
//
// Architecture:
//   - Client: HTTP client for OpenAI-compatible API with retry/backoff
//     and circuit breaker.
//   - Prompt: Context-enriched prompt assembly with injection defense.
//   - Verdict: Strict JSON response parsing and risk thresholding.
//   - WorkerPool: Concurrent goroutine pool consuming events from the
//     AI queue and executing the feedback loop (verdict map + SIGKILL).
package ai
