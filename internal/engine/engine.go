// Package engine implements the multi-tiered policy engine for ZASK.
//
// The engine processes execution events through a decision cascade:
//   - Tier 1: Kernel map lookup (< 1μs)
//   - Tier 2: Go deterministic rules (< 10ms)
//   - Tier 3: AI semantic analysis (1-5s)
package engine
