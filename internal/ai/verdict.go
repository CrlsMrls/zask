package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Verdict represents the parsed response from the AI provider.
type Verdict struct {
	// Reasoning is the AI's explanation for the risk score.
	Reasoning string `json:"reasoning"`
	// Risk is the threat probability score in [0.0, 1.0].
	Risk float64 `json:"risk"`
}

// Action is the enforcement decision derived from a Verdict's risk score.
type Action int

const (
	// ActionAllow permits the execution.
	ActionAllow Action = iota
	// ActionBlock terminates the process and writes a BLOCK verdict.
	ActionBlock
)

// String returns a human-readable label for the action.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

// ParseVerdict parses a raw JSON response from the AI provider into a
// Verdict struct. It enforces strict validation:
//   - Only "risk" and "reasoning" fields are accepted.
//   - "risk" must be a float in [0.0, 1.0].
//   - "reasoning" must be a non-empty string.
//
// Invalid or malformed responses return an error with a descriptive message.
func ParseVerdict(data []byte) (Verdict, error) {
	// Use a strict decoder that rejects unknown fields.
	var v Verdict
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return Verdict{}, fmt.Errorf("parse AI verdict JSON: %w", err)
	}

	// Ensure no trailing data after the JSON object.
	if dec.More() {
		return Verdict{}, fmt.Errorf("parse AI verdict JSON: unexpected trailing data")
	}

	// Check for EOF — ensures we consumed the entire input cleanly.
	if _, err := dec.Token(); err != io.EOF {
		return Verdict{}, fmt.Errorf("parse AI verdict JSON: unexpected trailing data")
	}

	// Validate risk range.
	if v.Risk < 0.0 || v.Risk > 1.0 {
		return Verdict{}, fmt.Errorf("AI verdict risk %f out of range [0.0, 1.0]", v.Risk)
	}

	// Validate reasoning is present.
	if v.Reasoning == "" {
		return Verdict{}, fmt.Errorf("AI verdict missing required field \"reasoning\"")
	}

	return v, nil
}

// Evaluate applies the configured risk threshold to determine the action.
// A risk score strictly greater than the threshold triggers a BLOCK.
func (v Verdict) Evaluate(threshold float64) Action {
	if v.Risk > threshold {
		return ActionBlock
	}
	return ActionAllow
}
