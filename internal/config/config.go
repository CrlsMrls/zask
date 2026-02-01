// Package config provides configuration loading and validation for ZASK.
//
// Configuration follows a kube-apiserver-style declarative YAML manifest
// loaded from a single --config CLI flag (default: /etc/zask/config.yaml).
// All settings are validated at startup; invalid config causes a fast fail
// with clear error messages.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Format constants used across logging and audit output configuration.
const (
	formatJSON    = "json"
	formatConsole = "console"
	formatParquet = "parquet"
	formatText    = "text"
)

// Config is the top-level declarative configuration for zaskd.
type Config struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Spec       Spec   `yaml:"spec"`
}

// Spec is the main configuration body.
type Spec struct {
	SelfProtection *bool       `yaml:"selfProtection,omitempty"`
	Logging        Logging     `yaml:"logging"`
	Mode           string      `yaml:"mode"`
	MapPaths       MapPaths    `yaml:"mapPaths"`
	Health         Health      `yaml:"health"`
	Rules          Rules       `yaml:"rules"`
	Interpreters   []string    `yaml:"interpreters"`
	Audit          Audit       `yaml:"audit"`
	AI             AI          `yaml:"ai"`
	RateLimiter    RateLimiter `yaml:"rateLimiter"`
}

// MapPaths configures BPF map pin locations on the BPF filesystem.
type MapPaths struct {
	VerdictMap string `yaml:"verdictMap"`
}

// Logging configures structured logging output.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// AI configures the Tier 3 AI provider integration.
type AI struct {
	ProviderURL    string         `yaml:"providerUrl"`
	Model          string         `yaml:"model"`
	APIKeyEnv      string         `yaml:"apiKeyEnv"`
	APIKeyFile     string         `yaml:"apiKeyFile"`
	SystemPrompt   string         `yaml:"systemPrompt"`
	CircuitBreaker CircuitBreaker `yaml:"circuitBreaker"`
	Timeout        time.Duration  `yaml:"timeout"`
	RiskThreshold  float64        `yaml:"riskThreshold"`
	MaxRetries     int            `yaml:"maxRetries"`
	Workers        int            `yaml:"workers"`
	QueueSize      int            `yaml:"queueSize"`
	FailOpen       bool           `yaml:"failOpen"`
}

// CircuitBreaker configures the circuit breaker for the AI provider.
type CircuitBreaker struct {
	MaxFailures     int           `yaml:"maxFailures"`
	CooldownTime    time.Duration `yaml:"cooldownTime"`
	HalfOpenMaxReqs int           `yaml:"halfOpenMaxReqs"`
}

// Health configures the HTTP health endpoint.
type Health struct {
	ListenAddress string `yaml:"listenAddress"`
}

// RateLimiter configures the Token Bucket rate limiter for Tier 3 events.
type RateLimiter struct {
	Rate  float64 `yaml:"rate"`
	Burst int     `yaml:"burst"`
}

// Rules configures the Tier 2 static rule engine.
type Rules struct {
	Path string `yaml:"path"`
}

// Audit configures multi-format audit logging.
type Audit struct {
	Outputs []AuditOutput `yaml:"outputs"`
}

// AuditOutput configures a single audit log output.
type AuditOutput struct {
	Format string `yaml:"format"` // json, parquet, or text
	Path   string `yaml:"path"`   // file path or "stdout"/"stderr"
}

// SelfProtectionEnabled returns whether self-protection is enabled.
// Defaults to true when the field is nil (not set in config).
func (s *Spec) SelfProtectionEnabled() bool {
	if s.SelfProtection == nil {
		return true
	}
	return *s.SelfProtection
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		APIVersion: "zask.io/v1alpha1",
		Kind:       "ZaskConfig",
		Spec: Spec{
			Mode: "lockdown",
			Interpreters: []string{
				"python3", "python", "python2",
				"bash", "sh", "zsh", "dash", "fish",
				"node", "nodejs",
				"ruby", "perl", "php", "lua",
			},
			MapPaths: MapPaths{
				VerdictMap: "/sys/fs/bpf/zask_verdicts",
			},
			Logging: Logging{
				Level:  "info",
				Format: formatJSON,
				Output: "stdout",
			},
			AI: AI{
				RiskThreshold: 0.8,
				Timeout:       5 * time.Second,
				MaxRetries:    3,
				Workers:       4,
				QueueSize:     256,
				FailOpen:      true,
				CircuitBreaker: CircuitBreaker{
					MaxFailures:     5,
					CooldownTime:    30 * time.Second,
					HalfOpenMaxReqs: 1,
				},
			},
			Health: Health{
				ListenAddress: ":7453",
			},
			RateLimiter: RateLimiter{
				Rate:  10,
				Burst: 20,
			},
			Rules: Rules{
				Path: "/etc/zask/rules.yaml",
			},
			Audit: Audit{
				Outputs: []AuditOutput{
					{Format: formatJSON, Path: "/var/log/zask/audit.json"},
				},
			},
		},
	}
}

// Load reads a YAML config file from the given path and returns a
// validated Config. Missing fields are filled with defaults.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

// Validate checks that all required configuration fields are present and
// have valid values. Returns an error describing the first invalid field.
func (c *Config) Validate() error {
	if c.APIVersion != "zask.io/v1alpha1" {
		return fmt.Errorf("unsupported apiVersion %q, expected \"zask.io/v1alpha1\"", c.APIVersion)
	}

	if c.Kind != "ZaskConfig" {
		return fmt.Errorf("unsupported kind %q, expected \"ZaskConfig\"", c.Kind)
	}

	if c.Spec.MapPaths.VerdictMap == "" {
		return fmt.Errorf("spec.mapPaths.verdictMap is required")
	}

	switch c.Spec.Logging.Level {
	case "trace", "debug", "info", "warn", "error", "fatal", "panic", "disabled":
		// valid
	default:
		return fmt.Errorf("spec.logging.level %q is invalid, must be one of: trace, debug, info, warn, error, fatal, panic, disabled", c.Spec.Logging.Level)
	}

	switch c.Spec.Logging.Format {
	case formatJSON, formatConsole:
		// valid
	default:
		return fmt.Errorf("spec.logging.format %q is invalid, must be \"json\" or \"console\"", c.Spec.Logging.Format)
	}

	if c.Spec.Health.ListenAddress == "" {
		return fmt.Errorf("spec.health.listenAddress is required")
	}

	if c.Spec.RateLimiter.Rate <= 0 {
		return fmt.Errorf("spec.rateLimiter.rate must be positive, got %f", c.Spec.RateLimiter.Rate)
	}

	if c.Spec.RateLimiter.Burst <= 0 {
		return fmt.Errorf("spec.rateLimiter.burst must be positive, got %d", c.Spec.RateLimiter.Burst)
	}

	if c.Spec.AI.RiskThreshold < 0 || c.Spec.AI.RiskThreshold > 1 {
		return fmt.Errorf("spec.ai.riskThreshold must be between 0 and 1, got %f", c.Spec.AI.RiskThreshold)
	}

	if c.Spec.AI.Timeout < 0 {
		return fmt.Errorf("spec.ai.timeout must be non-negative, got %s", c.Spec.AI.Timeout)
	}

	// Validate operational mode.
	switch c.Spec.Mode {
	case "lockdown", "monitor":
		// valid
	default:
		return fmt.Errorf("spec.mode %q is invalid, must be \"lockdown\" or \"monitor\"", c.Spec.Mode)
	}

	// Validate audit outputs.
	for i, out := range c.Spec.Audit.Outputs {
		switch out.Format {
		case formatJSON, formatParquet, formatText:
			// valid
		default:
			return fmt.Errorf("spec.audit.outputs[%d].format %q is invalid, must be \"json\", \"parquet\", or \"text\"", i, out.Format)
		}
		if out.Path == "" {
			return fmt.Errorf("spec.audit.outputs[%d].path is required", i)
		}
	}

	return nil
}
