package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `
apiVersion: zask.io/v1alpha1
kind: ZaskConfig
spec:
  mapPaths:
    verdictMap: /sys/fs/bpf/zask_verdicts
  logging:
    level: debug
    format: json
    output: stdout
  ai:
    providerUrl: http://localhost:8081
    model: gemma
    riskThreshold: 0.9
    timeout: 3s
  health:
    listenAddress: ":9090"
  rateLimiter:
    rate: 5.0
    burst: 10
  rules:
    path: /etc/zask/rules.yaml
`
	path := writeTempFile(t, "config.yaml", content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.APIVersion != "zask.io/v1alpha1" {
		t.Errorf("APIVersion = %q, want %q", cfg.APIVersion, "zask.io/v1alpha1")
	}
	if cfg.Kind != "ZaskConfig" {
		t.Errorf("Kind = %q, want %q", cfg.Kind, "ZaskConfig")
	}
	if cfg.Spec.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Spec.Logging.Level, "debug")
	}
	if cfg.Spec.AI.RiskThreshold != 0.9 {
		t.Errorf("AI.RiskThreshold = %f, want 0.9", cfg.Spec.AI.RiskThreshold)
	}
	if cfg.Spec.RateLimiter.Rate != 5.0 {
		t.Errorf("RateLimiter.Rate = %f, want 5.0", cfg.Spec.RateLimiter.Rate)
	}
	if cfg.Spec.Health.ListenAddress != ":9090" {
		t.Errorf("Health.ListenAddress = %q, want %q", cfg.Spec.Health.ListenAddress, ":9090")
	}
}

func TestLoad_DefaultsFillMissing(t *testing.T) {
	content := `
apiVersion: zask.io/v1alpha1
kind: ZaskConfig
`
	path := writeTempFile(t, "config.yaml", content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Spec.Logging.Level != "info" {
		t.Errorf("default Logging.Level = %q, want %q", cfg.Spec.Logging.Level, "info")
	}
	if cfg.Spec.RateLimiter.Rate != 10 {
		t.Errorf("default RateLimiter.Rate = %f, want 10", cfg.Spec.RateLimiter.Rate)
	}
	if cfg.Spec.Health.ListenAddress != ":7453" {
		t.Errorf("default Health.ListenAddress = %q, want %q", cfg.Spec.Health.ListenAddress, ":7453")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("Load() expected error for missing file, got nil")
	}
}

func TestValidate_InvalidAPIVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIVersion = "invalid/v99"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for invalid apiVersion")
	}
}

func TestValidate_InvalidKind(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Kind = "WrongKind"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for invalid kind")
	}
}

func TestValidate_MissingVerdictMapPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spec.MapPaths.VerdictMap = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for empty verdictMap path")
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spec.Logging.Level = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for invalid log level")
	}
}

func TestValidate_InvalidLogFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spec.Logging.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for invalid log format")
	}
}

func TestValidate_NegativeRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spec.RateLimiter.Rate = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for negative rate limit")
	}
}

func TestValidate_NegativeBurst(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spec.RateLimiter.Burst = -5
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for negative burst")
	}
}

func TestValidate_InvalidRiskThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spec.AI.RiskThreshold = 1.5
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for riskThreshold > 1")
	}

	cfg.Spec.AI.RiskThreshold = -0.1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for riskThreshold < 0")
	}
}

func TestValidate_MissingHealthAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Spec.Health.ListenAddress = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for empty health listenAddress")
	}
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
