// Package engine implements the multi-tiered policy engine for ZASK.
//
// The engine processes execution events through a decision cascade:
//   - Tier 1: Internal LRU cache keyed by inode (fast-path ignore for known-good)
//   - Tier 2: Static rule engine with CEL-based conditions
//   - Tier 3: AI queue routing for suspicious events
//
// Additional capabilities:
//   - Script/Interpreter Awareness: detects interpreters (python3, bash, etc.)
//     and evaluates rules against the script's identity instead of the interpreter.
//   - Operational Modes: Monitor (log-only) vs. Lockdown (enforce).
//
// Events pass through tiers sequentially. The first tier that matches
// determines the action; remaining tiers are skipped.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	zaskebpf "github.com/CrlsMrls/zask/internal/ebpf"
)

// Mode represents the daemon's operational mode.
type Mode string

const (
	// ModeLockdown enforces all BLOCK decisions (SIGKILL + verdict map).
	ModeLockdown Mode = "lockdown"
	// ModeMonitor logs decisions but does not enforce (no SIGKILL, no map writes).
	ModeMonitor Mode = "monitor"
)

// Action represents the enforcement outcome for an event.
type Action int

const (
	// ActionAllow permits the execution (Tier 1 cache hit or no rule match).
	ActionAllow Action = iota
	// ActionBlock terminates the process and writes a BLOCK verdict.
	ActionBlock
	// ActionAlert logs a warning but does not block.
	ActionAlert
	// ActionAIQueue routes the event to Tier 3 for AI analysis.
	ActionAIQueue
)

// actionBlockLabel is the canonical string representation of a BLOCK action,
// used both in Action.String() and when matching rule actions from YAML.
const actionBlockLabel = "BLOCK"

// actionAllowLabel is the canonical string representation of an ALLOW action.
// ALLOW rules explicitly whitelist binaries: the inode is added to the Tier 1
// cache and the event skips Tier 3 AI analysis. Rule ordering matters — the
// first matching rule wins, so place BLOCK rules before ALLOW rules if there
// is overlap.
const actionAllowLabel = "ALLOW"

// String returns a human-readable action label.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionBlock:
		return actionBlockLabel
	case ActionAlert:
		return "ALERT"
	case ActionAIQueue:
		return "AI_QUEUE"
	default:
		return "UNKNOWN"
	}
}

// Verdict is the result of processing an event through the engine.
type Verdict struct {
	RuleName   string // populated for Tier 2 matches
	ScriptPath string // resolved script path for interpreter events; empty for non-interpreter binaries
	Action     Action
	Tier       int
}

// loaderFace is the subset of *ebpf.Loader methods used by the engine.
// Kept unexported; the concrete *ebpf.Loader satisfies this automatically.
// Tests inject a mock implementation.
type loaderFace interface {
	BlockExec(key zaskebpf.ZaskExecKey) error
	AllowExec(key zaskebpf.ZaskExecKey) error
}

// Engine is the multi-tiered policy engine.
type Engine struct {
	log          zerolog.Logger
	cache        *ContentCache
	rules        *RuleEngine
	limiter      *rate.Limiter
	loader       loaderFace
	aiQueue      chan<- zaskebpf.ZaskEvent
	interpreters map[string]bool
	mode         Mode
}

// EngineOptions configures the policy engine.
type EngineOptions struct {
	Loader       *zaskebpf.Loader
	AIQueue      chan<- zaskebpf.ZaskEvent
	RulesPath    string
	Mode         Mode
	Interpreters []string
	CacheTTL     time.Duration
	RateLimit    float64
	CacheSize    int
	RateBurst    int
	HotReload    bool
}

// defaultInterpreters is the set of known script interpreters used when
// no explicit list is provided via configuration.
var defaultInterpreters = []string{
	"python3", "python", "python2",
	"bash", "sh", "zsh", "dash", "fish",
	"node", "nodejs",
	"ruby", "perl", "php", "lua",
}

// buildInterpreterSet constructs the interpreter lookup map from a list
// of names or paths. Each entry is indexed by its basename so that both
// full paths ("/usr/bin/python3") and bare names ("python3") match
// against filepath.Base(argv).
func buildInterpreterSet(entries []string) map[string]bool {
	m := make(map[string]bool, len(entries))
	for _, e := range entries {
		name := filepath.Base(e)
		m[name] = true
	}
	return m
}

// New creates a new policy engine with all three tiers configured.
func New(opts EngineOptions, log zerolog.Logger) (*Engine, error) {
	engineLog := log.With().Str("component", "engine").Logger()

	// Operational mode (default: lockdown).
	mode := opts.Mode
	if mode == "" {
		mode = ModeLockdown
	}
	engineLog.Info().Str("mode", string(mode)).Msg("operational mode")

	// Tier 1: LRU cache
	cacheTTL := opts.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	cacheSize := opts.CacheSize
	if cacheSize == 0 {
		cacheSize = 10000
	}
	cache := NewContentCache(cacheSize, cacheTTL)

	// Tier 2: Static rules
	rules := NewRuleEngine(engineLog)
	if opts.RulesPath != "" {
		if err := rules.LoadFromFile(opts.RulesPath); err != nil {
			return nil, fmt.Errorf("load rules from %s: %w", opts.RulesPath, err)
		}
	}

	// Wire cache invalidation: when rules are reloaded, all cached
	// "known-good" hashes must be re-evaluated against the new rule set.
	rules.onReload = func() {
		engineLog.Info().Msg("rules reloaded, clearing content cache")
		cache.Clear()
	}

	if opts.RulesPath != "" && opts.HotReload {
		if err := rules.WatchFile(opts.RulesPath); err != nil {
			return nil, fmt.Errorf("watch rules file %s: %w", opts.RulesPath, err)
		}
	}

	// Tier 3: Rate limiter for AI queue
	limiter := rate.NewLimiter(rate.Limit(opts.RateLimit), opts.RateBurst)

	// Interpreter set (configurable or default).
	interps := opts.Interpreters
	if len(interps) == 0 {
		interps = defaultInterpreters
	}
	interpreterSet := buildInterpreterSet(interps)
	engineLog.Info().Int("count", len(interpreterSet)).Msg("interpreter set loaded")

	// Wrap the concrete loader in the interface, preserving the nil check:
	// a nil *Loader must become a nil loaderFace, not a non-nil interface
	// wrapping a nil pointer (which would defeat the nil guards below).
	var l loaderFace
	if opts.Loader != nil {
		l = opts.Loader
	}

	return &Engine{
		cache:        cache,
		rules:        rules,
		limiter:      limiter,
		loader:       l,
		aiQueue:      opts.AIQueue,
		log:          engineLog,
		mode:         mode,
		interpreters: interpreterSet,
	}, nil
}

// Process evaluates an event through the decision cascade.
// It returns the verdict and executes any enforcement actions (SIGKILL, map update).
func (e *Engine) Process(ctx context.Context, ev zaskebpf.ZaskEvent) Verdict {
	argv := ev.GetArgv()
	scriptArgv := ev.GetScriptArgv()

	// resolvedScript tracks the script path determined during interpreter
	// detection. It is returned in the Verdict so the caller can use the
	// correct value for audit logging (the event's ScriptArgv field may
	// hold stale pre-exec data from the eBPF layer).
	var resolvedScript string

	// hashUnavailable is set when IMA did not provide a hash (e.g., IMA not
	// configured). In this case rules still run, but we skip kernel map writes.
	hashUnavailable := ev.HashAvailable == 0

	if hashUnavailable {
		e.log.Warn().
			Uint32("pid", ev.Pid).
			Str("argv", argv).
			Msg("IMA hash unavailable, skipping kernel fast-path")
	}

	// key is the compound exec-chain identity: (parent_hash, child_hash).
	// It encodes WHO invokes WHAT, enabling context-aware verdicts
	// (e.g., nginx→bash BLOCK, sshd→bash ALLOW).
	//
	// When ParentHashAvailable == 0, the parent hash is all-zeros (unknown-parent
	// sentinel). The verdict map key technically works, but we log at Debug so
	// operators know the first-seen verdict is based on incomplete chain context.
	key := ev.ExecKey()
	if ev.ParentHashAvailable == 0 && !hashUnavailable {
		e.log.Debug().
			Uint32("pid", ev.Pid).
			Str("argv", argv).
			Msg("parent hash unavailable, using zero sentinel in exec-chain key")
	}

	// Script/Interpreter Awareness (§2b.2, §3c.4.5): if the binary is a known
	// interpreter, resolve the script path for CEL rule evaluation. Unlike
	// Phase 3c, the script hash is NOT used as the verdict cache key —
	// the compound (parent, interpreter) exec-chain key is the correct
	// kernel-tier granularity. Script content analysis belongs in Tier 2
	// (CEL `script_path` field).
	binaryName := filepath.Base(argv)
	if e.interpreters[binaryName] {
		// Prefer procfs — the authoritative source once exec completes.
		scriptPath := zaskebpf.FindScriptPath(ev.Pid)
		if scriptPath == "" {
			// Process may have exited before we could read /proc.
			// Fall back to the eBPF-captured value as a best-effort.
			scriptPath = scriptArgv
			if strings.HasPrefix(scriptPath, "-") {
				scriptPath = "" // Flag, not a path.
			}
		}

		if scriptPath != "" {
			resolvedScript = scriptPath
			// Update the event's ScriptArgv so CEL rules see the
			// resolved script path.
			if scriptPath != scriptArgv {
				e.setScriptArgv(&ev, scriptPath)
			}
		}
	}

	// Tier 1: Cache lookup (fast-path for known-good exec chains).
	// Skip when hashUnavailable: the zero key would cause unrelated events to
	// collide in the cache, producing incorrect verdicts.
	if !hashUnavailable && e.cache.Contains(key) {
		e.log.Debug().
			Str("child_hash", fmt.Sprintf("%.8x", key.ChildHash)).
			Msg("tier 1 cache hit — skipping")
		return Verdict{Action: ActionAllow, Tier: 1, ScriptPath: resolvedScript}
	}

	// Tier 2: Static rule matching.
	if match, rule := e.rules.Match(ev); match {
		action := ActionAlert
		switch rule.Action {
		case actionBlockLabel:
			action = ActionBlock
			e.enforce(ev, key)
		case actionAllowLabel:
			// Explicit ALLOW: cache the hash as known-good, promote to
			// the kernel map for fast-path handling, and skip Tier 3.
			action = ActionAllow
			if !hashUnavailable {
				e.cache.Add(key)
			}
			if e.loader != nil && !hashUnavailable {
				if err := e.loader.AllowExec(key); err != nil {
					e.log.Warn().Err(err).
						Str("child_hash", fmt.Sprintf("%.8x", key.ChildHash)).
						Msg("failed to promote ALLOW rule to verdict map")
				}
			}
		}
		e.log.Warn().
			Str("rule", rule.Name).
			Str("action", rule.Action).
			Str("severity", rule.Severity).
			Str("mode", string(e.mode)).
			Uint32("pid", ev.Pid).
			Str("argv", argv).
			Str("script", resolvedScript).
			Msg("tier 2 rule matched")
		return Verdict{Action: action, Tier: 2, RuleName: rule.Name, ScriptPath: resolvedScript}
	}

	// No rule match — add to Tier 1 cache as known-good, promote to the
	// kernel map for fast-path handling, then route to Tier 3.
	if !hashUnavailable {
		e.cache.Add(key)
	}
	if e.loader != nil && !hashUnavailable {
		if err := e.loader.AllowExec(key); err != nil {
			e.log.Warn().Err(err).
				Str("child_hash", fmt.Sprintf("%.8x", key.ChildHash)).
				Msg("failed to promote unknown binary to verdict map")
		}
	}

	// Tier 3: Rate-limited AI queue routing.
	if e.aiQueue != nil && e.limiter.Allow() {
		select {
		case e.aiQueue <- ev:
			e.log.Debug().
				Uint32("pid", ev.Pid).
				Str("argv", argv).
				Msg("event routed to tier 3 AI queue")
			return Verdict{Action: ActionAIQueue, Tier: 3, ScriptPath: resolvedScript}
		case <-ctx.Done():
			return Verdict{Action: ActionAllow, Tier: 3, ScriptPath: resolvedScript}
		default:
			e.log.Warn().Msg("tier 3 AI queue full, defaulting to ALLOW")
		}
	} else if e.aiQueue != nil {
		e.log.Warn().Msg("tier 3 rate limit exceeded, defaulting to ALLOW")
	}

	return Verdict{Action: ActionAllow, Tier: 3, ScriptPath: resolvedScript}
}

// enforce sends SIGKILL to the offending process and writes a BLOCK
// entry into the verdict map. In Monitor mode, it only logs.
func (e *Engine) enforce(ev zaskebpf.ZaskEvent, key zaskebpf.ZaskExecKey) {
	if e.mode == ModeMonitor {
		e.log.Warn().
			Uint32("pid", ev.Pid).
			Str("child_hash", fmt.Sprintf("%.8x", key.ChildHash)).
			Str("argv", ev.GetArgv()).
			Msg("monitor mode: would have blocked (no enforcement)")
		return
	}

	// Send SIGKILL to the process.
	if err := syscall.Kill(int(ev.Pid), syscall.SIGKILL); err != nil {
		e.log.Error().Err(err).Uint32("pid", ev.Pid).Msg("failed to kill process")
	} else {
		e.log.Info().Uint32("pid", ev.Pid).Msg("process killed")
	}

	// Write BLOCK verdict to the kernel map only if IMA hash is available.
	if e.loader != nil && ev.HashAvailable != 0 {
		if err := e.loader.BlockExec(key); err != nil {
			e.log.Error().Err(err).Msg("failed to update verdict map")
		}
	}
}

// Close releases engine resources (stops file watcher, etc.).
func (e *Engine) Close() {
	e.rules.Close()
}

// setScriptArgv overwrites the event's ScriptArgv field with the given
// string so that downstream CEL rules see the resolved script path.
func (e *Engine) setScriptArgv(ev *zaskebpf.ZaskEvent, path string) {
	// Zero out the field.
	for i := range ev.ScriptArgv {
		ev.ScriptArgv[i] = 0
	}
	// Copy the path (truncated to field size).
	for i := 0; i < len(path) && i < len(ev.ScriptArgv); i++ {
		ev.ScriptArgv[i] = int8(path[i])
	}
}

// ---------------------------------------------------------------------------
// Tier 1: Content-Hash-Based LRU Cache
// ---------------------------------------------------------------------------

// ContentCache is a thread-safe, time-expiring cache keyed by exec-chain key.
// It caches known-good exec-chain decisions so the engine skips Tier 2/3 for
// previously-evaluated (parent, child) binary pairs. Content-addressed:
// the same binary pair shares a single cache entry regardless of path or inode.
type ContentCache struct {
	entries map[zaskebpf.ZaskExecKey]time.Time
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

// NewContentCache creates a new exec-chain cache with the given capacity and TTL.
func NewContentCache(maxSize int, ttl time.Duration) *ContentCache {
	return &ContentCache{
		entries: make(map[zaskebpf.ZaskExecKey]time.Time, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Contains checks if the exec-chain key is in the cache and not expired.
func (c *ContentCache) Contains(key zaskebpf.ZaskExecKey) bool {
	c.mu.RLock()
	expiry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		// Expired — remove lazily.
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return false
	}
	return true
}

// Add inserts an exec-chain key into the cache. If the cache is full,
// expired entries are evicted first; if still full, the oldest entry
// is removed.
func (c *ContentCache) Add(key zaskebpf.ZaskExecKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict expired entries if at capacity.
	if len(c.entries) >= c.maxSize {
		now := time.Now()
		for k, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, k)
			}
		}
	}

	// If still at capacity, evict the oldest entry.
	if len(c.entries) >= c.maxSize {
		var oldestKey zaskebpf.ZaskExecKey
		var oldestTime time.Time
		first := true
		for k, exp := range c.entries {
			if first || exp.Before(oldestTime) {
				oldestKey = k
				oldestTime = exp
				first = false
			}
		}
		delete(c.entries, oldestKey)
	}

	c.entries[key] = time.Now().Add(c.ttl)
}

// Size returns the current number of entries in the cache.
func (c *ContentCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries from the cache. This is used when rules are
// reloaded so that previously-cached "known-good" hashes are re-evaluated
// against the new rule set.
func (c *ContentCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[zaskebpf.ZaskExecKey]time.Time, c.maxSize)
}

// ---------------------------------------------------------------------------
// Tier 2: Static Rule Engine
// ---------------------------------------------------------------------------

// Rule is a single static detection rule from rules.yaml.
// Each rule contains a CEL expression that is evaluated against event attributes.
type Rule struct {
	celProgram  cel.Program `yaml:"-"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Condition   string      `yaml:"condition"`
	Action      string      `yaml:"action"`
	Severity    string      `yaml:"severity"`
}

// rulesFile is the top-level structure of rules.yaml.
type rulesFile struct {
	Rules []Rule `yaml:"rules"`
}

// celEnv is the shared CEL environment with the event attribute declarations.
var celEnv *cel.Env

func init() {
	var err error
	celEnv, err = cel.NewEnv(
		cel.Variable("argv", cel.StringType),
		cel.Variable("script_path", cel.StringType),
		cel.Variable("pid", cel.IntType),
		cel.Variable("ppid", cel.IntType),
		cel.Variable("uid", cel.IntType),
		cel.Variable("cgroup_id", cel.IntType),
		cel.Variable("inode", cel.IntType),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create CEL environment: %v", err))
	}
}

// RuleEngine manages static detection rules and supports hot-reload.
type RuleEngine struct {
	log      zerolog.Logger
	onReload func() // called after successful rule reload; may be nil
	stopCh   chan struct{}
	rules    []Rule
	mu       sync.RWMutex
	stopped  bool
}

// NewRuleEngine creates a new rule engine.
func NewRuleEngine(log zerolog.Logger) *RuleEngine {
	return &RuleEngine{
		log:    log.With().Str("component", "rule-engine").Logger(),
		stopCh: make(chan struct{}),
	}
}

// LoadFromFile reads and parses rules from a YAML file.
func (r *RuleEngine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file %s: %w", path, err)
	}
	return r.LoadFromBytes(data)
}

// LoadFromBytes parses rules from raw YAML bytes.
func (r *RuleEngine) LoadFromBytes(data []byte) error {
	var rf rulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}

	// Compile all CEL conditions.
	for i := range rf.Rules {
		rule := &rf.Rules[i]
		if rule.Condition == "" {
			return fmt.Errorf("rule %q: 'condition' field is required", rule.Name)
		}
		ast, issues := celEnv.Compile(rule.Condition)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("compile CEL condition for rule %q: %w", rule.Name, issues.Err())
		}
		if ast.OutputType() != cel.BoolType {
			return fmt.Errorf("CEL condition for rule %q must evaluate to bool, got %s", rule.Name, ast.OutputType())
		}
		prg, err := celEnv.Program(ast)
		if err != nil {
			return fmt.Errorf("create CEL program for rule %q: %w", rule.Name, err)
		}
		rule.celProgram = prg
	}

	r.mu.Lock()
	r.rules = rf.Rules
	r.mu.Unlock()

	r.log.Info().Int("count", len(rf.Rules)).Msg("rules loaded")

	// Notify the engine so it can clear caches for the new rule set.
	if r.onReload != nil {
		r.onReload()
	}

	return nil
}

// Match checks an event against all loaded rules and returns the first match.
func (r *RuleEngine) Match(ev zaskebpf.ZaskEvent) (bool, Rule) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	activation := map[string]any{
		"argv":        ev.GetArgv(),
		"script_path": ev.GetScriptArgv(),
		"pid":         int64(ev.Pid),
		"ppid":        int64(ev.Ppid),
		"uid":         int64(ev.Uid),
		"cgroup_id":   int64(ev.CgroupId),
		"inode":       int64(ev.InodeNumber),
	}

	for _, rule := range r.rules {
		out, _, err := rule.celProgram.Eval(activation)
		if err != nil {
			r.log.Error().Err(err).Str("rule", rule.Name).Msg("CEL evaluation error")
			continue
		}
		if out == types.True {
			return true, rule
		}
	}
	return false, Rule{}
}

// Rules returns a copy of the currently loaded rules.
func (r *RuleEngine) Rules() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rule, len(r.rules))
	copy(out, r.rules)
	return out
}

// WatchFile starts watching the rules file for changes and reloads
// automatically. Uses fsnotify for file-system event watching.
func (r *RuleEngine) WatchFile(path string) error {
	return r.watchFileInternal(path)
}

// Close stops the file watcher if running.
func (r *RuleEngine) Close() {
	if !r.stopped {
		r.stopped = true
		close(r.stopCh)
	}
}
