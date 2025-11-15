// Package engine implements the multi-tiered policy engine for ZASK.
//
// The engine processes execution events through a decision cascade:
//   - Tier 1: Internal LRU cache keyed by inode (fast-path ignore for known-good)
//   - Tier 2: Static rule engine with regex-based pattern matching and hot-reload
//   - Tier 3: AI queue routing for suspicious events
//
// Events pass through tiers sequentially. The first tier that matches
// determines the action; remaining tiers are skipped.
package engine

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	zaskebpf "github.com/CrlsMrls/zask/internal/ebpf"
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
	RuleName string // populated for Tier 2 matches
	Action   Action
	Tier     int
}

// Engine is the multi-tiered policy engine.
type Engine struct {
	cache   *InodeCache
	rules   *RuleEngine
	limiter *rate.Limiter
	loader  *zaskebpf.Loader
	aiQueue chan<- zaskebpf.ZaskEvent
	log     zerolog.Logger
}

// EngineOptions configures the policy engine.
type EngineOptions struct {
	Loader    *zaskebpf.Loader
	AIQueue   chan<- zaskebpf.ZaskEvent
	RulesPath string
	CacheTTL  time.Duration
	RateLimit float64
	CacheSize int
	RateBurst int
	HotReload bool
}

// New creates a new policy engine with all three tiers configured.
func New(opts EngineOptions, log zerolog.Logger) (*Engine, error) {
	engineLog := log.With().Str("component", "engine").Logger()

	// Tier 1: LRU cache
	cacheTTL := opts.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	cacheSize := opts.CacheSize
	if cacheSize == 0 {
		cacheSize = 10000
	}
	cache := NewInodeCache(cacheSize, cacheTTL)

	// Tier 2: Static rules
	rules := NewRuleEngine(engineLog)
	if opts.RulesPath != "" {
		if err := rules.LoadFromFile(opts.RulesPath); err != nil {
			return nil, fmt.Errorf("load rules from %s: %w", opts.RulesPath, err)
		}
		if opts.HotReload {
			if err := rules.WatchFile(opts.RulesPath); err != nil {
				return nil, fmt.Errorf("watch rules file %s: %w", opts.RulesPath, err)
			}
		}
	}

	// Tier 3: Rate limiter for AI queue
	limiter := rate.NewLimiter(rate.Limit(opts.RateLimit), opts.RateBurst)

	return &Engine{
		cache:   cache,
		rules:   rules,
		limiter: limiter,
		loader:  opts.Loader,
		aiQueue: opts.AIQueue,
		log:     engineLog,
	}, nil
}

// Process evaluates an event through the decision cascade.
// It returns the verdict and executes any enforcement actions (SIGKILL, map update).
func (e *Engine) Process(ctx context.Context, ev zaskebpf.ZaskEvent) Verdict {
	key := ev.InodeKey()

	// Tier 1: Cache lookup (fast-path ignore for known-good inodes).
	if e.cache.Contains(key) {
		e.log.Debug().
			Uint64("inode", key.InodeNumber).
			Msg("tier 1 cache hit — skipping")
		return Verdict{Action: ActionAllow, Tier: 1}
	}

	// Tier 2: Static rule matching.
	argv := ev.GetArgv()
	if match, rule := e.rules.Match(argv); match {
		action := ActionAlert
		if rule.Action == actionBlockLabel {
			action = ActionBlock
			e.enforce(ev, key)
		}
		e.log.Warn().
			Str("rule", rule.Name).
			Str("action", rule.Action).
			Str("severity", rule.Severity).
			Uint32("pid", ev.Pid).
			Str("argv", argv).
			Msg("tier 2 rule matched")
		return Verdict{Action: action, Tier: 2, RuleName: rule.Name}
	}

	// No rule match — add to Tier 1 cache as known-good and route to Tier 3.
	e.cache.Add(key)

	// Tier 3: Rate-limited AI queue routing.
	if e.aiQueue != nil && e.limiter.Allow() {
		select {
		case e.aiQueue <- ev:
			e.log.Debug().
				Uint32("pid", ev.Pid).
				Str("argv", argv).
				Msg("event routed to tier 3 AI queue")
			return Verdict{Action: ActionAIQueue, Tier: 3}
		case <-ctx.Done():
			return Verdict{Action: ActionAllow, Tier: 3}
		default:
			e.log.Warn().Msg("tier 3 AI queue full, defaulting to ALLOW")
		}
	} else if e.aiQueue != nil {
		e.log.Warn().Msg("tier 3 rate limit exceeded, defaulting to ALLOW")
	}

	return Verdict{Action: ActionAllow, Tier: 3}
}

// enforce sends SIGKILL to the offending process and writes a BLOCK
// entry into the verdict map.
func (e *Engine) enforce(ev zaskebpf.ZaskEvent, key zaskebpf.ZaskInodeKey) {
	// Send SIGKILL to the process.
	if err := syscall.Kill(int(ev.Pid), syscall.SIGKILL); err != nil {
		e.log.Error().Err(err).Uint32("pid", ev.Pid).Msg("failed to kill process")
	} else {
		e.log.Info().Uint32("pid", ev.Pid).Msg("process killed")
	}

	// Write BLOCK verdict to the kernel map.
	if e.loader != nil {
		if err := e.loader.BlockInode(key); err != nil {
			e.log.Error().Err(err).Msg("failed to update verdict map")
		}
	}
}

// Close releases engine resources (stops file watcher, etc.).
func (e *Engine) Close() {
	e.rules.Close()
}

// ---------------------------------------------------------------------------
// Tier 1: Inode-based LRU Cache
// ---------------------------------------------------------------------------

// InodeCache is a thread-safe, time-expiring cache keyed by inode.
// It uses a simple map with periodic eviction rather than a full LRU
// to keep the implementation straightforward (KISS).
type InodeCache struct {
	entries map[zaskebpf.ZaskInodeKey]time.Time
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

// NewInodeCache creates a new inode cache with the given capacity and TTL.
func NewInodeCache(maxSize int, ttl time.Duration) *InodeCache {
	return &InodeCache{
		entries: make(map[zaskebpf.ZaskInodeKey]time.Time, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Contains checks if the inode key is in the cache and not expired.
func (c *InodeCache) Contains(key zaskebpf.ZaskInodeKey) bool {
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

// Add inserts an inode key into the cache. If the cache is full,
// expired entries are evicted first; if still full, the oldest entry
// is removed.
func (c *InodeCache) Add(key zaskebpf.ZaskInodeKey) {
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
		var oldestKey zaskebpf.ZaskInodeKey
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
func (c *InodeCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ---------------------------------------------------------------------------
// Tier 2: Static Rule Engine
// ---------------------------------------------------------------------------

// Rule is a single static detection rule from rules.yaml.
type Rule struct {
	compiled    *regexp.Regexp `yaml:"-"`
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Pattern     string         `yaml:"pattern"`
	Action      string         `yaml:"action"`
	Severity    string         `yaml:"severity"`
}

// rulesFile is the top-level structure of rules.yaml.
type rulesFile struct {
	Rules []Rule `yaml:"rules"`
}

// RuleEngine manages static detection rules and supports hot-reload.
type RuleEngine struct {
	log     zerolog.Logger
	stopCh  chan struct{}
	rules   []Rule
	mu      sync.RWMutex
	stopped bool
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

	// Compile all regex patterns.
	for i := range rf.Rules {
		compiled, err := regexp.Compile(rf.Rules[i].Pattern)
		if err != nil {
			return fmt.Errorf("compile pattern for rule %q: %w", rf.Rules[i].Name, err)
		}
		rf.Rules[i].compiled = compiled
	}

	r.mu.Lock()
	r.rules = rf.Rules
	r.mu.Unlock()

	r.log.Info().Int("count", len(rf.Rules)).Msg("rules loaded")
	return nil
}

// Match checks argv against all loaded rules and returns the first match.
func (r *RuleEngine) Match(argv string) (bool, Rule) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rule := range r.rules {
		if rule.compiled != nil && rule.compiled.MatchString(argv) {
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
