package ai

import (
	"fmt"
	"os"
	"os/user"
	"regexp"
	"strings"
	"unicode"
)

// defaultSystemPrompt is the SOC analyst persona prompt that instructs the
// LLM to return structured JSON verdicts. It can be overridden via config.
const defaultSystemPrompt = `You are a seasoned Security Operations Center (SOC) analyst embedded in a Linux kernel security system. Your task is to analyze binary execution events and assess their threat level.

You MUST respond with ONLY a JSON object in the following format:
{"risk": <float between 0.0 and 1.0>, "reasoning": "<brief explanation>"}

Do NOT include any text outside the JSON object. No markdown, no code fences, no commentary.

Risk scoring guidelines:
- 0.0-0.3: Normal system operations (package managers, cron jobs, legitimate admin tools)
- 0.3-0.6: Unusual but potentially legitimate (uncommon binaries, atypical arguments)
- 0.6-0.8: Suspicious activity (reverse shells, encoded payloads, privilege escalation attempts)
- 0.8-1.0: High-confidence threat (known attack patterns, command injection, data exfiltration)`

// contextDelimiterStart marks the beginning of untrusted event data in the
// prompt. The LLM is instructed to treat everything between these delimiters
// as raw data, not instructions.
const contextDelimiterStart = "<<<EVENT_DATA>>>"

// contextDelimiterEnd marks the end of untrusted event data.
const contextDelimiterEnd = "<<<END_EVENT_DATA>>>"

// EventContext holds the enriched execution context for prompt assembly.
// Fields are populated from the ring buffer event and OS lookups.
type EventContext struct {
	Argv        string
	ScriptPath  string
	ParentName  string // resolved from PPID via /proc/[ppid]/comm
	ParentArgv  string // resolved from PPID via /proc/[ppid]/cmdline
	Username    string // resolved from UID
	CgroupPath  string // resolved from /proc/[pid]/cgroup
	CgroupID    uint64 // raw cgroup ID (used internally, not sent to LLM)
	InodeNumber uint64 // raw inode (informational only — not used as identity in Phase 3c+)
	PID         uint32 // used internally for process kill, not sent to LLM
	PPID        uint32
	UID         uint32
}

// EnrichContext populates derived fields (Username, ParentName, ParentArgv,
// CgroupPath) from OS lookups. Failures are non-fatal — fields are left as
// descriptive fallbacks (e.g., "uid:0" if user lookup fails).
func (ec *EventContext) EnrichContext() {
	// Resolve UID to username.
	if u, err := user.LookupId(fmt.Sprintf("%d", ec.UID)); err == nil {
		ec.Username = u.Username
	} else {
		ec.Username = fmt.Sprintf("uid:%d", ec.UID)
	}

	// Resolve PPID to parent process name via /proc.
	ec.ParentName = resolveProcessName(ec.PPID)

	// Resolve PPID to parent command line via /proc.
	ec.ParentArgv = resolveProcessCmdline(ec.PPID)

	// Resolve PID to cgroup path via /proc.
	ec.CgroupPath = resolveCgroupPath(ec.PID)
}

// resolveProcessName reads /proc/[pid]/comm to get the process name.
// Returns a fallback string if the process has exited or is unreadable.
func resolveProcessName(pid uint32) string {
	if pid == 0 {
		return "kernel"
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid:%d", pid)
	}
	return strings.TrimSpace(string(data))
}

// resolveProcessCmdline reads /proc/[pid]/cmdline to get the full command
// line of a process. Arguments are NUL-separated in procfs; we join them
// with spaces. Returns empty string if unreadable (process exited).
func resolveProcessCmdline(pid uint32) string {
	if pid == 0 {
		return ""
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	// cmdline is NUL-separated; trim trailing NUL and replace with spaces.
	data = []byte(strings.TrimRight(string(data), "\x00"))
	return strings.ReplaceAll(string(data), "\x00", " ")
}

// resolveCgroupPath reads /proc/[pid]/cgroup and extracts the cgroup path.
// For cgroup v2 (unified hierarchy), the format is "0::/path". For v1,
// we look for common controllers. Returns empty string if unreadable.
func resolveCgroupPath(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// cgroup v2 unified: "0::/system.slice/nginx.service"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			path := parts[2]
			if path != "" && path != "/" {
				return path
			}
		}
	}
	return ""
}

// BuildPrompt assembles the full prompt from the system prompt template
// and the enriched event context. The event data is wrapped in delimiter
// tokens to clearly separate system instructions from untrusted input.
//
// If customSystemPrompt is non-empty, it replaces the default system prompt.
func BuildPrompt(ctx EventContext, customSystemPrompt string) (system string, userMsg string) {
	system = defaultSystemPrompt
	if customSystemPrompt != "" {
		system = customSystemPrompt
	}

	// Sanitize all user-controlled inputs before injection.
	safeArgv := SanitizeInput(ctx.Argv)
	safeScript := SanitizeInput(ctx.ScriptPath)
	safeParent := SanitizeInput(ctx.ParentName)
	safeUsername := SanitizeInput(ctx.Username)

	// Sanitize new enrichment fields.
	safeParentArgv := SanitizeInput(ctx.ParentArgv)
	safeCgroupPath := SanitizeInput(ctx.CgroupPath)

	var b strings.Builder
	b.WriteString("Analyze the following binary execution event for security threats.\n\n")
	b.WriteString(contextDelimiterStart)
	b.WriteString("\n")
	fmt.Fprintf(&b, "User: %s (UID %d)\n", safeUsername, ctx.UID)
	fmt.Fprintf(&b, "Command: %s\n", safeArgv)
	if safeScript != "" {
		fmt.Fprintf(&b, "Script: %s\n", safeScript)
	}
	fmt.Fprintf(&b, "Parent: %s\n", safeParent)
	if safeParentArgv != "" {
		fmt.Fprintf(&b, "Parent Command: %s\n", safeParentArgv)
	}
	if safeCgroupPath != "" {
		fmt.Fprintf(&b, "Service: %s\n", safeCgroupPath)
	}
	b.WriteString(contextDelimiterEnd)

	return system, b.String()
}

// promptInjectionPattern matches common prompt injection attempts.
// This catches patterns like "ignore previous instructions", "you are now",
// "system:", and similar instruction-override phrases.
var promptInjectionPattern = regexp.MustCompile(
	`(?i)(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)|` +
		`you\s+are\s+now|` +
		`new\s+instructions?:|` +
		`system\s*:|` +
		`assistant\s*:|` +
		`\bdo\s+not\s+follow\b|` +
		`\bforget\s+(everything|all|previous)\b|` +
		`\brole\s*:\s*system\b)`)

// SanitizeInput removes or escapes potentially dangerous content from
// user-controlled inputs (argv, script paths, etc.) before injection
// into the AI prompt. This defends against prompt injection attacks.
//
// The function:
//  1. Strips control characters (except common whitespace).
//  2. Removes markdown formatting that could confuse the LLM.
//  3. Replaces known prompt injection patterns with a safe placeholder.
//  4. Truncates excessively long inputs.
func SanitizeInput(input string) string {
	if input == "" {
		return ""
	}

	const maxInputLen = 4096

	// 1. Strip control characters (keep \n, \t, \r, space).
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return r
		}
		if unicode.IsControl(r) {
			return -1 // drop
		}
		return r
	}, input)

	// 2. Escape markdown-like formatting that could alter LLM parsing.
	// Replace backticks and triple-backticks to prevent code block injection.
	cleaned = strings.ReplaceAll(cleaned, "```", "'''")
	cleaned = strings.ReplaceAll(cleaned, "`", "'")

	// 3. Neutralize prompt injection patterns.
	cleaned = promptInjectionPattern.ReplaceAllString(cleaned, "[FILTERED]")

	// 4. Truncate to maximum length.
	if len(cleaned) > maxInputLen {
		cleaned = cleaned[:maxInputLen] + "...[truncated]"
	}

	return cleaned
}
