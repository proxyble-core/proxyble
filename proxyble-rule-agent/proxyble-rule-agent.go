/*
Copyright (c) 2026 Lucio D'Orazio Pedro de Matos,  www.proxyble.com
License: Subject to proxyble license.)
__________________________________________________________________________________________


# Documentation: Unified Proxyble Rule Agent (UPM)

**Version:** 2026.2

**Target Architecture:** Linux (ARM64/x86_64)

**Core Dependencies:** `nftables`, `haproxy` (with Runtime API enabled)

---

## 1. Project Overview

Proxyble Rule Agent is an event-driven Go application designed to orchestrate network security and traffic shaping across two different layers of the Linux networking stack:
1. **Layer 3/4 (Network/Transport):** Managed via `nftables` for high-performance packet filtering.
2. **Layer 7 (Application):** Managed via `HAProxy` for sophisticated request handling, rate limiting, and busy deflection.

The program acts as a "brain" that parses intent from a simple text-based inbox, determines the most efficient layer to enforce that intent, and ensures the underlying systems stay synchronized with a persisted JSON state.
Rule routing is exclusive. Each action is enforced by either NFTables or HAProxy, never both. Actions routed to NFTables are not written to HAProxy maps. Actions routed to HAProxy are not written to NFTables state.

---

## 2. Supported Actions & Implementation

The program accepts the `mode` flag (`http` or `tcp`) provided at runtime for service-profile
alignment and logging. Enforcement routing is action-based: each rule is routed to exactly
one backend.

### Layer 3/4 Actions (Implemented via `nftables`)

These actions are routed ONLY to the kernel's `pmgr` table. Source targets are IPv4-only and may be either a single IP or CIDR. Single IP input is normalized to `/32`.

| Action | Logic | Implementation Detail |
| --- | --- | --- |
| **DROP** | Silently discards packets. | Uses a per-rule source scope set; rule: `ip saddr @<scope> drop`. |
| **REJECT** | Discards packets and sends an unreachable response. | Uses a per-rule source scope set; rule: `ip saddr @<scope> reject`. |
| **LIMIT_CONCURRENT** | Limits total active connections from one source. | Uses a per-rule scope set plus a dynamic per-source set keyed by `ip saddr` with `ct count over <limit> drop`. |
| **LIMIT_CONN_RATE** | Limits how fast new connections are made from one source. | Uses a per-rule scope set plus a dynamic per-source set keyed by `ip saddr` with `ct state new` and `limit rate over <rate> drop`. |

### Layer 7 Actions (Implemented via `HAProxy`)

These actions use ONLY HAProxy Map files and the Runtime API. Except for `LIMIT_ENDPOINT_RATE`, source targets are IPv4-only and may be either a single IP or CIDR. Single IP input is normalized to `/32`.

| Action | Logic | Implementation Detail |
| --- | --- | --- |
| **LIMIT_BANDWIDTH** | Limits response bandwidth. | Maps target to `BW_LIM` in `rules.map` and stores the limit (e.g., `15mb`) in `params.map`. |
| **TIMEOUT** | Forces a shorter backend response timeout. | Maps target to `T_OUT` code in `rules.map`. |
| **LIMIT_RATE_SLOW** | Applies the HAProxy rate-reject policy. | Maps target to `RATE_REJ` code in `rules.map`. |
| **BUSY_DEFLECTION** | Applies the HAProxy busy policy. | Maps target to `BUSY` code in `rules.map`. |
| **LIMIT_ENDPOINT_RATE** | Applies a path-scoped HAProxy rate rule for one source. | Maps IP to `ENDPOINT_RATE` in `rules.map`, stores the requested rate in `params.map`, and writes `<ip>|<path-prefix> -> <limit-per-10s>` entries to `endpoint-rates.map`. |

Source target examples:
* `203.0.113.42` is accepted as a single IPv4 source and normalized internally to `203.0.113.42/32`.
* `203.0.113.0/24` applies the rule to the entire IPv4 CIDR block.
* `0.0.0.0/0` is accepted for global IPv4 rules and emits an alert log. Permanent global `DROP` and `REJECT` rules are refused; they must include an expiration.

For `LIMIT_CONCURRENT` and `LIMIT_CONN_RATE`, CIDR targets define the scope of
eligible clients, while the dynamic NFTables set uses each packet's `ip saddr`
as the counter key. A `/24` or `0.0.0.0/0` target therefore gives each matching
source IP its own connection counter or rate bucket.

`LIMIT_ENDPOINT_RATE` is intended for HTTP/HTTPS mode, where HAProxy can inspect the request path.
The inbox syntax is:

`LIMIT_ENDPOINT_RATE IP RATE ENDPOINTS [EXPIRATION]`

`LIMIT_ENDPOINT_RATE` intentionally remains single-IP only for the MVP because it uses a composite `IP|path` key.

* `RATE` uses the same readable style as connection-rate rules, but supports second and minute units because the generated HAProxy frontend enforces a fixed 10-second request-rate window. Examples: `10/second`, `120/minute`.
* `ENDPOINTS` is a comma-separated list of path prefixes with no spaces. Each endpoint must start with `/`, must not include query strings or fragments, and must be more specific than `/`. Example: `/login,/api/export,/mcp/tools`.
* The rule is source-specific and endpoint-specific. HAProxy builds a lookup key from the current source address and request path, then uses `map_beg` so `/api/export` also covers `/api/export/jobs/123`.
* Matching requests are tracked in a stick table with the HAProxy `base32+src` key, which scopes the request rate to the source plus requested path. When the current rate exceeds the normalized 10-second threshold, HAProxy returns HTTP `429`.

---

## 3. Operational Mechanics

### Runtime Usage

The program must be executed with exactly one mode argument unless printing help or version
information.

Usage:

`proxyble-rule-agent [http|tcp]`
`proxyble-rule-agent -h | --help`
`proxyble-rule-agent -v | --version`

* `http` processes rules for HTTP/HTTPS HAProxy enforcement, including endpoint rules.
* `tcp` processes rules for TCP-focused enforcement; endpoint rules are skipped.
* `-h` and `--help` print usage instructions and exit without touching rule state, locks,
  logs, HAProxy, or NFTables.
* `-v` and `--version` print the current version (`2026.2`) and exit without touching rule
  state, locks, logs, HAProxy, or NFTables.

### Batch Processing & Zero-Downtime Updates

One of the core design principles of this program is to **avoid service restarts**.

* **HAProxy Updates:** The program **never restarts HAProxy**. Instead, it connects to the HAProxy Runtime API via a Unix Domain Socket (`/run/haproxy/admin.sock`). It clears and repopulates `rules.map`, `params.map`, and `endpoint-rates.map` using runtime commands, reads the Runtime API responses, and treats reported command errors as enforcement failures. These map updates do not drop active connections.
* **NFTables Updates:** The program uses a "Nuclear Reset" batch pattern. It writes all instructions to a private temporary file and executes `nft -f`. This tells the kernel to process the entire table wipe and rebuild as a **single atomic transaction**. The firewall is never "open" during the update.

### Synchronization & Persistence

The program maintains "Source of Truth" JSON files in `/var/lib/proxyble-rule-agent/`.

1. **Parsing:** New rules arrive in `inbox.tmp`.
2. **Merging:** The program loads the existing JSON state and merges the new rules. If a target moves between enforcement backends, stale state is removed from the previous backend.
3. **Expiring:** It checks the `ExpiresAt` field of every rule. If the time has passed, the rule is deleted from the state.
4. **Enforcement:** Only after the state is cleaned and updated does the program trigger the `applyNFT` or `applyHAProxy` functions.

### Execution Triggers

The program does not run as a continuous background daemon. It is triggered by `systemd` in two ways:

1. **Event-Driven:** A `.path` unit monitors `inbox.tmp`. The moment a rule is written to that file, the program runs.
2. **Time-Driven:** A `.timer` unit runs the program every minute. This ensures that even if no new rules are added, expired rules are still purged from the firewall regularly.

---

## 4. Safety & Concurrency Controls

* **File Locking:** The program uses `syscall.Flock` on `/run/proxyble-rule-agent/rule_agent.lock`. If a large batch of rules is still being processed and another trigger occurs, the second instance will exit immediately to prevent data corruption.
* **Backoff Timer:** To prevent CPU spikes during "rule storms," the program records a timestamp in `last_reload`. It will wait at least 1 second between consecutive executions.
* **Renaming Logic:** Upon starting, the program renames `inbox.tmp` to `inbox.tmp.processing`, then immediately recreates a fresh `root:riodb` inbox file. This gives the processor a stable snapshot while RioDB keeps a narrow append-only handoff target.




*/

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// --- Configuration ---
const (
	// File paths for communication and state
	inputTmpFile   = "/var/spool/proxyble/rules/inbox.tmp"      // Path triggered by .path unit
	lockFile       = "/run/proxyble-rule-agent/rule_agent.lock" // Ensures only one instance runs
	lastReloadFile = "/var/lib/proxyble-rule-agent/last_reload" // Tracks timestamps for backoff logic
	logDir         = "/var/log/proxyble-rule-agent"             // Directory for daily logs

	// State persistence: allows the program to remember active rules between runs
	nftStateFile     = "/var/lib/proxyble-rule-agent/rule_state_nft.json"
	haproxyStateFile = "/var/lib/proxyble-rule-agent/rule_state_haproxy.json"

	// HAProxy Core configuration
	socketPath       = "/run/haproxy/admin.sock"              // Unix socket for HAProxy Runtime API
	mapRules         = "/etc/haproxy/maps/rules.map"          // Maps source targets to HAProxy actions
	mapParams        = "/etc/haproxy/maps/params.map"         // Maps source targets to specific values (e.g., "15mb")
	mapEndpointRates = "/etc/haproxy/maps/endpoint-rates.map" // Maps "IP|path-prefix" to per-window request limits

	backoffSeconds = 1 // Minimum time between executions
	maxRetries     = 3 // Socket connection retries

	endpointRateWindowSeconds = 10 // Must match HAProxy http_req_rate(10s)
	maxHAProxyInt             = 2147483647
	globalIPv4CIDR            = "0.0.0.0/0"
	inboxFileMode             = 0o620
	privateFileMode           = 0o600
	privateDirMode            = 0o700
	maxInputLinesPerRun       = 10000
	nftDynamicSetSize         = 65536
)

var errNoInput = errors.New("no input")

const (
	appName    = "proxyble-rule-agent"
	appVersion = "2026.2"

	SystemNFTables = "NFTABLES"
	SystemHAProxy  = "HAPROXY"
)

// Rule Types: Supported actions from the inbox.tmp file
const (
	ActionDrop            = "DROP"
	ActionReject          = "REJECT"
	ActionLimitConcurrent = "LIMIT_CONCURRENT"
	ActionLimitConnRate   = "LIMIT_CONN_RATE"
	ActionLimitBandwidth  = "LIMIT_BANDWIDTH"
	ActionTimeout         = "TIMEOUT"
	ActionLimitRateSlow   = "LIMIT_RATE_SLOW"
	ActionBusyDeflection  = "BUSY_DEFLECTION"
	ActionLimitEndpoint   = "LIMIT_ENDPOINT_RATE"

	// HAProxy Internal Codes: Translated from Rule Types for HAProxy map consumption
	HaCodeBandwidth    = "BW_LIM"
	HaCodeTimeout      = "T_OUT"
	HaCodeRateRej      = "RATE_REJ"
	HaCodeBusy         = "BUSY"
	HaCodeEndpointRate = "ENDPOINT_RATE"
)

// Rule represents a single firewall or proxy rule
type Rule struct {
	IP        string    `json:"ip"`         // IPv4 CIDR target for most actions; single IP for LIMIT_ENDPOINT_RATE
	Action    string    `json:"action"`     // e.g., DROP, REJECT
	Parameter string    `json:"parameter"`  // e.g., "15mb", "55"
	Duration  string    `json:"duration"`   // Raw string for nftables timeout (e.g., "10m")
	System    string    `json:"system"`     // Routed to "NFTABLES" or "HAPROXY"
	ExpiresAt time.Time `json:"expires_at"` // Calculated absolute time for expiration

	Endpoints         []string `json:"endpoints,omitempty"`           // LIMIT_ENDPOINT_RATE path prefixes
	EndpointRateLimit int      `json:"endpoint_rate_limit,omitempty"` // LIMIT_ENDPOINT_RATE threshold per endpointRateWindowSeconds
}

// State represents the total set of active rules to be persisted to disk
type State struct {
	Rules map[string]Rule `json:"rules"`
}

// durationRegex matches input like "10s", "5m", "1h", "2d"
var durationRegex = regexp.MustCompile(`^([0-9]+)([smhd])$`)
var positiveIntRegex = regexp.MustCompile(`^[1-9][0-9]*$`)
var connRateRegex = regexp.MustCompile(`^([1-9][0-9]*)/(s|sec|second|m|min|minute|h|hour|d|day)$`)
var bandwidthRegex = regexp.MustCompile(`^([1-9][0-9]*)(b|byte|bytes|kb|kbyte|kbytes|mb|mbyte|mbytes)(?:/(s|sec|second|m|min|minute|h|hour|d|day))?$`)
var endpointPathRegex = regexp.MustCompile(`^/[A-Za-z0-9._~%!$&'()*+;=:@/-]+$`)

func main() {
	mode, handled, exitCode := handleCLIArgs(os.Args[1:], os.Stdout, os.Stderr)
	if handled {
		os.Exit(exitCode)
	}

	setupDailyLogger()

	// Ensure mutual exclusion using a file lock
	lock := acquireLock(lockFile)
	defer releaseLock(lock)

	// Respect the backoff timer to prevent CPU thrashing
	waitBackoff()

	now := time.Now()
	nftState := loadState(nftStateFile)
	haState := loadState(haproxyStateFile)

	hasNftChanges := false
	hasHaChanges := false

	// Load and parse new entries from the inbox.tmp file
	newRules := loadInput(inputTmpFile, now)

	// 1. Distribution Logic: Route rules to either NFTables or HAProxy based on action type.
	for target, p := range newRules {
		if shouldSkipRuleForMode(p, mode) {
			log.Printf("ACTION=SKIPPED MODE=%s TYPE=%s TARGET=%s MSG=\"action requires HTTP/HTTPS HAProxy mode\"", mode, p.Action, p.IP)
			continue
		}

		system := p.System
		if p.System == SystemNFTables {
			nftState.Rules[target] = p
			if _, exists := haState.Rules[target]; exists {
				delete(haState.Rules, target)
				hasHaChanges = true
				log.Printf("ACTION=MOVED_FROM_HAPROXY SYSTEM=NFTABLES MODE=%s TYPE=%s TARGET=%s", mode, p.Action, p.IP)
			}
			hasNftChanges = true
		} else {
			haState.Rules[target] = p
			if _, exists := nftState.Rules[target]; exists {
				delete(nftState.Rules, target)
				hasNftChanges = true
				log.Printf("ACTION=MOVED_FROM_NFTABLES SYSTEM=HAPROXY MODE=%s TYPE=%s TARGET=%s", mode, p.Action, p.IP)
			}
			hasHaChanges = true
		}

		logMsg := fmt.Sprintf("ACTION=ADDED SYSTEM=%s MODE=%s TYPE=%s TARGET=%s", system, mode, p.Action, p.IP)
		if p.Parameter != "" {
			logMsg += " PARAM=" + p.Parameter
		}
		if len(p.Endpoints) > 0 {
			logMsg += " ENDPOINTS=" + strings.Join(p.Endpoints, ",")
		}
		log.Println(logMsg)
	}

	// 2. Expiration Logic: Remove rules that have passed their ExpiresAt timestamp
	for target, p := range nftState.Rules {
		if !p.ExpiresAt.IsZero() && p.ExpiresAt.Before(now) {
			delete(nftState.Rules, target)
			hasNftChanges = true
			log.Printf("ACTION=EXPIRED SYSTEM=NFTABLES TYPE=%s TARGET=%s", p.Action, p.IP)
		}
	}
	for target, p := range haState.Rules {
		if !p.ExpiresAt.IsZero() && p.ExpiresAt.Before(now) {
			delete(haState.Rules, target)
			hasHaChanges = true
			log.Printf("ACTION=EXPIRED SYSTEM=HAPROXY TYPE=%s TARGET=%s", p.Action, p.IP)
		}
	}

	// 3. Apply Changes: Push the new states to the respective kernels/services
	if hasNftChanges {
		if err := applyNFT(nftState); err != nil {
			log.Printf("ERROR SYSTEM=NFTABLES MSG=\"%v\"", err)
		} else {
			if err := saveState(nftStateFile, nftState); err != nil {
				log.Printf("ERROR SYSTEM=NFTABLES MSG=\"state save failed: %v\"", err)
			}
		}
	}

	if hasHaChanges {
		if err := applyHAProxy(haState); err != nil {
			log.Printf("ERROR SYSTEM=HAPROXY MSG=\"%v\"", err)
		} else {
			if err := saveState(haproxyStateFile, haState); err != nil {
				log.Printf("ERROR SYSTEM=HAPROXY MSG=\"state save failed: %v\"", err)
			}
		}
	}
}

func handleCLIArgs(args []string, stdout, stderr io.Writer) (mode string, handled bool, exitCode int) {
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "-h", "--help", "-help", "help":
			printUsage(stdout)
			return "", true, 0
		case "-v", "--version", "-version", "version":
			printVersion(stdout)
			return "", true, 0
		}
	}

	if len(args) != 1 {
		fmt.Fprintf(stderr, "Usage error: expected exactly one mode argument.\n\n")
		printUsage(stderr)
		return "", true, 1
	}

	mode = strings.ToLower(args[0])
	if mode != "http" && mode != "tcp" {
		fmt.Fprintf(stderr, "Usage error: mode must be either http or tcp.\n\n")
		printUsage(stderr)
		return "", true, 1
	}

	return mode, false, 0
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "%s %s\n", appName, appVersion)
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `%s %s

Usage:
  %s [http|tcp]
  %s -h | --help
  %s -v | --version

Modes:
  http    Process rules for HTTP/HTTPS HAProxy enforcement, including endpoint rules.
  tcp     Process rules for TCP-focused enforcement; endpoint rules are skipped.

Input:
  Reads rule commands from %s.

Examples:
  %s http
  %s tcp
  %s --version
`, appName, appVersion, appName, appName, appName, inputTmpFile, appName, appName, appName)
}

// --- Logic Dispatcher ---

// isNftAction determines if a rule belongs in the kernel firewall (L3/L4)
func isNftAction(action string) bool {
	switch action {
	case ActionDrop, ActionReject, ActionLimitConcurrent, ActionLimitConnRate:
		return true
	}
	return false
}

func shouldSkipRuleForMode(p Rule, mode string) bool {
	return mode == "tcp" && p.Action == ActionLimitEndpoint
}

// applyNFT generates a batch script for nftables and executes it
func applyNFT(s State) error {
	batch := buildNFTBatch(s)
	if err := applyNFTBatch(batch); err != nil {
		if nftBatchFailedBecauseTableMissing(err) {
			return applyNFTBatch(buildNFTBatchForMissingTable(s))
		}
		return err
	}
	return nil
}

func applyNFTBatch(batch string) error {
	// Write batch to a private temp file for atomic nft execution.
	tmp, err := os.CreateTemp("", "proxyble-nft-*.rules")
	if err != nil {
		return err
	}
	tmpFile := tmp.Name()
	defer os.Remove(tmpFile)
	if _, err := tmp.WriteString(batch); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(privateFileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// -f executes the entire file as a single transaction
	output, err := exec.Command("nft", "-f", tmpFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildNFTBatch(s State) string {
	return buildNFTBatchWithReset(s, true)
}

func buildNFTBatchForMissingTable(s State) string {
	return buildNFTBatchWithReset(s, false)
}

func buildNFTBatchWithReset(s State, deleteExistingTable bool) string {
	var sb strings.Builder
	// Recreate only proxyble-rule-agent-owned objects in one nft transaction.
	if deleteExistingTable {
		sb.WriteString("delete table inet pmgr\n")
	}
	sb.WriteString("add table inet pmgr\n")

	// Re-initialize the infrastructure skeleton
	sb.WriteString("add chain inet pmgr managed_rules\n")
	sb.WriteString("add chain inet pmgr input { type filter hook input priority 0; policy accept; }\n")

	// Link the input hook to our managed chain
	sb.WriteString("add rule inet pmgr input jump managed_rules\n")

	for _, p := range sortedRules(s, SystemNFTables) {
		switch p.Action {
		case ActionDrop:
			writeNFTVerdictRule(&sb, p, "drop")
		case ActionReject:
			writeNFTVerdictRule(&sb, p, "reject")
		case ActionLimitConcurrent:
			writeNFTLimitConcurrentRule(&sb, p)
		case ActionLimitConnRate:
			writeNFTLimitConnRateRule(&sb, p)
		}
	}
	return sb.String()
}

func nftBatchFailedBecauseTableMissing(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "no such file") ||
		strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "not found")
}

// applyHAProxy communicates with the HAProxy Runtime API over a Unix Domain Socket
func applyHAProxy(s State) error {
	for _, command := range buildHAProxyCommands(s) {
		response, err := runHAProxyRuntimeCommand(command)
		if err != nil {
			return fmt.Errorf("runtime api command %q failed: %w", command, err)
		}
		if hasHAProxyRuntimeError(response) {
			return fmt.Errorf("runtime api command %q returned: %s", command, strings.TrimSpace(response))
		}
		if strings.TrimSpace(response) != "" {
			log.Printf("ACTION=HAPROXY_RUNTIME_RESPONSE CMD=%q MSG=%q", command, strings.TrimSpace(response))
		}
	}
	return nil
}

func runHAProxyRuntimeCommand(command string) (string, error) {
	var lastErr error
	payload := command + "\n"

	// Retry loop for socket connectivity
	for i := 0; i < maxRetries; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			return sendHAProxyRuntimePayload(conn, payload)
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("socket connection failed: %v", lastErr)
}

func buildHAProxyCommands(s State) []string {
	commands := []string{
		fmt.Sprintf("clear map %s", mapRules),
		fmt.Sprintf("clear map %s", mapParams),
		fmt.Sprintf("clear map %s", mapEndpointRates),
	}

	for _, p := range sortedRules(s, SystemHAProxy) {
		haCode := translateToHaCode(p.Action)
		commands = append(commands, fmt.Sprintf("add map %s %s %s", mapRules, p.IP, haCode))
		if p.Parameter != "" {
			commands = append(commands, fmt.Sprintf("add map %s %s %s", mapParams, p.IP, p.Parameter))
		}
		if p.Action == ActionLimitEndpoint {
			for _, endpoint := range p.Endpoints {
				commands = append(commands, fmt.Sprintf("add map %s %s %d", mapEndpointRates, endpointMapKey(p.IP, endpoint), p.EndpointRateLimit))
			}
		}
	}
	return commands
}

func buildHAProxyPayload(s State) string {
	commands := buildHAProxyCommands(s)
	if len(commands) == 0 {
		return ""
	}
	return strings.Join(commands, "\n") + "\n"
}

func sendHAProxyRuntimePayload(conn net.Conn, payload string) (string, error) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && len(response) > 0 {
			return string(response), nil
		}
		return string(response), err
	}
	return string(response), nil
}

func hasHAProxyRuntimeError(response string) bool {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		lowerLine := strings.ToLower(line)
		if lowerLine == "" {
			continue
		}
		if strings.Contains(lowerLine, "unknown") ||
			strings.Contains(lowerLine, "invalid") ||
			strings.Contains(lowerLine, "error") ||
			strings.Contains(lowerLine, "failed") ||
			strings.Contains(lowerLine, "can't find") ||
			strings.Contains(lowerLine, "cannot find") ||
			strings.Contains(lowerLine, "not found") ||
			strings.Contains(lowerLine, "no such") {
			return true
		}
	}
	return false
}

// translateToHaCode converts human-friendly actions to short HAProxy codes used in ACLs
func translateToHaCode(action string) string {
	switch action {
	case ActionLimitBandwidth:
		return HaCodeBandwidth
	case ActionTimeout:
		return HaCodeTimeout
	case ActionLimitRateSlow:
		return HaCodeRateRej
	case ActionBusyDeflection:
		return HaCodeBusy
	case ActionLimitEndpoint:
		return HaCodeEndpointRate
	}
	return action
}

// --- IO and Parsing ---

// loadInput reads the inbox file, renames it for processing, recreates the
// narrow RioDB-writable handoff, and parses commands from the stable snapshot.
func loadInput(path string, now time.Time) map[string]Rule {
	out := make(map[string]Rule)
	procPath, err := rotateInput(path)
	if err != nil {
		if !errors.Is(err, errNoInput) && !errors.Is(err, os.ErrNotExist) {
			log.Printf("ERROR ACTION=ROTATE_INPUT FILE=%s MSG=\"%v\"", path, err)
		}
		return out
	}
	defer os.Remove(procPath)

	file, err := os.Open(procPath)
	if err != nil {
		log.Printf("ERROR ACTION=OPEN_INPUT FILE=%s MSG=\"%v\"", procPath, err)
		return out
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > maxInputLinesPerRun {
			log.Printf("ACTION=SKIPPED MSG=\"input batch line limit exceeded\" LIMIT=%d FILE=%s", maxInputLinesPerRun, procPath)
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := parseRuleLine(line, now)
		if err != nil {
			log.Printf("ACTION=SKIPPED MSG=%q LINE=%q", err.Error(), line)
			continue
		}
		out[p.IP] = p
	}
	if err := scanner.Err(); err != nil {
		log.Printf("ERROR ACTION=READ_INPUT FILE=%s MSG=\"%v\"", procPath, err)
	}
	return out
}

func rotateInput(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = ensureInboxFromParent(path)
		}
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing symlinked inbox")
	}
	if info.Size() == 0 {
		if err := ensureInboxFile(path, ownerFromInfo(info), groupFromInfo(info)); err != nil {
			return "", err
		}
		return "", errNoInput
	}

	uid, gid := ownerFromInfo(info), groupFromInfo(info)
	procPath := path + ".processing"
	if err := os.Remove(procPath); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(path, procPath); err != nil {
		return "", err
	}
	if err := ensureInboxFile(path, uid, gid); err != nil {
		log.Printf("ERROR ACTION=RECREATE_INPUT FILE=%s MSG=\"%v\"", path, err)
	}
	return procPath, nil
}

func ensureInboxFromParent(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return err
	}
	uid := os.Getuid()
	if os.Geteuid() == 0 {
		uid = 0
	}
	return ensureInboxFile(path, uid, groupFromInfo(info))
}

func ensureInboxFile(path string, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, inboxFileMode)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, inboxFileMode)
}

func ownerFromInfo(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return os.Getuid()
}

func groupFromInfo(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Gid)
	}
	return os.Getgid()
}

func parseRuleLine(line string, now time.Time) (Rule, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return Rule{}, fmt.Errorf("expected action and source target")
	}

	action := strings.ToUpper(parts[0])
	if !isKnownAction(action) {
		return Rule{}, fmt.Errorf("unknown action %s", action)
	}

	system := SystemHAProxy
	if isNftAction(action) {
		system = SystemNFTables
	}

	args, err := parseActionArgs(action, parts[2:], now)
	if err != nil {
		return Rule{}, err
	}

	target, err := normalizeRuleTarget(action, parts[1])
	if err != nil {
		return Rule{}, err
	}
	if isGlobalIPv4Target(target) {
		if (action == ActionDrop || action == ActionReject) && args.ExpiresAt.IsZero() {
			log.Printf("ALERT ACTION=GLOBAL_IPV4_TARGET_REJECTED TYPE=%s TARGET=%s MSG=\"permanent global denial refused\"", action, target)
			return Rule{}, fmt.Errorf("%s %s requires an expiration to avoid permanent global denial", action, globalIPv4CIDR)
		}
		log.Printf("ALERT ACTION=GLOBAL_IPV4_TARGET_ACCEPTED TYPE=%s TARGET=%s MSG=\"rule applies to every IPv4 source\"", action, target)
	}

	return Rule{
		IP:                target,
		Action:            action,
		Parameter:         args.Parameter,
		Duration:          args.Duration,
		System:            system,
		ExpiresAt:         args.ExpiresAt,
		Endpoints:         args.Endpoints,
		EndpointRateLimit: args.EndpointRateLimit,
	}, nil
}

func normalizeRuleTarget(action, rawTarget string) (string, error) {
	if action == ActionLimitEndpoint {
		if strings.Contains(rawTarget, "/") {
			return "", fmt.Errorf("%s does not support CIDR targets yet", action)
		}
		parsedIP := net.ParseIP(rawTarget)
		if parsedIP == nil || parsedIP.To4() == nil {
			return "", fmt.Errorf("%s requires a single IPv4 source", action)
		}
		return parsedIP.To4().String(), nil
	}
	return normalizeIPv4CIDRTarget(rawTarget)
}

func normalizeIPv4CIDRTarget(rawTarget string) (string, error) {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return "", fmt.Errorf("source target cannot be empty")
	}

	if strings.Contains(rawTarget, "/") {
		ip, network, err := net.ParseCIDR(rawTarget)
		if err != nil {
			return "", fmt.Errorf("invalid IPv4 CIDR target %s", rawTarget)
		}
		if ip.To4() == nil || network.IP.To4() == nil {
			return "", fmt.Errorf("source target %s must be IPv4", rawTarget)
		}
		network.IP = network.IP.To4()
		return network.String(), nil
	}

	parsedIP := net.ParseIP(rawTarget)
	if parsedIP == nil || parsedIP.To4() == nil {
		return "", fmt.Errorf("source target %s must be an IPv4 address or IPv4 CIDR", rawTarget)
	}
	return parsedIP.To4().String() + "/32", nil
}

func isGlobalIPv4Target(target string) bool {
	return target == globalIPv4CIDR
}

type parsedActionArgs struct {
	Parameter         string
	Duration          string
	ExpiresAt         time.Time
	Endpoints         []string
	EndpointRateLimit int
}

func parseActionArgs(action string, args []string, now time.Time) (parsedActionArgs, error) {
	switch action {
	case ActionDrop, ActionReject, ActionLimitRateSlow, ActionBusyDeflection:
		return parseNoParamArgs(action, args, now)
	case ActionLimitConcurrent:
		if len(args) < 1 || len(args) > 2 {
			return parsedActionArgs{}, fmt.Errorf("%s expects a limit and optional expiration", action)
		}
		if !positiveIntRegex.MatchString(args[0]) {
			return parsedActionArgs{}, fmt.Errorf("%s limit must be a positive integer", action)
		}
		return parseParamWithOptionalExpiration(args[0], args[1:], now)
	case ActionLimitConnRate:
		if len(args) < 1 || len(args) > 2 {
			return parsedActionArgs{}, fmt.Errorf("%s expects a rate and optional expiration", action)
		}
		rate, err := normalizeConnRate(args[0])
		if err != nil {
			return parsedActionArgs{}, err
		}
		return parseParamWithOptionalExpiration(rate, args[1:], now)
	case ActionLimitBandwidth:
		if len(args) < 1 || len(args) > 2 {
			return parsedActionArgs{}, fmt.Errorf("%s expects a bandwidth and optional expiration", action)
		}
		bandwidth, err := normalizeBandwidth(args[0])
		if err != nil {
			return parsedActionArgs{}, err
		}
		return parseParamWithOptionalExpiration(bandwidth, args[1:], now)
	case ActionTimeout:
		if len(args) < 1 || len(args) > 2 {
			return parsedActionArgs{}, fmt.Errorf("%s expects a timeout and optional expiration", action)
		}
		timeoutValue, err := normalizeDurationValue(args[0])
		if err != nil {
			return parsedActionArgs{}, fmt.Errorf("%s timeout %q is invalid", action, args[0])
		}
		return parseParamWithOptionalExpiration(timeoutValue, args[1:], now)
	case ActionLimitEndpoint:
		if len(args) < 2 || len(args) > 3 {
			return parsedActionArgs{}, fmt.Errorf("%s expects a rate, comma-separated endpoints, and optional expiration", action)
		}
		rate, limit, err := normalizeEndpointRate(args[0])
		if err != nil {
			return parsedActionArgs{}, err
		}
		endpoints, err := normalizeEndpoints(args[1])
		if err != nil {
			return parsedActionArgs{}, err
		}
		parsed, err := parseParamWithOptionalExpiration(rate, args[2:], now)
		if err != nil {
			return parsedActionArgs{}, err
		}
		parsed.Endpoints = endpoints
		parsed.EndpointRateLimit = limit
		return parsed, nil
	}
	return parsedActionArgs{}, fmt.Errorf("unknown action %s", action)
}

func parseNoParamArgs(action string, args []string, now time.Time) (parsedActionArgs, error) {
	if len(args) > 1 {
		return parsedActionArgs{}, fmt.Errorf("%s expects only an optional expiration", action)
	}
	if len(args) == 0 {
		return parsedActionArgs{}, nil
	}
	duration, expiry, err := parseExpiration(args[0], now)
	if err != nil {
		return parsedActionArgs{}, err
	}
	return parsedActionArgs{Duration: duration, ExpiresAt: expiry}, nil
}

func parseParamWithOptionalExpiration(param string, args []string, now time.Time) (parsedActionArgs, error) {
	if len(args) == 0 {
		return parsedActionArgs{Parameter: param}, nil
	}
	duration, expiry, err := parseExpiration(args[0], now)
	if err != nil {
		return parsedActionArgs{}, err
	}
	return parsedActionArgs{Parameter: param, Duration: duration, ExpiresAt: expiry}, nil
}

func parseExpiration(input string, now time.Time) (string, time.Time, error) {
	duration := strings.ToLower(input)
	expiry, ok := parseDuration(duration, now)
	if !ok {
		return "", time.Time{}, fmt.Errorf("expiration %q is invalid", input)
	}
	return duration, expiry, nil
}

// parseDuration converts "10m" to a Go time.Time object
func parseDuration(input string, now time.Time) (time.Time, bool) {
	input = strings.ToLower(input)
	m := durationRegex.FindStringSubmatch(input)
	if len(m) != 3 {
		return time.Time{}, false
	}
	val, _ := strconv.Atoi(m[1])
	var d time.Duration
	switch m[2] {
	case "s":
		d = time.Duration(val) * time.Second
	case "m":
		d = time.Duration(val) * time.Minute
	case "h":
		d = time.Duration(val) * time.Hour
	case "d":
		d = time.Duration(val) * 24 * time.Hour
	}
	return now.Add(d), true
}

func normalizeDurationValue(input string) (string, error) {
	value := strings.ToLower(input)
	if !durationRegex.MatchString(value) {
		return "", fmt.Errorf("invalid duration %q", input)
	}
	return value, nil
}

func normalizeConnRate(input string) (string, error) {
	value := strings.ToLower(input)
	m := connRateRegex.FindStringSubmatch(value)
	if len(m) != 3 {
		return "", fmt.Errorf("connection rate %q must look like 25/second", input)
	}
	return fmt.Sprintf("%s/%s", m[1], normalizeTimeUnit(m[2])), nil
}

func normalizeEndpointRate(input string) (string, int, error) {
	value := strings.ToLower(input)
	m := connRateRegex.FindStringSubmatch(value)
	if len(m) != 3 {
		return "", 0, fmt.Errorf("endpoint rate %q must look like 10/second or 120/minute", input)
	}

	count, _ := strconv.Atoi(m[1])
	unit := normalizeTimeUnit(m[2])
	limit, err := endpointRateLimitPerWindow(count, unit)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%d/%s", count, unit), limit, nil
}

func endpointRateLimitPerWindow(count int, unit string) (int, error) {
	var unitSeconds int64
	switch unit {
	case "second":
		unitSeconds = 1
	case "minute":
		unitSeconds = 60
	default:
		return 0, fmt.Errorf("LIMIT_ENDPOINT_RATE supports second or minute rates; got %s", unit)
	}

	limit := (int64(count)*endpointRateWindowSeconds + unitSeconds - 1) / unitSeconds
	if limit < 1 {
		limit = 1
	}
	if limit > maxHAProxyInt {
		return 0, fmt.Errorf("LIMIT_ENDPOINT_RATE normalized limit %d is too large", limit)
	}
	return int(limit), nil
}

func normalizeEndpoints(input string) ([]string, error) {
	if input == "" {
		return nil, fmt.Errorf("endpoint list cannot be empty")
	}

	rawEndpoints := strings.Split(input, ",")
	seen := make(map[string]struct{}, len(rawEndpoints))
	endpoints := make([]string, 0, len(rawEndpoints))
	for _, raw := range rawEndpoints {
		endpoint := strings.TrimSpace(raw)
		if endpoint == "" {
			return nil, fmt.Errorf("endpoint list contains an empty value")
		}
		if endpoint == "/" {
			return nil, fmt.Errorf("endpoint %q is too broad for LIMIT_ENDPOINT_RATE", endpoint)
		}
		if strings.ContainsAny(endpoint, " \t\r\n|?#,") {
			return nil, fmt.Errorf("endpoint %q must not contain whitespace, pipe, query, fragment, or comma characters", endpoint)
		}
		if !endpointPathRegex.MatchString(endpoint) {
			return nil, fmt.Errorf("endpoint %q must be a URL path prefix that starts with /", endpoint)
		}
		if _, exists := seen[endpoint]; exists {
			continue
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	sort.Strings(endpoints)
	return endpoints, nil
}

func normalizeBandwidth(input string) (string, error) {
	value := strings.ToLower(input)
	m := bandwidthRegex.FindStringSubmatch(value)
	if len(m) != 4 {
		return "", fmt.Errorf("bandwidth %q must look like 15mb", input)
	}
	unit := normalizeBandwidthUnit(m[2])
	if unit == "" {
		return "", fmt.Errorf("bandwidth unit %q is not supported", m[2])
	}
	return m[1] + unit, nil
}

func normalizeTimeUnit(unit string) string {
	switch unit {
	case "s", "sec", "second":
		return "second"
	case "m", "min", "minute":
		return "minute"
	case "h", "hour":
		return "hour"
	case "d", "day":
		return "day"
	}
	return unit
}

func normalizeBandwidthUnit(unit string) string {
	switch unit {
	case "b", "byte", "bytes":
		return "b"
	case "kb", "kbyte", "kbytes":
		return "kb"
	case "mb", "mbyte", "mbytes":
		return "mb"
	}
	return ""
}

func isKnownAction(action string) bool {
	switch action {
	case ActionDrop, ActionReject, ActionLimitConcurrent, ActionLimitConnRate,
		ActionLimitBandwidth, ActionTimeout, ActionLimitRateSlow, ActionBusyDeflection,
		ActionLimitEndpoint:
		return true
	}
	return false
}

func sortedRules(s State, system string) []Rule {
	rules := make([]Rule, 0, len(s.Rules))
	for _, p := range s.Rules {
		if p.System == system {
			rules = append(rules, p)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].IP != rules[j].IP {
			return rules[i].IP < rules[j].IP
		}
		return rules[i].Action < rules[j].Action
	})
	return rules
}

func writeNFTSetElement(sb *strings.Builder, setName string, p Rule) {
	if p.Duration != "" {
		sb.WriteString(fmt.Sprintf("add element inet pmgr %s { %s timeout %s }\n", setName, p.IP, p.Duration))
		return
	}
	sb.WriteString(fmt.Sprintf("add element inet pmgr %s { %s }\n", setName, p.IP))
}

func writeNFTRuleSet(sb *strings.Builder, setName string, p Rule) {
	sb.WriteString(fmt.Sprintf("add set inet pmgr %s { type ipv4_addr; flags interval, timeout; }\n", setName))
	writeNFTSetElement(sb, setName, p)
}

func writeNFTVerdictRule(sb *strings.Builder, p Rule, verdict string) {
	scopeSetName, _ := nftPerSourceSetNames(p)
	if isGlobalIPv4Target(p.IP) {
		sb.WriteString(fmt.Sprintf("add rule inet pmgr managed_rules %s\n", verdict))
		return
	}
	writeNFTRuleSet(sb, scopeSetName, p)
	sb.WriteString(fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s %s\n", scopeSetName, verdict))
}

func writeNFTLimitConcurrentRule(sb *strings.Builder, p Rule) {
	scopeSetName, sourceSetName := nftPerSourceSetNames(p)
	writeNFTConcurrentSet(sb, sourceSetName)
	if isGlobalIPv4Target(p.IP) {
		sb.WriteString(fmt.Sprintf("add rule inet pmgr managed_rules add @%s { ip saddr ct count over %s } drop\n", sourceSetName, p.Parameter))
		return
	}
	writeNFTRuleSet(sb, scopeSetName, p)
	sb.WriteString(fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s add @%s { ip saddr ct count over %s } drop\n", scopeSetName, sourceSetName, p.Parameter))
}

func writeNFTLimitConnRateRule(sb *strings.Builder, p Rule) {
	scopeSetName, sourceSetName := nftPerSourceSetNames(p)
	writeNFTDynamicSet(sb, sourceSetName, nftConnRateElementTimeout(p.Parameter))
	if isGlobalIPv4Target(p.IP) {
		sb.WriteString(fmt.Sprintf("add rule inet pmgr managed_rules ct state new add @%s { ip saddr limit rate over %s } drop\n", sourceSetName, p.Parameter))
		return
	}
	writeNFTRuleSet(sb, scopeSetName, p)
	sb.WriteString(fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s ct state new add @%s { ip saddr limit rate over %s } drop\n", scopeSetName, sourceSetName, p.Parameter))
}

func writeNFTConcurrentSet(sb *strings.Builder, setName string) {
	sb.WriteString(fmt.Sprintf("add set inet pmgr %s { type ipv4_addr; flags dynamic; size %d; }\n", setName, nftDynamicSetSize))
}

func writeNFTDynamicSet(sb *strings.Builder, setName, timeout string) {
	sb.WriteString(fmt.Sprintf("add set inet pmgr %s { type ipv4_addr; flags dynamic, timeout; timeout %s; size %d; }\n", setName, timeout, nftDynamicSetSize))
}

func nftPerSourceSetNames(p Rule) (scopeSetName, sourceSetName string) {
	base := nftRuleSetName(p)
	return base + "_scope", base + "_src"
}

func nftRuleSetName(p Rule) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(p.Action))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(p.IP))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(p.Parameter))
	return fmt.Sprintf("p_%08x", h.Sum32())
}

func nftConnRateElementTimeout(rate string) string {
	parts := strings.Split(rate, "/")
	if len(parts) != 2 {
		return "10s"
	}
	switch parts[1] {
	case "second":
		return "10s"
	case "minute":
		return "2m"
	case "hour":
		return "2h"
	case "day":
		return "2d"
	default:
		return "10s"
	}
}

func endpointMapKey(ip, endpoint string) string {
	return ip + "|" + endpoint
}

// --- Infrastructure Utils ---

// loadState reads the persisted JSON state from disk
func loadState(path string) State {
	s := State{Rules: make(map[string]Rule)}
	data, err := os.ReadFile(path)
	if err == nil {
		if strings.TrimSpace(string(data)) != "" {
			if err := json.Unmarshal(data, &s); err != nil {
				log.Printf("ERROR ACTION=LOAD_STATE FILE=%s MSG=\"%v\"", path, err)
			}
		}
	} else if !os.IsNotExist(err) {
		log.Printf("ERROR ACTION=LOAD_STATE FILE=%s MSG=\"%v\"", path, err)
	}
	if s.Rules == nil {
		s.Rules = make(map[string]Rule)
	}
	s.Rules = normalizeStateRuleKeys(s.Rules)
	return s
}

func normalizeStateRuleKeys(rules map[string]Rule) map[string]Rule {
	normalized := make(map[string]Rule, len(rules))
	for key, p := range rules {
		if p.IP == "" {
			p.IP = key
		}
		if p.Action != ActionLimitEndpoint {
			if target, err := normalizeIPv4CIDRTarget(p.IP); err == nil {
				p.IP = target
			}
		}
		normalized[p.IP] = p
	}
	return normalized
}

// saveState writes the current state to JSON for persistence
func saveState(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), privateDirMode); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(path), privateDirMode)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

// setupDailyLogger configures the log package to write to YYYY-MM-DD.log
func setupDailyLogger() {
	if err := os.MkdirAll(logDir, privateDirMode); err != nil {
		log.SetOutput(os.Stderr)
		log.Printf("ERROR ACTION=SETUP_LOG_DIR DIR=%s MSG=\"%v\"", logDir, err)
		return
	}
	_ = os.Chmod(logDir, privateDirMode)
	logPath := filepath.Join(logDir, time.Now().Format("2006-01-02")+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, privateFileMode)
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Printf("ERROR ACTION=OPEN_LOG FILE=%s MSG=\"%v\"", logPath, err)
		return
	}
	_ = os.Chmod(logPath, privateFileMode)
	log.SetOutput(f)
}

// acquireLock uses syscall.Flock to prevent multiple instances from running
func acquireLock(path string) *os.File {
	if err := os.MkdirAll(filepath.Dir(path), privateDirMode); err != nil {
		log.Printf("ERROR ACTION=OPEN_LOCK_DIR DIR=%s MSG=\"%v\"", filepath.Dir(path), err)
		os.Exit(1)
	}
	_ = os.Chmod(filepath.Dir(path), privateDirMode)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, privateFileMode)
	if err != nil {
		log.Printf("ERROR ACTION=OPEN_LOCK FILE=%s MSG=\"%v\"", path, err)
		os.Exit(1)
	}
	_ = os.Chmod(path, privateFileMode)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		os.Exit(0) // Exit silently if another process holds the lock
	}
	return f
}

// releaseLock unlocks and closes the lock file
func releaseLock(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

// waitBackoff ensures the program doesn't run more than once per backoffSeconds
func waitBackoff() {
	data, _ := os.ReadFile(lastReloadFile)
	if epoch, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
		elapsed := time.Since(time.Unix(epoch, 0))
		if elapsed < backoffSeconds*time.Second {
			time.Sleep(backoffSeconds*time.Second - elapsed)
		}
	}
	// Update last reload timestamp
	if err := os.MkdirAll(filepath.Dir(lastReloadFile), privateDirMode); err != nil {
		log.Printf("ERROR ACTION=BACKOFF_DIR DIR=%s MSG=\"%v\"", filepath.Dir(lastReloadFile), err)
		return
	}
	_ = os.Chmod(filepath.Dir(lastReloadFile), privateDirMode)
	if err := writePrivateFile(lastReloadFile, []byte(fmt.Sprintf("%d", time.Now().Unix()))); err != nil {
		log.Printf("ERROR ACTION=BACKOFF_WRITE FILE=%s MSG=\"%v\"", lastReloadFile, err)
	}
}

func writePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, privateFileMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, privateFileMode)
}
