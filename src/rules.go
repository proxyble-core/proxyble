package main

// rules.go implements Proxyble's manual rule workflows for both the CLI and the
// interactive wizard. It intentionally mirrors the legacy bash text and table
// layout for rule selection, prompt wording, and summaries because operators
// have already tested that flow. The file also reads rule-agent state JSON,
// writes inbox commands, performs IP/rule matching, and coordinates safe resets
// with the rule agent.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// knownActions is the complete display/order baseline for rule types.
var knownActions = []string{
	"BUSY_DEFLECTION",
	"DROP",
	"LIMIT_BANDWIDTH",
	"LIMIT_CONCURRENT",
	"LIMIT_CONN_RATE",
	"LIMIT_ENDPOINT_RATE",
	"LIMIT_RATE_SLOW",
	"REJECT",
	"TIMEOUT",
}

// tcpRuleSupport identifies the subset of rules that can work in TCP mode; HTTP
// and HTTPS modes can use all known actions.
var tcpRuleSupport = map[string]bool{
	"DROP":             true,
	"LIMIT_CONCURRENT": true,
	"LIMIT_CONN_RATE":  true,
	"REJECT":           true,
}

// ruleDescriptions is the operator-facing rule help text copied from the legacy
// bash wizard.
var ruleDescriptions = map[string]string{
	"BUSY_DEFLECTION":     "Returns a temporary busy response when service pressure is rising. Useful when a source may be legitimate but should back off for a few minutes.",
	"DROP":                "Silently blocks traffic from the source. Best for clearly hostile traffic where no response is needed and you want the lowest processing cost.",
	"LIMIT_BANDWIDTH":     "Slows response bandwidth for downloads or large API output. Useful when a source is expensive but should not be fully blocked.",
	"LIMIT_CONCURRENT":    "Caps how many active connections the source can hold at once. Useful when a client is tying up connection slots or holding sessions open.",
	"LIMIT_CONN_RATE":     "Caps how quickly the source can create new connections. Useful for floods, scanners, and aggressive retry loops.",
	"LIMIT_ENDPOINT_RATE": "Rate-limits one individual source IP on selected HTTP paths. Useful when abuse is focused on /login, /search, or /api/export.",
	"LIMIT_RATE_SLOW":     "Returns HTTP 429 rate-limit responses to an overactive source. Useful when a client should be told to slow down before stronger action.",
	"REJECT":              "Blocks traffic and fails it quickly. Best when a source is unwanted and a fast failure is better than making the client wait.",
	"TIMEOUT":             "Shortens how long backend requests may wait for this source. Useful when a client is causing slow or expensive work that should end sooner.",
}

// ruleDefaultParam supplies prompt defaults for rule types that require a
// parameter.
var ruleDefaultParam = map[string]string{
	"LIMIT_BANDWIDTH":     "10mb",
	"LIMIT_CONCURRENT":    "50",
	"LIMIT_CONN_RATE":     "25/second",
	"LIMIT_ENDPOINT_RATE": "10/second",
	"TIMEOUT":             "5s",
}

// Check IP table widths match the compact legacy bash table closely enough to
// keep selectable rows readable on standard 80-column terminals.
const (
	checkIPRuleWidth       = 15
	checkIPTypeWidth       = 19
	checkIPParametersWidth = 17
	checkIPExpirationWidth = 20
	checkIPTableWidth      = checkIPRuleWidth + checkIPTypeWidth + checkIPParametersWidth + checkIPExpirationWidth + 6
)

// rulePaths groups all filesystem and executable paths needed by rule workflows.
type rulePaths struct {
	StateDir      string
	LogDir        string
	WatchFile     string
	RuleAgentBin  string
	RuleAgentMode string
	NFTState      string
	HAProxyState  string
	CurrentLog    string
}

// stateFile is the parsed rule-agent state JSON; Extra exists so future changes
// can preserve awareness of fields outside the rules map.
type stateFile struct {
	Rules map[string]map[string]any `json:"rules"`
	Extra map[string]any            `json:"-"`
}

// ruleMatch represents one active rule that matched a check-IP lookup.
type ruleMatch struct {
	System     string
	Path       string
	Key        string
	Target     string
	Action     string
	Parameters string
	Expires    string
}

// ruleDraft is the validated rule command before it is written to the inbox.
type ruleDraft struct {
	Rule       string
	Target     string
	Parameter  string
	Endpoints  string
	Expiration string
	Line       string
}

// getRulePaths resolves rule-agent paths from config.ini and the current traffic
// mode.
func getRulePaths(c *Config) rulePaths {
	stateDir := c.Get("rule_agent", "state_dir", "/var/lib/proxyble-rule-agent")
	logDir := c.Get("rule_agent", "log_dir", "/var/log/proxyble-rule-agent")
	watchFile := c.Get("rule_agent", "watch_file", defaultRuleInbox)
	bin := c.Get("rule_agent", "binary_path", "/usr/local/bin/proxyble-rule-agent")
	mode := "tcp"
	if trafficMode, err := c.TrafficMode(); err == nil {
		if m, err := ruleAgentModeForTraffic(trafficMode); err == nil {
			mode = m
		}
	}
	return rulePaths{
		StateDir:      stateDir,
		LogDir:        logDir,
		WatchFile:     watchFile,
		RuleAgentBin:  bin,
		RuleAgentMode: mode,
		NFTState:      filepath.Join(stateDir, "rule_state_nft.json"),
		HAProxyState:  filepath.Join(stateDir, "rule_state_haproxy.json"),
		CurrentLog:    filepath.Join(logDir, time.Now().Format("2006-01-02")+".log"),
	}
}

// availableRules returns rule types valid for the current traffic mode.
func availableRules(c *Config) []string {
	mode, _ := c.TrafficMode()
	var rules []string
	for _, action := range knownActions {
		if mode == "http" || mode == "https" || tcpRuleSupport[action] {
			rules = append(rules, action)
		}
	}
	return rules
}

// trafficModeLabel returns the menu label for the current listener mode.
func trafficModeLabel(c *Config) string {
	mode, _ := c.TrafficMode()
	switch mode {
	case "http":
		return "HTTP"
	case "https":
		return "HTTPS with local TLS termination"
	default:
		return "TCP/TLS-passthrough"
	}
}

// listRules counts active rules by type across nftables and HAProxy state files.
func listRules(a *App) error {
	paths := getRulePaths(a.Config)
	counts := map[string]int{}
	for _, action := range knownActions {
		counts[action] = 0
	}
	for _, path := range []string{paths.NFTState, paths.HAProxyState} {
		state, err := loadRuleState(path)
		if err != nil {
			a.Printf("[NOTICE] %v\n", err)
			continue
		}
		for _, policy := range state.Rules {
			if !policyActive(policy) {
				continue
			}
			action := strings.ToUpper(valueString(policy["action"]))
			if action != "" {
				counts[action]++
			}
		}
	}
	a.Printf("Rules Currently In Effect\n\n")
	total := 0
	keys := append([]string(nil), knownActions...)
	sort.Strings(keys)
	for _, action := range keys {
		total += counts[action]
		a.Printf("%-28s%8d\n", action+":", counts[action])
	}
	a.Printf("%-28s%8d\n", "TOTAL:", total)
	a.Printf("%s\n\n", hr(79))
	return nil
}

// parseRuleAddArgs parses non-interactive --rules-add flags into draft fields.
func parseRuleAddArgs(args []string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := func() (string, error) {
			if strings.Contains(arg, "=") {
				return strings.SplitN(arg, "=", 2)[1], nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}
		switch {
		case arg == "--rule" || arg == "--rule-type":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["rule"] = v
		case strings.HasPrefix(arg, "--rule=") || strings.HasPrefix(arg, "--rule-type="):
			out["rule"], _ = value()
		case arg == "--target" || arg == "--source":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["target"] = v
		case strings.HasPrefix(arg, "--target=") || strings.HasPrefix(arg, "--source="):
			out["target"], _ = value()
		case arg == "--expiration" || arg == "--expires":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["expiration"] = v
		case strings.HasPrefix(arg, "--expiration=") || strings.HasPrefix(arg, "--expires="):
			out["expiration"], _ = value()
		case arg == "--parameter" || arg == "--bandwidth" || arg == "--limit" || arg == "--max-connections" || arg == "--rate" || arg == "--timeout-value":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["parameter"] = v
		case strings.HasPrefix(arg, "--parameter=") || strings.HasPrefix(arg, "--bandwidth=") || strings.HasPrefix(arg, "--limit=") || strings.HasPrefix(arg, "--max-connections=") || strings.HasPrefix(arg, "--rate=") || strings.HasPrefix(arg, "--timeout-value="):
			out["parameter"], _ = value()
		case arg == "--endpoints" || arg == "--endpoint-prefixes":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["endpoints"] = v
		case strings.HasPrefix(arg, "--endpoints=") || strings.HasPrefix(arg, "--endpoint-prefixes="):
			out["endpoints"], _ = value()
		case arg == "--yes" || arg == "-y":
			out["yes"] = "true"
		default:
			return nil, fmt.Errorf("unknown option for --rules-add: %s", arg)
		}
	}
	return out, nil
}

// addRule routes to the interactive rule wizard or validates and commits a CLI
// rule addition.
func addRule(ctx context.Context, a *App, args []string) error {
	fields, err := parseRuleAddArgs(args)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		if a.CommandLine {
			return fmt.Errorf("--rules-add requires --rule, --target, and --expiration")
		}
		return addRuleInteractive(ctx, a)
	}
	draft, err := prepareRuleDraft(a.Config, fields)
	if err != nil {
		return err
	}
	assumeYes := a.AssumeYes
	if fields["yes"] == "true" {
		assumeYes = true
	}
	if a.CommandLine {
		ok, err := commandLineConfirm("Add this rule now?", assumeYes)
		if err != nil || !ok {
			if err != nil {
				return err
			}
			a.Printf("[NOTICE] Rule creation cancelled.\n")
			return nil
		}
		return commitRule(ctx, a, draft)
	}
	ok, err := confirm("Add this rule now?", assumeYes)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		a.Printf("[NOTICE] Rule creation cancelled.\n")
		return nil
	}
	return commitRule(ctx, a, draft)
}

// prepareRuleDraft validates rule fields and builds the exact inbox line for the
// rule agent.
func prepareRuleDraft(c *Config, fields map[string]string) (ruleDraft, error) {
	rule := strings.ToUpper(fields["rule"])
	target := fields["target"]
	expiration := fields["expiration"]
	if rule == "" || target == "" || expiration == "" {
		return ruleDraft{}, fmt.Errorf("--rules-add requires --rule, --target, and --expiration")
	}
	if !contains(availableRules(c), rule) {
		return ruleDraft{}, fmt.Errorf("rule type is not available for current traffic mode: %s", rule)
	}
	normalizedTarget, err := normalizeSourceTarget(rule, target)
	if err != nil {
		return ruleDraft{}, err
	}
	normalizedExpiration, err := normalizeExpiration(expiration)
	if err != nil {
		return ruleDraft{}, fmt.Errorf("--expiration must be none or a duration like 10s, 30m, 1h, or 1d")
	}
	parameter, endpoints := "", ""
	switch rule {
	case "LIMIT_BANDWIDTH":
		parameter, err = normalizeBandwidth(fields["parameter"])
		if err != nil {
			return ruleDraft{}, fmt.Errorf("LIMIT_BANDWIDTH requires --bandwidth like 500kb, 10mb, or 1gb")
		}
	case "LIMIT_CONCURRENT":
		if !positiveInteger(fields["parameter"]) {
			return ruleDraft{}, fmt.Errorf("LIMIT_CONCURRENT requires --limit with a positive whole number")
		}
		parameter = fields["parameter"]
	case "LIMIT_CONN_RATE":
		parameter, err = normalizeRate(fields["parameter"])
		if err != nil {
			return ruleDraft{}, fmt.Errorf("LIMIT_CONN_RATE requires --rate like 25/second or 100/minute")
		}
	case "LIMIT_ENDPOINT_RATE":
		parameter, err = normalizeRate(fields["parameter"])
		if err != nil {
			return ruleDraft{}, fmt.Errorf("LIMIT_ENDPOINT_RATE requires --rate like 10/second or 100/minute")
		}
		if !validEndpointList(fields["endpoints"]) {
			return ruleDraft{}, fmt.Errorf("LIMIT_ENDPOINT_RATE requires --endpoints with comma-separated path prefixes, each starting with /")
		}
		endpoints = fields["endpoints"]
	case "TIMEOUT":
		parameter, err = normalizeTimeout(fields["parameter"])
		if err != nil {
			return ruleDraft{}, fmt.Errorf("TIMEOUT requires --timeout-value like 5, 5s, 500ms, or 1m")
		}
	default:
		if fields["parameter"] != "" || fields["endpoints"] != "" {
			return ruleDraft{}, fmt.Errorf("%s does not accept rule parameters", rule)
		}
	}
	line := buildRuleLine(rule, normalizedTarget, parameter, endpoints, normalizedExpiration)
	return ruleDraft{Rule: rule, Target: normalizedTarget, Parameter: parameter, Endpoints: endpoints, Expiration: normalizedExpiration, Line: line}, nil
}

// commitRule appends a validated rule command, nudges the rule agent, writes an
// audit event, and reports success to the user.
func commitRule(ctx context.Context, a *App, draft ruleDraft) error {
	if err := ensureRuleInbox(a.Config); err != nil {
		return err
	}
	paths := getRulePaths(a.Config)
	if err := appendRuleToInbox(paths.WatchFile, draft.Line); err != nil {
		return err
	}
	if err := triggerRuleAgent(ctx, a, paths); err != nil {
		return err
	}
	writeRuleAudit(paths.LogDir, "ACTION=ADD_RULE TYPE=%s TARGET=%s PARAMETER=%s ENDPOINTS=%s EXPIRATION=%s INBOX=%s MSG=\"Manual rule appended to proxyble-rule-agent inbox.\"", draft.Rule, draft.Target, draft.Parameter, draft.Endpoints, expirationLabel(draft.Expiration), paths.WatchFile)
	a.Printf("[PASS] Rule added: %s\n", draft.Line)
	return nil
}

// addRuleInteractive runs the multi-page Rules -> Add wizard.
func addRuleInteractive(ctx context.Context, a *App) error {
	for {
		rule, err := selectRuleType(a.Config)
		if err != nil || rule == "" {
			return err
		}
		fields := map[string]string{"rule": rule}
		target, err := promptRuleSourceTarget(rule)
		if err != nil {
			if continueRuleAddAfterCancel() {
				continue
			}
			return nil
		}
		fields["target"] = target
		if err := promptRuleParameters(rule, fields); err != nil {
			if continueRuleAddAfterCancel() {
				continue
			}
			return nil
		}
		expiration, err := promptRuleExpiration(rule)
		if err != nil {
			if continueRuleAddAfterCancel() {
				continue
			}
			return nil
		}
		fields["expiration"] = expiration
		draft, err := prepareRuleDraft(a.Config, fields)
		if err != nil {
			return err
		}
		ok, err := confirmRuleDraft(draft, a.AssumeYes)
		if err != nil {
			return err
		}
		if !ok {
			if continueRuleAddAfterCancel() {
				continue
			}
			return nil
		}
		if err := commitRule(ctx, a, draft); err != nil {
			return err
		}
		if !selectNextRuleAction(getRulePaths(a.Config).WatchFile, draft.Line) {
			return nil
		}
	}
}

// selectRuleType renders the legacy rule-type table and returns the chosen rule.
func selectRuleType(c *Config) (string, error) {
	rules := availableRules(c)
	returnIndex := len(rules)
	if !supportsArrowMenu() {
		renderRuleTypePage(c, rules, -1)
		fmt.Fprint(os.Stderr, "\nSelect option: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		choice := strings.TrimSpace(line)
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(rules)+1 {
			return "", nil
		}
		if n == len(rules)+1 {
			return "", nil
		}
		clearScreen()
		return rules[n-1], nil
	}
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		return "", err
	}
	defer restore()
	fmt.Fprint(os.Stderr, "\033[?25l")
	defer fmt.Fprint(os.Stderr, "\033[?25h")
	selected := 0
	for {
		renderRuleTypePage(c, rules, selected)
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			return "", err
		}
		switch key {
		case "up":
			if selected > 0 {
				selected--
			}
		case "down":
			if selected < returnIndex {
				selected++
			}
		case "enter":
			clearScreen()
			if selected == returnIndex {
				return "", nil
			}
			return rules[selected], nil
		case "interrupt":
			handleInterruptRequest()
		case "q", "escape":
			clearScreen()
			return "", nil
		default:
			if n, ok := numericMenuChoice(key, len(rules)+1); ok {
				clearScreen()
				if n == returnIndex {
					return "", nil
				}
				return rules[n], nil
			}
		}
	}
}

// renderRuleTypePage draws the rule selection page with descriptions and current
// traffic-mode context.
func renderRuleTypePage(c *Config, rules []string, selected int) {
	renderRulesPage(fmt.Sprintf(`Rules are enforced 24x7, regardless of current traffic conditions.
Rules are always enforced on a per-IP basis. If you create a rule for a
network CIDR, limit counters and enforcement are still applied per individual
requester IP.

Rules available for %s traffic:`, trafficModeLabel(c)))
	printRuleTableHeader()
	for i, rule := range rules {
		printRuleOption(i == selected, rule, ruleDescriptions[rule])
	}
	fmt.Fprintf(os.Stderr, "  %s\n", hr(78))
	printRuleOption(selected == len(rules), "return to Rules menu", "Go back without adding a rule.")
	fmt.Fprintf(os.Stderr, "\n%sUse Up/Down arrows, Enter to select.%s", colorDim, colorReset)
}

// printRuleTableHeader prints the fixed two-column rule selector header.
func printRuleTableHeader() {
	fmt.Fprintf(os.Stderr, "  %-21s  %s\n", "RULE TYPE", "WHAT IT DOES")
	fmt.Fprintf(os.Stderr, "  %s\n", hr(78))
}

// printRuleOption prints one wrapped rule option row, highlighting it when
// selected.
func printRuleOption(selected bool, rule, description string) {
	prefix := "  "
	suffix := ""
	marker := " "
	if selected {
		prefix = "  " + colorBlueDark + colorReverse
		suffix = colorReset
		marker = ">"
	}
	wrapped := wrapWords(description, 50)
	if len(wrapped) == 0 {
		wrapped = []string{""}
	}
	for i, descLine := range wrapped {
		if i == 0 {
			fmt.Fprintf(os.Stderr, "%s%s %-21s  %-50s%s\n", prefix, marker, rule, descLine, suffix)
		} else {
			fmt.Fprintf(os.Stderr, "%s  %-21s  %-50s%s\n", prefix, "", descLine, suffix)
		}
	}
}

// promptRuleSourceTarget asks for and validates the source IP/CIDR affected by a
// new rule.
func promptRuleSourceTarget(rule string) (string, error) {
	hint := "Enter a client IPv4 address or CIDR block, such as 203.0.113.25 or 203.0.113.0/24."
	if rule == "LIMIT_ENDPOINT_RATE" {
		hint = "Enter one client IPv4 address. CIDR blocks are not supported for LIMIT_ENDPOINT_RATE."
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		renderRulesPage("Rule type: " + rule)
		fmt.Fprintf(os.Stderr, "%s\n\n", hint)
		fmt.Fprintf(os.Stderr, "%sType cancel to stop rule creation.%s\n\n", colorDim, colorReset)
		fmt.Fprint(os.Stderr, "Source target: ")
		value, err := reader.ReadString('\n')
		if err != nil && value == "" {
			return "", err
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(value) {
		case "", "cancel", "q", "quit":
			return "", fmt.Errorf("rule creation cancelled")
		}
		normalized, err := normalizeSourceTarget(rule, value)
		if err == nil {
			return normalized, nil
		}
		fmt.Fprintf(os.Stderr, "\n[ERROR] %s\n", sentenceCaseError(err.Error()))
		pauseAnyKey()
	}
}

// promptRuleParameters collects rule-specific parameters only for rules that
// need them.
func promptRuleParameters(rule string, fields map[string]string) error {
	switch rule {
	case "LIMIT_BANDWIDTH":
		value, err := promptRuleParameter(rule, "Bandwidth", ruleDefaultParam[rule], "Limit outbound response bandwidth for the source. Use units like kb, mb, or gb.", "bandwidth")
		fields["parameter"] = value
		return err
	case "LIMIT_CONCURRENT":
		value, err := promptRuleParameter(rule, "Maximum concurrent connections", ruleDefaultParam[rule], "Limit how many active connections this source can hold at once.", "integer")
		fields["parameter"] = value
		return err
	case "LIMIT_CONN_RATE":
		value, err := promptRuleParameter(rule, "Connection rate", ruleDefaultParam[rule], "Limit how quickly this source can create new connections. Use count/second or count/minute.", "rate")
		fields["parameter"] = value
		return err
	case "LIMIT_ENDPOINT_RATE":
		value, err := promptRuleParameter(rule, "Endpoint request rate", ruleDefaultParam[rule], "Limit requests from this IP on the selected endpoint prefixes. Use count/second or count/minute.", "rate")
		if err != nil {
			return err
		}
		fields["parameter"] = value
		endpoints, err := promptEndpointList(rule)
		fields["endpoints"] = endpoints
		return err
	case "TIMEOUT":
		value, err := promptRuleParameter(rule, "Backend timeout", ruleDefaultParam[rule], "Use a shorter backend response timeout for this source. A plain number means seconds.", "timeout")
		fields["parameter"] = value
		return err
	default:
		return nil
	}
}

// promptRuleParameter collects and validates one parameter such as bandwidth,
// count, rate, or timeout.
func promptRuleParameter(rule, label, defaultValue, helpText, validator string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		renderRulesPage("Rule type: " + rule)
		fmt.Fprintf(os.Stderr, "%s\n\n", helpText)
		fmt.Fprintf(os.Stderr, "%sPress Enter for default [%s], or type cancel to stop.%s\n\n", colorDim, defaultValue, colorReset)
		fmt.Fprintf(os.Stderr, "%s: ", label)
		value, err := reader.ReadString('\n')
		if err != nil && value == "" {
			return "", err
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(value) {
		case "cancel", "q", "quit":
			return "", fmt.Errorf("rule creation cancelled")
		}
		if value == "" {
			value = defaultValue
		}
		switch validator {
		case "bandwidth":
			if normalized, err := normalizeBandwidth(value); err == nil {
				return normalized, nil
			}
			fmt.Fprintln(os.Stderr, "\n[ERROR] Enter bandwidth like 500kb, 10mb, or 1gb. Short units like 10m are accepted and normalized.")
		case "integer":
			if positiveInteger(value) {
				return value, nil
			}
			fmt.Fprintln(os.Stderr, "\n[ERROR] Enter a positive whole number.")
		case "rate":
			if normalized, err := normalizeRate(value); err == nil {
				return normalized, nil
			}
			fmt.Fprintln(os.Stderr, "\n[ERROR] Enter a rate like 25/second or 100/minute.")
		case "timeout":
			if normalized, err := normalizeTimeout(value); err == nil {
				return normalized, nil
			}
			fmt.Fprintln(os.Stderr, "\n[ERROR] Enter a timeout like 5, 5s, 500ms, or 1m. A plain number means seconds.")
		}
		pauseAnyKey()
	}
}

// promptEndpointList collects HTTP path prefixes for LIMIT_ENDPOINT_RATE rules.
func promptEndpointList(rule string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	defaultValue := "/login,/api/export"
	for {
		renderRulesPage("Rule type: " + rule)
		fmt.Fprintln(os.Stderr, "Enter one or more HTTP path prefixes separated by commas.")
		fmt.Fprint(os.Stderr, "Examples: /login or /login,/api/export or /mcp/tools\n\n")
		fmt.Fprintf(os.Stderr, "%sPress Enter for default [%s], or type cancel to stop.%s\n\n", colorDim, defaultValue, colorReset)
		fmt.Fprint(os.Stderr, "Endpoint prefixes: ")
		value, err := reader.ReadString('\n')
		if err != nil && value == "" {
			return "", err
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(value) {
		case "cancel", "q", "quit":
			return "", fmt.Errorf("rule creation cancelled")
		}
		if value == "" {
			value = defaultValue
		}
		if validEndpointList(value) {
			return value, nil
		}
		fmt.Fprintln(os.Stderr, "\n[ERROR] Enter comma-separated HTTP path prefixes with no spaces. Each prefix must start with /.")
		pauseAnyKey()
	}
}

// promptRuleExpiration collects a duration or permanent "none" expiration.
func promptRuleExpiration(rule string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		renderRulesPage("Rule type: " + rule)
		fmt.Fprint(os.Stderr, "Enter an expiration value, or leave blank for a permanent rule.\n\n")
		fmt.Fprint(os.Stderr, "Examples for temporary rules: 10s, 30m, 1h, 1d.\n\n")
		fmt.Fprint(os.Stderr, "Expiration: ")
		value, err := reader.ReadString('\n')
		if err != nil && value == "" {
			return "", err
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(value) {
		case "":
			return "none", nil
		}
		if normalized, err := normalizeExpiration(value); err == nil {
			return normalized, nil
		}
		fmt.Fprintln(os.Stderr, "\n[ERROR] Enter a duration like 10s, 30m, 1h, or 1d, or leave blank for permanent.")
		pauseAnyKey()
	}
}

// confirmRuleDraft shows the final rule summary and asks for confirmation.
func confirmRuleDraft(draft ruleDraft, assumeYes bool) (bool, error) {
	renderRulesPage("Review the rule before it is added to the proxyble-rule-agent inbox.")
	printRuleSummary(draft)
	return confirm("Add this rule now?", assumeYes)
}

// printRuleSummary prints the reviewed fields for one rule draft.
func printRuleSummary(draft ruleDraft) {
	expiration := draft.Expiration
	if expiration == "none" {
		expiration = "none (permanent)"
	}
	fmt.Fprintf(os.Stderr, "Rule type       : %s\n", draft.Rule)
	fmt.Fprintf(os.Stderr, "Source target   : %s\n", draft.Target)
	if draft.Parameter != "" {
		fmt.Fprintf(os.Stderr, "Parameter       : %s\n", draft.Parameter)
	}
	if draft.Endpoints != "" {
		fmt.Fprintf(os.Stderr, "Endpoints       : %s\n", draft.Endpoints)
	}
	fmt.Fprintf(os.Stderr, "Expiration      : %s\n", expiration)
}

// continueRuleAddAfterCancel lets the operator recover from a cancelled prompt
// without leaving the Rules section.
func continueRuleAddAfterCancel() bool {
	choice, err := choiceMenu("[proxyble] Rules -> Add", "Rule creation was cancelled.\n\nChoose the next rule action.", [][2]string{
		{"add", "Add a rule"},
		{"back", "Return to Rules menu"},
	}, "")
	return err == nil && choice == "add"
}

// selectNextRuleAction asks whether another rule should be added after a
// successful commit.
func selectNextRuleAction(watchFile, line string) bool {
	prompt := fmt.Sprintf("Rule added to %s. Policy-manager will process it from that inbox.\n\nAdded rule:\n  %s\n\nChoose the next rule action.", watchFile, line)
	choice, err := choiceMenu("[proxyble] Rules -> Add", prompt, [][2]string{
		{"add", "Add another rule"},
		{"back", "Return to Rules menu"},
	}, "")
	return err == nil && choice == "add"
}

// renderRulesPage draws the standard Rules -> Add page chrome.
func renderRulesPage(prompt string) {
	clearScreen()
	banner(os.Stderr, "/var/log/proxyble/")
	pageHeader(os.Stderr, "[proxyble] Rules -> Add", prompt)
}

// wrapWords breaks description text into fixed-width lines for rule tables.
func wrapWords(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	line := ""
	for _, word := range words {
		if line == "" {
			line = word
		} else if len(line)+1+len(word) <= width {
			line += " " + word
		} else {
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// pauseAnyKey waits for one keystroke after validation errors in raw-menu flows.
func pauseAnyKey() {
	if !isTerminal(os.Stdin) {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%sPress any key to continue.%s", colorDim, colorReset)
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	defer restore()
	b, _ := readRequiredByte(os.Stdin)
	if b == 0x03 {
		handleInterruptRequest()
	}
	fmt.Fprintln(os.Stderr)
}

// sentenceCaseError makes validation errors look like sentence text in prompts.
func sentenceCaseError(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

// buildRuleLine creates the whitespace-delimited command consumed by the
// proxyble-rule-agent inbox.
func buildRuleLine(rule, target, parameter, endpoints, expiration string) string {
	parts := []string{rule, target}
	switch rule {
	case "LIMIT_BANDWIDTH", "LIMIT_CONCURRENT", "LIMIT_CONN_RATE", "TIMEOUT":
		parts = append(parts, parameter)
	case "LIMIT_ENDPOINT_RATE":
		parts = append(parts, parameter, endpoints)
	}
	if expiration != "none" {
		parts = append(parts, expiration)
	}
	return strings.Join(parts, " ")
}

// appendRuleToInbox safely appends one rule command to the watched inbox file.
func appendRuleToInbox(path, line string) error {
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o620)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscallFlock(f); err != nil {
		return err
	}
	defer syscallUnlock(f)
	_, err = fmt.Fprintln(f, line)
	return err
}

// syscallFlock acquires an exclusive lock for inbox appends.
func syscallFlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// syscallUnlock releases a lock acquired by syscallFlock.
func syscallUnlock(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// normalizeSourceTarget validates IPv4 addresses/CIDRs and applies rule-specific
// source-target restrictions.
func normalizeSourceTarget(action, target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, " \t\r\n") {
		return "", fmt.Errorf("enter one IPv4 address or CIDR block with no spaces")
	}
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err != nil || !prefix.Addr().Is4() {
			return "", fmt.Errorf("enter a valid IPv4 address or CIDR block, such as 203.0.113.25 or 203.0.113.0/24")
		}
		masked := prefix.Masked()
		if action == "LIMIT_ENDPOINT_RATE" {
			return "", fmt.Errorf("LIMIT_ENDPOINT_RATE supports one individual IPv4 address only, not CIDR notation")
		}
		if (action == "DROP" || action == "REJECT") && masked.String() == "0.0.0.0/0" {
			return "", fmt.Errorf("0.0.0.0/0 is not allowed for DROP or REJECT rules")
		}
		return masked.String(), nil
	}
	addr, err := netip.ParseAddr(target)
	if err != nil || !addr.Is4() {
		if action == "LIMIT_ENDPOINT_RATE" {
			return "", fmt.Errorf("enter a valid individual IPv4 address, such as 203.0.113.25")
		}
		return "", fmt.Errorf("enter a valid IPv4 address or CIDR block, such as 203.0.113.25 or 203.0.113.0/24")
	}
	return addr.String(), nil
}

// normalizeBandwidth accepts bandwidth values and expands short units.
func normalizeBandwidth(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) < 2 {
		return "", fmt.Errorf("invalid bandwidth")
	}
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	if i == 0 || v[0] == '0' {
		return "", fmt.Errorf("invalid bandwidth")
	}
	unit := v[i:]
	switch unit {
	case "k":
		unit = "kb"
	case "m":
		unit = "mb"
	case "g":
		unit = "gb"
	case "kb", "mb", "gb":
	default:
		return "", fmt.Errorf("invalid bandwidth")
	}
	return v[:i] + unit, nil
}

// normalizeRate validates rate values in count/second or count/minute form.
func normalizeRate(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	count, unit, ok := strings.Cut(v, "/")
	if !ok || !positiveInteger(count) {
		return "", fmt.Errorf("invalid rate")
	}
	if unit != "second" && unit != "minute" {
		return "", fmt.Errorf("invalid rate")
	}
	return count + "/" + unit, nil
}

// normalizeTimeout validates backend timeout parameters for TIMEOUT rules.
func normalizeTimeout(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	if i == 0 || v[0] == '0' {
		return "", fmt.Errorf("invalid timeout")
	}
	unit := v[i:]
	if unit == "" {
		unit = "s"
	}
	switch unit {
	case "ms", "s", "m":
		return v[:i] + unit, nil
	default:
		return "", fmt.Errorf("invalid timeout")
	}
}

// normalizeExpiration validates duration-style expirations and permanent aliases.
func normalizeExpiration(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "none", "never", "permanent":
		return "none", nil
	}
	if len(v) < 2 {
		return "", fmt.Errorf("invalid expiration")
	}
	unit := v[len(v)-1:]
	num := v[:len(v)-1]
	if !positiveInteger(num) {
		return "", fmt.Errorf("invalid expiration")
	}
	switch unit {
	case "s", "m", "h", "d":
		return num + unit, nil
	default:
		return "", fmt.Errorf("invalid expiration")
	}
}

// positiveInteger reports whether v is a non-zero whole number.
func positiveInteger(v string) bool {
	if v == "" || v[0] == '0' {
		return false
	}
	_, err := strconv.Atoi(v)
	return err == nil
}

// validEndpointList validates comma-separated HTTP path prefixes.
func validEndpointList(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	for _, part := range strings.Split(v, ",") {
		if !strings.HasPrefix(part, "/") || part == "" {
			return false
		}
		for _, r := range part {
			if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~/%:@+-", r) {
				continue
			}
			return false
		}
	}
	return true
}

// expirationLabel converts internal "none" into user/audit-facing "permanent".
func expirationLabel(v string) string {
	if v == "none" {
		return "permanent"
	}
	return v
}

// loadRuleState reads a rule-agent JSON state file, returning an empty state
// when the file does not exist yet.
func loadRuleState(path string) (stateFile, error) {
	state := stateFile{Rules: map[string]map[string]any{}, Extra: map[string]any{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return state, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return state, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}
	for k, v := range raw {
		if k != "rules" {
			state.Extra[k] = v
		}
	}
	if rules, ok := raw["rules"].(map[string]any); ok {
		for k, v := range rules {
			if m, ok := v.(map[string]any); ok {
				state.Rules[k] = m
			}
		}
	}
	return state, nil
}

// saveRuleState writes a state file while preserving non-rules top-level data.
func saveRuleState(path string, state stateFile) error {
	raw := map[string]any{}
	for k, v := range state.Extra {
		raw[k] = v
	}
	raw["rules"] = state.Rules
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteFile(path, data, 0o600)
}

// policyActive reports whether a state policy has not expired yet.
func policyActive(policy map[string]any) bool {
	expires := valueString(policy["expires_at"])
	if expires == "" || strings.HasPrefix(expires, "0001-01-01") {
		return true
	}
	t, err := parseGoTime(expires)
	if err != nil {
		return true
	}
	return t.After(time.Now().UTC())
}

// parseGoTime parses rule-agent timestamps, including truncated nanosecond
// fractions that can appear in JSON state.
func parseGoTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if strings.HasSuffix(value, "Z") {
		value = strings.TrimSuffix(value, "Z") + "+00:00"
	}
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		j := dot + 1
		for j < len(value) && value[j] >= '0' && value[j] <= '9' {
			j++
		}
		fraction := value[dot+1 : j]
		if len(fraction) > 9 {
			fraction = fraction[:9]
		}
		value = value[:dot+1] + fraction + value[j:]
	}
	return time.Parse(time.RFC3339Nano, value)
}

// valueString converts JSON state values into compact display strings.
func valueString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		parts := []string{}
		for _, item := range t {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

// checkIP finds active rules matching one IPv4 address and optionally removes a
// selected match. With no CLI arguments it runs the full interactive selector.
func checkIP(ctx context.Context, a *App, args []string) error {
	interactive := !a.CommandLine && len(args) == 0
	opts, err := parseCheckArgs(args)
	if err != nil {
		return err
	}
	if interactive {
		return checkIPInteractive(ctx, a)
	}
	if opts["ip"] == "" {
		return fmt.Errorf("--rules-check requires --ip")
	}
	ip, err := netip.ParseAddr(opts["ip"])
	if err != nil || !ip.Is4() {
		return fmt.Errorf("enter a valid IPv4 address")
	}
	paths := getRulePaths(a.Config)
	matches, err := loadMatchingRules(ip, paths)
	if err != nil {
		return err
	}
	if opts["remove"] != "1" {
		printMatches(a, ip.String(), matches)
		return nil
	}
	selected, err := selectMatch(opts, matches)
	if err != nil {
		printMatches(a, ip.String(), matches)
		return err
	}
	ok, err := confirmCheckedRuleRemoval(selected, a)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		a.Printf("[NOTICE] Rule removal cancelled.\n")
		return nil
	}
	return removeCheckedRule(ctx, a, paths, ip.String(), selected, false)
}

// checkIPInteractive prompts for IP addresses, lets the operator select a
// matching rule with arrows, and removes the selected rule after confirmation.
func checkIPInteractive(ctx context.Context, a *App) error {
	for {
		ipText, err := promptCheckIP()
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(ipText)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("enter a valid IPv4 address")
		}
		paths := getRulePaths(a.Config)
		matches, err := loadMatchingRules(ip, paths)
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			again, err := selectNoMatchesAction(ip.String())
			if err != nil {
				return err
			}
			if again {
				continue
			}
			return errActionCancelled
		}
		selected, action, err := selectMatchingRuleInteractive(ip.String(), matches)
		if err != nil {
			return err
		}
		switch action {
		case "again":
			continue
		case "back":
			return errActionCancelled
		}
		ok, err := confirmCheckedRuleRemoval(selected, a)
		if err != nil {
			return err
		}
		if !ok {
			a.Printf("[NOTICE] Rule removal cancelled.\n")
			return errActionCancelled
		}
		return removeCheckedRule(ctx, a, paths, ip.String(), selected, true)
	}
}

// removeCheckedRule safely removes one selected Check IP match and triggers
// rule-agent reconciliation.
func removeCheckedRule(ctx context.Context, a *App, paths rulePaths, ip string, selected ruleMatch, framedCompletion bool) error {
	cleanup, lock, err := quiesceRuleAgent(ctx, a)
	if err != nil {
		return err
	}
	removed, err := removeRuleFromState(selected)
	unlockFile(lock)
	if err != nil {
		cleanup()
		return err
	}
	if err := triggerRuleAgent(ctx, a, paths); err != nil {
		cleanup()
		return err
	}
	cleanup()
	writeRuleAudit(paths.LogDir, "ACTION=CHECK_IP_REMOVE_RULE QUERY_IP=%s TARGET=%s TYPE=%s SYSTEM=%s COUNT=%d MSG=\"Selected rule removed through proxyble-rule-agent state reconciliation.\"", ip, selected.Target, selected.Action, selected.System, removed)
	if framedCompletion {
		actionPage("[proxyble] Rules -> Check IP", "Rule removal complete.")
	}
	a.Printf("%s\n", checkedRuleRemovalCompleteMessage(ip, selected))
	return nil
}

func checkedRuleRemovalCompleteMessage(ip string, match ruleMatch) string {
	return fmt.Sprintf("Removed %s enforcement rule for source %s.", match.Action, ip)
}

// parseCheckArgs parses non-interactive --rules-check flags.
func parseCheckArgs(args []string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := func() (string, error) {
			if strings.Contains(arg, "=") {
				return strings.SplitN(arg, "=", 2)[1], nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}
		switch {
		case arg == "--ip":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["ip"] = v
		case strings.HasPrefix(arg, "--ip="):
			out["ip"], _ = value()
		case arg == "--remove" || arg == "--remove-rule":
			out["remove"] = "1"
		case arg == "--system":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["system"] = strings.ToUpper(v)
		case strings.HasPrefix(arg, "--system="):
			v, _ := value()
			out["system"] = strings.ToUpper(v)
		case arg == "--key" || arg == "--state-key":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["key"] = v
		case strings.HasPrefix(arg, "--key=") || strings.HasPrefix(arg, "--state-key="):
			out["key"], _ = value()
		case arg == "--rule" || arg == "--rule-type":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["rule"] = strings.ToUpper(v)
		case strings.HasPrefix(arg, "--rule=") || strings.HasPrefix(arg, "--rule-type="):
			v, _ := value()
			out["rule"] = strings.ToUpper(v)
		case arg == "--target":
			v, err := value()
			if err != nil {
				return nil, err
			}
			out["target"] = v
		case strings.HasPrefix(arg, "--target="):
			out["target"], _ = value()
		default:
			return nil, fmt.Errorf("unknown option for --rules-check: %s", arg)
		}
	}
	return out, nil
}

// promptCheckIP asks for one IPv4 address in the interactive check flow.
func promptCheckIP() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		clearScreen()
		banner(os.Stderr, "/var/log/proxyble/")
		pageHeader(os.Stderr, "[proxyble] Rules -> Check IP", "Enter an IP address to check, or type cancel to return to Rules.")
		fmt.Fprint(os.Stderr, "IP address or cancel: ")
		value, err := reader.ReadString('\n')
		if err != nil && value == "" {
			return "", err
		}
		value = strings.TrimSpace(value)
		if isCheckIPCancelInput(value) {
			return "", errActionCancelled
		}
		ip, err := netip.ParseAddr(value)
		if err == nil && ip.Is4() {
			return ip.String(), nil
		}
		fmt.Fprintln(os.Stderr, "\n[ERROR] Enter a valid IPv4 address.")
		pauseAnyKey()
	}
}

func isCheckIPCancelInput(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "cancel", "q", "quit":
		return true
	default:
		return false
	}
}

// loadMatchingRules returns active nftables/HAProxy state entries that affect
// the input IP address.
func loadMatchingRules(inputIP netip.Addr, paths rulePaths) ([]ruleMatch, error) {
	var matches []ruleMatch
	for _, spec := range []struct{ system, path string }{{"NFTABLES", paths.NFTState}, {"HAPROXY", paths.HAProxyState}} {
		state, err := loadRuleState(spec.path)
		if err != nil {
			return nil, err
		}
		for key, policy := range state.Rules {
			if !policyActive(policy) {
				continue
			}
			target := firstNonEmpty(valueString(policy["ip"]), key)
			if !targetContainsIP(target, inputIP) {
				continue
			}
			matches = append(matches, ruleMatch{
				System:     spec.system,
				Path:       spec.path,
				Key:        key,
				Target:     target,
				Action:     strings.ToUpper(valueString(policy["action"])),
				Parameters: parametersForPolicy(policy),
				Expires:    expiryDisplay(policy),
			})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Action+matches[i].Target+matches[i].System < matches[j].Action+matches[j].Target+matches[j].System
	})
	return matches, nil
}

// targetContainsIP reports whether a rule target IP or CIDR includes ip.
func targetContainsIP(target string, ip netip.Addr) bool {
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		return err == nil && prefix.Contains(ip)
	}
	addr, err := netip.ParseAddr(target)
	return err == nil && addr == ip
}

// parametersForPolicy extracts a readable parameter summary from a state policy.
func parametersForPolicy(policy map[string]any) string {
	action := strings.ToUpper(valueString(policy["action"]))
	param := firstPolicyValue(policy, "parameter", "parameters", "rate", "bandwidth", "timeout", "max_connections", "limit")
	endpoints := firstPolicyValue(policy, "endpoints", "endpoint", "paths", "path", "endpoint_prefixes", "path_prefixes")
	parts := []string{}
	if param != "" {
		if action == "LIMIT_ENDPOINT_RATE" {
			parts = append(parts, "rate "+param)
		} else {
			parts = append(parts, param)
		}
	}
	if endpoints != "" {
		parts = append(parts, endpoints)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "; ")
}

// firstPolicyValue returns the first non-empty value for a list of possible JSON
// keys used by different rule-agent versions.
func firstPolicyValue(policy map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := valueString(policy[key]); v != "" {
			return v
		}
	}
	return ""
}

// expiryDisplay formats a state expiration for tables and summaries.
func expiryDisplay(policy map[string]any) string {
	expires := valueString(policy["expires_at"])
	if expires == "" || strings.HasPrefix(expires, "0001-01-01") {
		return "none"
	}
	t, err := parseGoTime(expires)
	if err != nil {
		return expires
	}
	return t.UTC().Round(time.Second).Format(time.RFC3339)
}

// printMatches prints the CLI table for rules affecting an IP.
func printMatches(a *App, ip string, matches []ruleMatch) {
	if len(matches) == 0 {
		a.Printf("No active rules impact IP %s.\n", ip)
		return
	}
	a.Printf("Active rules impacting %s\n\n", ip)
	a.Printf("%-9s  %-24s  %-18s  %-21s  %-24s  %s\n", "SYSTEM", "KEY", "TARGET", "TYPE", "EXPIRATION", "PARAMETERS")
	a.Printf("%s\n", strings.Repeat("-", 118))
	for _, m := range matches {
		a.Printf("%-9s  %-24s  %-18s  %-21s  %-24s  %s\n", m.System, m.Key, m.Target, m.Action, m.Expires, m.Parameters)
	}
}

// printMatchesInteractive prints the shorter interactive match table.
func printMatchesInteractive(a *App, ip string, matches []ruleMatch) {
	if len(matches) == 0 {
		a.Printf("No active rules impact IP %s.\n", ip)
		return
	}
	a.Printf("Active rules impacting %s\n\n", ip)
	a.Printf("  Select rule and press ENTER to remove it\n")
	a.Printf("  %-15s  %-19s  %-17s  %-20s\n", "RULE", "TYPE", "PARAMETERS", "EXPIRATION")
	a.Printf("  %s\n", hr(78))
	for _, m := range matches {
		a.Printf("  %-15s  %-19s  %-17s  %-20s\n", truncateDisplay(m.Target, 15), truncateDisplay(m.Action, 19), truncateDisplay(m.Parameters, 17), truncateDisplay(m.Expires, 20))
	}
}

// selectNoMatchesAction lets the operator check another IP or return when no
// rules match the current IP.
func selectNoMatchesAction(ip string) (bool, error) {
	choice, err := choiceMenu("[proxyble] Rules -> Check IP", fmt.Sprintf("There are no rules currently impacting IP %s.", ip), [][2]string{
		{"again", "Check another IP Address"},
		{"back", "Return to Rules menu"},
	}, "")
	if err != nil {
		return false, err
	}
	return choice == "again", nil
}

// selectMatchingRuleInteractive renders the selectable Check IP match table and
// returns either a selected rule, a request to check another IP, or back.
func selectMatchingRuleInteractive(ip string, matches []ruleMatch) (ruleMatch, string, error) {
	if !supportsArrowMenu() {
		return selectMatchingRuleNumbered(ip, matches)
	}
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		return selectMatchingRuleNumbered(ip, matches)
	}
	defer restore()
	fmt.Fprint(os.Stderr, "\033[?25l")
	defer fmt.Fprint(os.Stderr, "\033[?25h")

	selected := 0
	checkAnotherIndex := len(matches)
	returnIndex := len(matches) + 1
	for {
		renderCheckIPMatchPage(ip, matches, selected)
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			return ruleMatch{}, "", err
		}
		switch key {
		case "up":
			if selected > 0 {
				selected--
			}
		case "down":
			if selected < returnIndex {
				selected++
			}
		case "enter":
			clearScreen()
			if selected == checkAnotherIndex {
				return ruleMatch{}, "again", nil
			}
			if selected == returnIndex {
				return ruleMatch{}, "back", nil
			}
			return matches[selected], "remove", nil
		case "interrupt":
			handleInterruptRequest()
		case "q", "escape":
			clearScreen()
			return ruleMatch{}, "back", nil
		default:
			if n, ok := numericMenuChoice(key, len(matches)+2); ok {
				clearScreen()
				if n == checkAnotherIndex {
					return ruleMatch{}, "again", nil
				}
				if n == returnIndex {
					return ruleMatch{}, "back", nil
				}
				return matches[n], "remove", nil
			}
		}
	}
}

// selectMatchingRuleNumbered is the portable fallback for Check IP match
// selection when raw arrow-key input is unavailable.
func selectMatchingRuleNumbered(ip string, matches []ruleMatch) (ruleMatch, string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		renderCheckIPMatchPage(ip, matches, -1)
		fmt.Fprint(os.Stderr, "\nSelect option: ")
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return ruleMatch{}, "", err
		}
		choice := strings.TrimSpace(line)
		if choice == "" {
			return ruleMatch{}, "back", nil
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(matches)+2 {
			fmt.Fprintf(os.Stderr, "[ERROR] Unknown selection: %s\n", choice)
			pauseAnyKey()
			continue
		}
		index := n - 1
		if index == len(matches) {
			return ruleMatch{}, "again", nil
		}
		if index == len(matches)+1 {
			return ruleMatch{}, "back", nil
		}
		return matches[index], "remove", nil
	}
}

// confirmCheckedRuleRemoval asks for removal confirmation with the Rules page
// frame intact so the operator keeps context after selecting a Check IP match.
func confirmCheckedRuleRemoval(match ruleMatch, a *App) (bool, error) {
	assumeYes := false
	if a != nil {
		assumeYes = a.AssumeYes
	}
	if assumeYes {
		return true, nil
	}
	prompt := checkedRuleRemovalPrompt(match)
	if a != nil && a.CommandLine {
		return commandLineConfirm(prompt, false)
	}
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("confirmation required; re-run with --yes for non-interactive execution")
	}
	if supportsArrowMenu() {
		ok, err := arrowCheckedRuleRemovalConfirm(prompt)
		if err == nil {
			return ok, nil
		}
		if !errors.Is(err, errArrowMenuUnavailable) {
			return false, err
		}
	}
	return numberedCheckedRuleRemovalConfirm(prompt)
}

func checkedRuleRemovalPrompt(match ruleMatch) string {
	target := firstNonEmpty(match.Target, match.Key)
	return fmt.Sprintf("Remove %s enforcement rule for source %s?", match.Action, target)
}

func arrowCheckedRuleRemovalConfirm(prompt string) (bool, error) {
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		return false, errArrowMenuUnavailable
	}
	defer restore()
	fmt.Fprint(os.Stderr, "\033[?25l")
	defer fmt.Fprint(os.Stderr, "\033[?25h")

	selected := 0
	for {
		renderCheckedRuleRemovalConfirm(prompt, selected)
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false, errArrowMenuUnavailable
			}
			return false, err
		}
		switch key {
		case "up", "down":
			if selected == 0 {
				selected = 1
			} else {
				selected = 0
			}
		case "enter":
			clearScreen()
			return selected == 0, nil
		case "interrupt":
			handleInterruptRequest()
		case "escape", "q":
			clearScreen()
			return false, nil
		default:
			if n, ok := numericMenuChoice(key, 2); ok {
				clearScreen()
				return n == 0, nil
			}
		}
	}
}

func numberedCheckedRuleRemovalConfirm(prompt string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		renderCheckedRuleRemovalConfirm(prompt, -1)
		fmt.Fprint(os.Stderr, "\nSelect option: ")
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "1", "yes", "y":
			clearScreen()
			return true, nil
		case "", "2", "no", "n", "q", "quit", "cancel":
			clearScreen()
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "[NOTICE] Select 1 or 2.")
			pauseAnyKey()
		}
	}
}

func renderCheckedRuleRemovalConfirm(prompt string, selected int) {
	clearScreen()
	banner(os.Stderr, "/var/log/proxyble/")
	pageHeader(os.Stderr, "[proxyble] Rules", prompt)
	options := []string{"Yes", "No"}
	for i, option := range options {
		if selected < 0 {
			fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, option)
			continue
		}
		marker := " "
		if i == selected {
			marker = ">"
		}
		row := fmt.Sprintf("  %s %s", marker, option)
		if i == selected {
			padding := 76 - displayWidth(row)
			if padding < 0 {
				padding = 0
			}
			fmt.Fprintf(os.Stderr, "%s%s%s%s\n", colorHighlight, row, strings.Repeat(" ", padding), colorReset)
			continue
		}
		fmt.Fprintln(os.Stderr, row)
	}
	if selected >= 0 {
		fmt.Fprintf(os.Stderr, "\n%sUse Up/Down and Enter. Press q to cancel.%s", colorDim, colorReset)
	}
}

// renderCheckIPMatchPage draws the Check IP selection table with one highlighted
// row when selected is non-negative.
func renderCheckIPMatchPage(ip string, matches []ruleMatch, selected int) {
	clearScreen()
	banner(os.Stderr, "/var/log/proxyble/")
	pageHeader(os.Stderr, "[proxyble] Rules -> Check IP", "Active rules impacting "+ip+".")
	fmt.Fprintf(os.Stderr, "%s  Select rule and press ENTER to remove it%s\n\n", colorBlueMedium, colorReset)
	fmt.Fprintf(os.Stderr, "  %-*s  %-*s  %-*s  %-*s\n", checkIPRuleWidth, "RULE", checkIPTypeWidth, "TYPE", checkIPParametersWidth, "PARAMETERS", checkIPExpirationWidth, "EXPIRATION")
	fmt.Fprintf(os.Stderr, "  %s\n", hr(checkIPTableWidth))
	for i, match := range matches {
		printCheckIPTableRow(i == selected, match.Target, match.Action, match.Parameters, match.Expires)
	}
	fmt.Fprintf(os.Stderr, "  %s\n", hr(checkIPTableWidth))
	printCheckIPTableRow(selected == len(matches), "", "Check another IP", "", "")
	printCheckIPTableRow(selected == len(matches)+1, "", "Return to Menu", "", "")
	fmt.Fprintf(os.Stderr, "\n%sUse Up/Down arrows, Enter to select.%s", colorDim, colorReset)
}

// printCheckIPTableRow prints one fixed-width row in the selectable Check IP
// table.
func printCheckIPTableRow(selected bool, target, action, parameters, expires string) {
	row := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s",
		checkIPRuleWidth, truncateDisplay(target, checkIPRuleWidth),
		checkIPTypeWidth, truncateDisplay(action, checkIPTypeWidth),
		checkIPParametersWidth, truncateDisplay(parameters, checkIPParametersWidth),
		checkIPExpirationWidth, truncateDisplay(expires, checkIPExpirationWidth),
	)
	if selected {
		padding := checkIPTableWidth + 2 - displayWidth(row)
		if padding < 0 {
			padding = 0
		}
		fmt.Fprintf(os.Stderr, "%s%s%s%s\n", colorBlueDark+colorReverse, row, strings.Repeat(" ", padding), colorReset)
		return
	}
	fmt.Fprintln(os.Stderr, row)
}

// truncateDisplay shortens table cells without changing the underlying value.
func truncateDisplay(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	return value[:width-3] + "..."
}

// selectMatch applies removal selectors and requires a single unambiguous match.
func selectMatch(opts map[string]string, matches []ruleMatch) (ruleMatch, error) {
	if len(matches) == 0 {
		return ruleMatch{}, fmt.Errorf("no active rules impact IP %s", opts["ip"])
	}
	if len(matches) > 1 && opts["key"] == "" && opts["system"] == "" && opts["rule"] == "" && opts["target"] == "" {
		return ruleMatch{}, fmt.Errorf("--remove matched multiple rules; add --system, --key, --rule, or --target")
	}
	filtered := []ruleMatch{}
	for _, m := range matches {
		if opts["system"] != "" && m.System != opts["system"] {
			continue
		}
		if opts["key"] != "" && m.Key != opts["key"] {
			continue
		}
		if opts["rule"] != "" && m.Action != opts["rule"] {
			continue
		}
		if opts["target"] != "" && m.Target != opts["target"] {
			continue
		}
		filtered = append(filtered, m)
	}
	if len(filtered) == 1 {
		return filtered[0], nil
	}
	if len(filtered) == 0 {
		return ruleMatch{}, fmt.Errorf("no matching rule was found for the removal selector")
	}
	return ruleMatch{}, fmt.Errorf("removal selector matched %d rules; add --system, --key, --rule, or --target", len(filtered))
}

// removeRuleFromState deletes one selected rule and inserts an expired sentinel
// policy so the rule agent reconciles enforcement state.
func removeRuleFromState(selected ruleMatch) (int, error) {
	state, err := loadRuleState(selected.Path)
	if err != nil {
		return 0, err
	}
	if _, ok := state.Rules[selected.Key]; !ok {
		return 0, nil
	}
	delete(state.Rules, selected.Key)
	ip, sentinel := sentinelPolicy(selected.System, state.Rules)
	state.Rules[ip] = sentinel
	if err := saveRuleState(selected.Path, state); err != nil {
		return 0, err
	}
	return 1, nil
}

// resetRules removes all active rules or all active rules of one type from both
// state files.
func resetRules(ctx context.Context, a *App, args []string) error {
	ruleType := ""
	cliMode := a.CommandLine || len(args) > 0
	assumeYes := a.AssumeYes
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--type" || arg == "--rule-type" || arg == "--rule-set":
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", arg)
			}
			i++
			ruleType = strings.ToUpper(args[i])
		case strings.HasPrefix(arg, "--type=") || strings.HasPrefix(arg, "--rule-type=") || strings.HasPrefix(arg, "--rule-set="):
			ruleType = strings.ToUpper(strings.SplitN(arg, "=", 2)[1])
		case arg == "--yes" || arg == "-y":
			assumeYes = true
		default:
			return fmt.Errorf("unknown option for --rules-reset: %s", arg)
		}
	}
	if a.CommandLine && ruleType == "" {
		return fmt.Errorf("--rules-reset requires --type ALL|RULE_TYPE")
	}
	paths := getRulePaths(a.Config)
	counts, total, err := countRules(paths)
	if err != nil {
		return err
	}
	if total == 0 {
		a.Printf("[NOTICE] No active Proxyble rules were found.\n")
		return nil
	}
	selectedCount := total
	if ruleType == "" {
		if assumeYes {
			ruleType = "ALL"
		} else {
			selected, count, err := selectResetRuleSet(counts, total)
			if err != nil {
				return err
			}
			if selected == "" {
				a.Printf("[NOTICE] Rule reset cancelled.\n")
				return errActionCancelled
			}
			ruleType = selected
			selectedCount = count
		}
	}
	if ruleType != "ALL" && !contains(knownActions, ruleType) {
		return fmt.Errorf("unknown rule type for reset: %s", ruleType)
	}
	if ruleType != "ALL" {
		selectedCount = counts[ruleType]
	}
	if selectedCount == 0 {
		a.Printf("[NOTICE] No active %s rules were found.\n", ruleType)
		return nil
	}
	targetLabel := "all active Proxyble rules"
	if ruleType != "ALL" {
		targetLabel = "all " + ruleType + " rules"
	}
	if cliMode && !assumeYes && !isTerminal(os.Stdin) {
		return fmt.Errorf("rule reset confirmation required; re-run with --yes for non-interactive execution")
	}
	var ok bool
	if a.CommandLine {
		ok, err = commandLineConfirm(fmt.Sprintf("Reset %s?", targetLabel), assumeYes)
	} else {
		ok, err = confirmRuleResetKeyword(targetLabel, assumeYes)
	}
	if err != nil || !ok {
		if err != nil {
			return err
		}
		a.Printf("[NOTICE] Rule reset cancelled.\n")
		return errActionCancelled
	}
	cleanup, lock, err := quiesceRuleAgent(ctx, a)
	if err != nil {
		return err
	}
	removedNFT, removedHA, err := rewriteRuleStateForReset(paths, ruleType)
	unlockFile(lock)
	if err != nil {
		cleanup()
		return err
	}
	if err := triggerRuleAgent(ctx, a, paths); err != nil {
		cleanup()
		return err
	}
	cleanup()
	removedTotal := removedNFT + removedHA
	writeRuleAudit(paths.LogDir, "ACTION=RESET_RULES TYPE=%s COUNT=%d NFTABLES=%d HAPROXY=%d MSG=\"Selected rules reset through proxyble-rule-agent state reconciliation.\"", ruleType, removedTotal, removedNFT, removedHA)
	if shouldFrameRuleResetCompletion(cliMode, assumeYes) {
		actionPage("[proxyble] Rules -> Reset", "Rule reset complete.")
	}
	a.Printf(" RULE RESET COMPLETE\n\n")
	a.Printf(" Rule set            : %s\n", ruleType)
	a.Printf(" Rules removed count : %d\n", removedTotal)
	a.Printf(" Audit log           : %s\n", paths.CurrentLog)
	return nil
}

func shouldFrameRuleResetCompletion(cliMode, assumeYes bool) bool {
	return !cliMode && !assumeYes
}

// confirmRuleResetKeyword keeps the Rules -> Reset breadcrumb visible while
// still requiring the exact destructive-action keyword.
func confirmRuleResetKeyword(targetLabel string, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("confirmation required; re-run with --yes for non-interactive execution")
	}
	reader := bufio.NewReader(os.Stdin)
	renderRuleResetKeywordConfirm(targetLabel)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return false, err
	}
	clearScreen()
	return strings.TrimSpace(line) == "RESET", nil
}

func resetConfirmationPrompt(targetLabel string) string {
	return fmt.Sprintf("This action is destructive.\nType RESET to confirm that %s should be reset.", targetLabel)
}

func renderRuleResetKeywordConfirm(targetLabel string) {
	clearScreen()
	banner(os.Stderr, "/var/log/proxyble/")
	pageHeader(os.Stderr, "[proxyble] Rules -> Reset", resetConfirmationPrompt(targetLabel))
	fmt.Fprint(os.Stderr, "Type RESET: ")
}

// selectResetRuleSet shows the interactive Rules -> Reset category menu with
// active counts, an ALL option, and a cancellation option.
func selectResetRuleSet(counts map[string]int, total int) (string, int, error) {
	items := resetRuleMenuItems(counts, total)
	choice, err := choiceMenu("[proxyble] Rules -> Reset", "Rules can be reset (completely cleared).\nYou can reset ALL rules, or just a set of rules of the same type.\n\nSelect a set of rules to be reset:", items, "")
	if err != nil {
		return "", 0, err
	}
	switch choice {
	case "", "cancel", "back", "exit":
		return "", 0, nil
	case "ALL":
		return "ALL", total, nil
	default:
		if _, ok := counts[choice]; ok {
			return choice, counts[choice], nil
		}
		return "", 0, fmt.Errorf("unknown selection: %s", choice)
	}
}

// resetRuleMenuItems builds the reset category menu in the same logical order as
// the legacy bash wizard, with ALL and cancel at the bottom.
func resetRuleMenuItems(counts map[string]int, total int) [][2]string {
	items := make([][2]string, 0, len(knownActions)+2)
	for _, action := range knownActions {
		items = append(items, [2]string{action, fmt.Sprintf("%8d", counts[action])})
	}
	items = append(items,
		[2]string{"ALL", fmt.Sprintf("%8d", total)},
		[2]string{"cancel", "Return to Rules menu"},
	)
	return items
}

// countRules counts active rules by action across both rule-agent state files.
func countRules(paths rulePaths) (map[string]int, int, error) {
	counts := map[string]int{}
	for _, action := range knownActions {
		counts[action] = 0
	}
	total := 0
	for _, path := range []string{paths.NFTState, paths.HAProxyState} {
		state, err := loadRuleState(path)
		if err != nil {
			return counts, total, err
		}
		for _, policy := range state.Rules {
			if !policyActive(policy) {
				continue
			}
			action := strings.ToUpper(valueString(policy["action"]))
			if action != "" {
				counts[action]++
				total++
			}
		}
	}
	return counts, total, nil
}

// rewriteRuleStateForReset rewrites nftables and HAProxy state for one reset
// selection.
func rewriteRuleStateForReset(paths rulePaths, selection string) (int, int, error) {
	removedNFT, err := rewriteOneState(paths.NFTState, "NFTABLES", selection)
	if err != nil {
		return 0, 0, err
	}
	removedHA, err := rewriteOneState(paths.HAProxyState, "HAPROXY", selection)
	return removedNFT, removedHA, err
}

// rewriteOneState removes selected active policies from one state file and adds
// an expired sentinel when anything changed.
func rewriteOneState(path, system, selection string) (int, error) {
	state, err := loadRuleState(path)
	if err != nil {
		return 0, err
	}
	removed := 0
	kept := map[string]map[string]any{}
	for key, policy := range state.Rules {
		remove := selection == "ALL" || strings.ToUpper(valueString(policy["action"])) == selection
		if remove {
			removed++
		} else {
			kept[key] = policy
		}
	}
	if removed > 0 {
		ip, sentinel := sentinelPolicy(system, kept)
		kept[ip] = sentinel
	}
	state.Rules = kept
	return removed, saveRuleState(path, state)
}

// sentinelPolicy creates an expired harmless policy that prompts the rule agent
// to reconcile state after manual state edits.
func sentinelPolicy(system string, rules map[string]map[string]any) (string, map[string]any) {
	used := map[string]bool{}
	for _, policy := range rules {
		if ip := valueString(policy["ip"]); ip != "" {
			used[ip] = true
		}
	}
	for _, prefix := range []string{"127.255.255", "198.51.100", "203.0.113", "192.0.2"} {
		for host := 254; host >= 1; host-- {
			candidate := fmt.Sprintf("%s.%d/32", prefix, host)
			if !used[candidate] {
				action := "DROP"
				if system == "HAPROXY" {
					action = "LIMIT_RATE_SLOW"
				}
				return candidate, map[string]any{
					"ip":         candidate,
					"action":     action,
					"parameter":  "",
					"duration":   "1s",
					"system":     system,
					"expires_at": "2000-01-01T00:00:00Z",
				}
			}
		}
	}
	return "127.255.255.254/32", map[string]any{"ip": "127.255.255.254/32", "action": "DROP", "expires_at": "2000-01-01T00:00:00Z", "system": system}
}

// quiesceRuleAgent stops path/timer triggers and takes the rule-agent lock while
// state files are being rewritten.
func quiesceRuleAgent(ctx context.Context, a *App) (func(), *os.File, error) {
	pathActive := systemctlQuiet(ctx, "is-active", "--quiet", "proxyble-rule-agent.path")
	timerActive := systemctlQuiet(ctx, "is-active", "--quiet", "proxyble-rule-agent.timer")
	_ = systemctl(ctx, stepOutput(a), "stop", "proxyble-rule-agent.path")
	_ = systemctl(ctx, stepOutput(a), "stop", "proxyble-rule-agent.timer")
	_ = timeoutCommand(ctx, stepOutput(a), 10, "systemctl", "stop", "proxyble-rule-agent.service")
	lock, err := lockFile(defaultRuleAgentLockFile)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		if pathActive {
			_ = systemctl(ctx, stepOutput(a), "start", "proxyble-rule-agent.path")
		}
		if timerActive {
			_ = systemctl(ctx, stepOutput(a), "start", "proxyble-rule-agent.timer")
		}
	}
	return cleanup, lock, nil
}

// triggerRuleAgent runs the rule agent through systemd when available or by
// direct binary fallback.
func triggerRuleAgent(ctx context.Context, a *App, paths rulePaths) error {
	if systemctlQuiet(ctx, "cat", "proxyble-rule-agent.service") {
		err := systemctl(ctx, stepOutput(a), "start", "proxyble-rule-agent.service")
		if err == nil {
			return nil
		}
		fmt.Fprintf(stepOutput(a), "[NOTICE] proxyble-rule-agent.service start failed; trying direct rule-agent fallback: %v\n", err)
		if fallbackErr := runRuleAgentDirect(ctx, a, paths); fallbackErr != nil {
			return fmt.Errorf("proxyble-rule-agent.service start failed: %v; direct fallback failed: %w", err, fallbackErr)
		}
		return nil
	}
	return runRuleAgentDirect(ctx, a, paths)
}

func runRuleAgentDirect(ctx context.Context, a *App, paths rulePaths) error {
	if st, err := os.Stat(paths.RuleAgentBin); err == nil && st.Mode()&0o111 != 0 {
		return runCommand(ctx, stepOutput(a), paths.RuleAgentBin, paths.RuleAgentMode)
	}
	return fmt.Errorf("proxyble-rule-agent.service is missing and binary is not executable: %s", paths.RuleAgentBin)
}

// writeRuleAudit appends one manual rule-management audit event to the
// rule-agent log directory.
func writeRuleAudit(logDir, format string, args ...any) {
	_ = mkdirAllNoSymlink(logDir, 0o700)
	path := filepath.Join(logDir, time.Now().Format("2006-01-02")+".log")
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s ", logTimestamp())
	fmt.Fprintf(f, format, args...)
	fmt.Fprintln(f)
}

// contains reports whether needle appears in values.
func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
