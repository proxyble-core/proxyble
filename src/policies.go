// Proxyble protects APIs, web applications, and TCP services.
// Copyright (C) 2026 Lucio D'Orazio Pedro de Matos
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package main

// policies.go implements the Proxyble managed policy surfaces. Managed
// policies are SQL templates under templates/RioSQL/policies; deployment copies
// the selected policy plus declared dependencies into RioDB's sql directory.
// The installed SQL directory is the source of truth for deployed policy state.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// mandatoryRuleQueueSQLFile is required for any RioDB-enabled Proxyble host:
// policy queries output into rule_queue and this stream writes those lines to
// the proxyble-rule-agent inbox file.
const mandatoryRuleQueueSQLFile = "00-stream-rule-queue.sql"

// policyDefinition is the parsed metadata and dependency list for one managed
// RioSQL policy template under templates/RioSQL/policies.
type policyDefinition struct {
	ID               string
	Name             string
	Summary          string
	Threat           string
	DetectionSignals string
	MetricsLayer     string
	Visibility       []string
	FileName         string
	Path             string
	Dependencies     []string
}

// policySQLDir returns the installed RioDB SQL directory used for Proxyble
// policy files.
func policySQLDir(c *Config) string {
	return filepath.Join(riodbHome(c), "sql")
}

// policyTemplateRoot returns the bundled RioSQL template root for the current
// source or installed application tree.
func policyTemplateRoot(a *App) string {
	root := "."
	if a != nil && a.SourceRoot != "" {
		root = a.SourceRoot
	}
	return filepath.Join(root, "templates", "RioSQL")
}

// policyTemplateDir returns the subdirectory containing deployable managed
// policy templates, distinct from shared stream/window templates.
func policyTemplateDir(a *App) string {
	return filepath.Join(policyTemplateRoot(a), "policies")
}

// isPolicySQL excludes Proxyble bootstrap SQL and keeps only operator policy
// files.
func isPolicySQL(path string) bool {
	name := filepath.Base(path)
	switch name {
	case mandatoryRuleQueueSQLFile, "10-rule-queue.sql", "20-tcp-log-input.sql", "20-http-log-input.sql":
		return false
	default:
		return strings.HasSuffix(name, ".sql")
	}
}

// loadPolicyFiles returns installed policy SQL files in the RioDB SQL directory.
func loadPolicyFiles(c *Config) ([]string, error) {
	dir := policySQLDir(c)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if isPolicySQL(path) {
			files = append(files, path)
		}
	}
	return files, nil
}

// loadPolicyCatalog parses every managed policy template and returns a stable
// display order for wizard and CLI selectors.
func loadPolicyCatalog(a *App) ([]policyDefinition, error) {
	dir := policyTemplateDir(a)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var policies []policyDefinition
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		policy, err := parsePolicyTemplate(path)
		if err != nil {
			return nil, err
		}
		policy.FileName = entry.Name()
		policy.Path = path
		if policy.ID == "" {
			policy.ID = strings.TrimSuffix(entry.Name(), ".sql")
		}
		if policy.Name == "" {
			policy.Name = strings.TrimSuffix(entry.Name(), ".sql")
		}
		policies = append(policies, policy)
	}
	sort.Slice(policies, func(i, j int) bool {
		return strings.ToLower(policies[i].Name) < strings.ToLower(policies[j].Name)
	})
	return policies, nil
}

// parsePolicyTemplate reads the comment header from one policy SQL template and
// extracts catalog metadata plus first-level dependencies.
func parsePolicyTemplate(path string) (policyDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policyDefinition{}, err
	}
	var policy policyDefinition
	inDependencies := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if text == "" {
			continue
		}
		if inDependencies {
			if dep, ok := strings.CutPrefix(text, "- "); ok {
				dep = strings.TrimSpace(dep)
				if dep != "" {
					policy.Dependencies = append(policy.Dependencies, dep)
				}
				continue
			}
			inDependencies = false
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "policy":
			policy.Name = value
		case "policy id":
			policy.ID = value
		case "summary", "description":
			policy.Summary = value
		case "threat":
			policy.Threat = value
		case "detection signals":
			policy.DetectionSignals = value
		case "metrics layer", "metric layer":
			policy.MetricsLayer = value
		case "visibility":
			policy.Visibility = parsePolicyVisibility(value)
		case "dependencies":
			inDependencies = true
		}
	}
	if len(policy.Visibility) == 0 {
		policy.Visibility = []string{"tcp", "http", "https"}
	}
	return policy, nil
}

// parsePolicyVisibility normalizes the Visibility header into Proxyble traffic
// modes. It keeps legacy prose support so older templates remain deployable.
func parsePolicyVisibility(value string) []string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, ";", ",")
	normalized = strings.ReplaceAll(normalized, "|", ",")
	if strings.Contains(normalized, "http-visible only") {
		return []string{"http", "https"}
	}
	if strings.Contains(normalized, "tcp/l4 fallback") || strings.Contains(normalized, "tcp fallback") || strings.Contains(normalized, "l4 fallback") {
		return []string{"tcp", "http", "https"}
	}
	modes := map[string]bool{}
	for _, part := range strings.FieldsFunc(normalized, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '/'
	}) {
		switch strings.TrimSpace(part) {
		case "tcp":
			modes["tcp"] = true
		case "http":
			modes["http"] = true
		case "https":
			modes["https"] = true
		}
	}
	out := []string{}
	for _, mode := range []string{"tcp", "http", "https"} {
		if modes[mode] {
			out = append(out, mode)
		}
	}
	return out
}

// policyCompatibleWithMode reports whether a policy can run with the configured
// listener mode; HTTPS maps to HTTP-visible policy semantics at the template
// layer because HAProxy terminates TLS before logging HTTP fields.
func policyCompatibleWithMode(policy policyDefinition, mode string) bool {
	mode, err := normalizeTrafficMode(mode)
	if err != nil {
		return false
	}
	for _, visible := range policy.Visibility {
		if visible == mode {
			return true
		}
	}
	return false
}

// deployedPolicyBasenames returns the installed SQL filenames currently present
// in RioDB's sql directory, which is the source of truth for deployed state.
func deployedPolicyBasenames(a *App) (map[string]bool, error) {
	files, err := loadPolicyFiles(a.Config)
	if err != nil {
		return nil, err
	}
	deployed := map[string]bool{}
	for _, file := range files {
		deployed[filepath.Base(file)] = true
	}
	return deployed, nil
}

// deployedManagedPolicies intersects the template catalog with installed SQL
// files so only Proxyble-managed policy templates appear in policy listings.
func deployedManagedPolicies(a *App) ([]policyDefinition, error) {
	catalog, err := loadPolicyCatalog(a)
	if err != nil {
		return nil, err
	}
	deployed, err := deployedPolicyBasenames(a)
	if err != nil {
		return nil, err
	}
	var policies []policyDefinition
	for _, policy := range catalog {
		if deployed[policy.FileName] {
			policies = append(policies, policy)
		}
	}
	return policies, nil
}

// deployablePolicies returns catalog policies that match the current traffic
// mode and whose policy file has not already been copied into RioDB.
func deployablePolicies(a *App) ([]policyDefinition, error) {
	mode, err := a.Config.TrafficMode()
	if err != nil {
		return nil, err
	}
	catalog, err := loadPolicyCatalog(a)
	if err != nil {
		return nil, err
	}
	deployed, err := deployedPolicyBasenames(a)
	if err != nil {
		return nil, err
	}
	var policies []policyDefinition
	for _, policy := range catalog {
		if deployed[policy.FileName] || !policyCompatibleWithMode(policy, mode) {
			continue
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// policyMenuItems converts policy definitions into two-column wizard rows and
// appends the common back row used by deploy/remove screens.
func policyMenuItems(policies []policyDefinition, emptyBackDescription string) [][2]string {
	items := make([][2]string, 0, len(policies)+1)
	for _, policy := range policies {
		items = append(items, [2]string{policy.ID + "|" + policy.Name, policy.Summary})
	}
	backDescription := "Return and do not deploy a new policy"
	if len(policies) == 0 && emptyBackDescription != "" {
		backDescription = emptyBackDescription
	}
	items = append(items, [2]string{"back", backDescription})
	return items
}

// selectPolicyByID finds the policy chosen by the menu dispatch value. The
// function also accepts filenames and display names for CLI-style reuse.
func selectPolicyByID(policies []policyDefinition, id string) (policyDefinition, bool) {
	for _, policy := range policies {
		if policy.ID == id || policy.FileName == id || policy.Name == id {
			return policy, true
		}
	}
	return policyDefinition{}, false
}

// resolveCatalogPolicy maps a CLI selector to either a deployable or already
// deployed managed policy, depending on the action being performed.
func resolveCatalogPolicy(a *App, selector string, requireDeployable bool) (policyDefinition, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return policyDefinition{}, fmt.Errorf("--policy is required")
	}
	var policies []policyDefinition
	var err error
	if requireDeployable {
		policies, err = deployablePolicies(a)
	} else {
		policies, err = deployedManagedPolicies(a)
	}
	if err != nil {
		return policyDefinition{}, err
	}
	lowerSelector := strings.ToLower(selector)
	var matches []policyDefinition
	for _, policy := range policies {
		candidates := []string{policy.ID, policy.Name, policy.FileName, strings.TrimSuffix(policy.FileName, ".sql")}
		for _, candidate := range candidates {
			if strings.ToLower(candidate) == lowerSelector {
				matches = append(matches, policy)
				break
			}
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return policyDefinition{}, fmt.Errorf("policy selector is ambiguous: %s", selector)
	}
	if requireDeployable {
		return policyDefinition{}, fmt.Errorf("deployable policy not found: %s", selector)
	}
	return policyDefinition{}, fmt.Errorf("deployed policy not found: %s", selector)
}

// policyFileCopyList builds the dependency-ordered list of SQL template files
// needed for a policy. It walks policy -> window -> stream dependencies so
// RioDB loads streams before windows and windows before the policy queries.
func policyFileCopyList(root string, policy policyDefinition) ([]string, error) {
	seen := map[string]bool{}
	var files []string
	var add func(string) error
	add = func(rel string) error {
		rel = cleanPolicyDependency(rel)
		if rel == "" || seen[rel] {
			return nil
		}
		path, err := safePolicyTemplatePath(root, rel)
		if err != nil {
			return err
		}
		deps, err := parseTemplateDependencies(path)
		if err != nil {
			return err
		}
		for _, dep := range deps {
			if err := add(dep); err != nil {
				return err
			}
		}
		seen[rel] = true
		files = append(files, rel)
		return nil
	}
	if err := add(mandatoryRuleQueueSQLFile); err != nil {
		return nil, err
	}
	for _, dep := range policy.Dependencies {
		if err := add(dep); err != nil {
			return nil, err
		}
	}
	if err := add(filepath.Join("policies", policy.FileName)); err != nil {
		return nil, err
	}
	return files, nil
}

// parseTemplateDependencies extracts dependency filenames from any RioSQL
// template header. It supports both inline and block forms used in this tree.
func parseTemplateDependencies(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var deps []string
	inDependencies := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if text == "" {
			continue
		}
		if inDependencies {
			if dep, ok := strings.CutPrefix(text, "- "); ok {
				if dep = cleanPolicyDependency(dep); dep != "" {
					deps = append(deps, dep)
				}
				continue
			}
			inDependencies = false
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Dependencies") {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			inDependencies = true
			continue
		}
		for _, dep := range strings.Split(value, ",") {
			if dep = cleanPolicyDependency(dep); dep != "" {
				deps = append(deps, dep)
			}
		}
	}
	return deps, nil
}

// cleanPolicyDependency normalizes one dependency token from a comment line into
// a slash-separated relative path suitable for cycle/de-duplication checks.
func cleanPolicyDependency(dep string) string {
	dep = strings.TrimSpace(strings.TrimPrefix(dep, "- "))
	if dep == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(dep))
}

// safePolicyTemplatePath joins a dependency with the template root after
// rejecting absolute paths and attempts to escape the bundled template tree.
func safePolicyTemplatePath(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("policy dependency must be relative: %s", rel)
	}
	clean := filepath.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || clean == ".." {
		return "", fmt.Errorf("policy dependency escapes template root: %s", rel)
	}
	return filepath.Join(root, clean), nil
}

// copyPolicyFiles copies all SQL files required by a policy into RioDB's flat
// sql directory, preserving dependency order and RioDB ownership/permissions.
func copyPolicyFiles(a *App, policy policyDefinition) error {
	sqlDir := policySQLDir(a.Config)
	if err := mkdirAllNoSymlink(sqlDir, 0o700); err != nil {
		return err
	}
	_ = chownPath(sqlDir, riodbUser(a.Config), riodbGroup(a.Config))
	root := policyTemplateRoot(a)
	files, err := policyFileCopyList(root, policy)
	if err != nil {
		return err
	}
	for _, rel := range files {
		src, err := safePolicyTemplatePath(root, rel)
		if err != nil {
			return err
		}
		dst := filepath.Join(sqlDir, filepath.Base(rel))
		if err := copyFile(src, dst, 0o600); err != nil {
			return fmt.Errorf("copy %s: %w", filepath.Base(rel), err)
		}
		_ = chownPath(dst, riodbUser(a.Config), riodbGroup(a.Config))
		if a.LogFile != nil {
			fmt.Fprintf(a.LogFile, "%s ACTION=POLICY_FILE_COPIED POLICY=%s SRC=%s DST=%s\n", logTimestamp(), policy.ID, src, dst)
		}
	}
	return nil
}

// maybeRestartRioDB handles the post-change restart decision. CLI actions only
// restart when explicitly requested; wizard actions ask the operator.
func maybeRestartRioDB(ctx context.Context, a *App, prompt string, requested bool) error {
	if a != nil && a.CommandLine && !requested {
		a.Printf("[NOTICE] RioDB restart skipped. Policy changes take effect after RioDB is restarted.\n")
		return nil
	}
	if !requested {
		ok, err := appConfirm(a, prompt)
		if err != nil || !ok {
			if err != nil {
				return err
			}
			a.Printf("[NOTICE] RioDB restart skipped. Policy changes take effect after RioDB is restarted.\n")
			return nil
		}
	}
	unit := riodbServiceName(a.Config)
	if err := timeoutCommand(ctx, stepOutput(a), 20, "systemctl", "restart", unit); err != nil {
		return fmt.Errorf("failed to restart %s: %w", unit, err)
	}
	a.Printf("[OK] RioDB restarted. Policy changes are now loading.\n")
	return nil
}

// deployPolicy performs the filesystem mutation for a managed policy after the
// caller has already validated selection and gathered any interactive approval.
func deployPolicy(ctx context.Context, a *App, policy policyDefinition, restart bool) error {
	if err := copyPolicyFiles(a, policy); err != nil {
		return err
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, "%s ACTION=POLICY_DEPLOYED POLICY=%s FILE=%s\n", logTimestamp(), policy.ID, policy.FileName)
	}
	a.Printf("[OK] Deployed policy: %s\n", policy.Name)
	a.Printf("[NOTICE] The change will be effective after restarting the RioDB service.\n")
	return maybeRestartRioDB(ctx, a, "Restart RioDB service now?", restart)
}

// removePolicy deletes one deployed managed policy and then prunes only
// dependency files that no remaining deployed policy still references.
func removePolicy(ctx context.Context, a *App, policy policyDefinition, restart bool) error {
	path := filepath.Join(policySQLDir(a.Config), policy.FileName)
	if err := rejectSymlinkIfExists(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("deployed policy file was already removed: %s", policy.FileName)
		}
		return err
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, "%s ACTION=POLICY_REMOVED POLICY=%s FILE=%s\n", logTimestamp(), policy.ID, policy.FileName)
	}
	removedDeps, err := cleanupUnusedPolicyDependencies(a, policy)
	if err != nil {
		return err
	}
	a.Printf("[OK] Removed policy: %s\n", policy.Name)
	for _, dep := range removedDeps {
		a.Printf("[OK] Removed unused policy dependency: %s\n", filepath.Base(dep))
	}
	a.Printf("[NOTICE] The change will be effective after restarting the RioDB service.\n")
	return maybeRestartRioDB(ctx, a, "Restart RioDB service now?", restart)
}

// cleanupUnusedPolicyDependencies removes orphaned dependency files from the
// removed policy's dependency tree while preserving shared windows and streams.
func cleanupUnusedPolicyDependencies(a *App, removed policyDefinition) ([]string, error) {
	root := policyTemplateRoot(a)
	candidates, err := policyFileCopyList(root, removed)
	if err != nil {
		return nil, err
	}
	remaining, err := deployedManagedPolicies(a)
	if err != nil {
		return nil, err
	}
	required, err := requiredPolicyFileBasenames(root, remaining)
	if err != nil {
		return nil, err
	}
	var removedFiles []string
	sqlDir := policySQLDir(a.Config)
	removedPolicyRel := filepath.ToSlash(filepath.Join("policies", removed.FileName))
	for i := len(candidates) - 1; i >= 0; i-- {
		rel := candidates[i]
		if rel == removedPolicyRel || rel == mandatoryRuleQueueSQLFile {
			continue
		}
		name := filepath.Base(rel)
		if required[name] {
			continue
		}
		path := filepath.Join(sqlDir, name)
		if err := rejectSymlinkIfExists(path); err != nil {
			return removedFiles, err
		}
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removedFiles, err
		}
		removedFiles = append(removedFiles, path)
		if a.LogFile != nil {
			fmt.Fprintf(a.LogFile, "%s ACTION=POLICY_DEPENDENCY_REMOVED POLICY=%s FILE=%s\n", logTimestamp(), removed.ID, name)
		}
	}
	return removedFiles, nil
}

// requiredPolicyFileBasenames returns the flattened set of SQL basenames still
// required by all remaining deployed managed policies.
func requiredPolicyFileBasenames(root string, policies []policyDefinition) (map[string]bool, error) {
	required := map[string]bool{}
	for _, policy := range policies {
		files, err := policyFileCopyList(root, policy)
		if err != nil {
			return nil, err
		}
		for _, rel := range files {
			required[filepath.Base(rel)] = true
		}
	}
	return required, nil
}

// policyCommandOptions stores parsed flags common to policy deploy/remove/list
// CLI actions.
type policyCommandOptions struct {
	selector     string
	restartRioDB bool
}

// parsePolicyCommandOptions parses --policy and optional --restart-riodb flags
// for managed policy CLI actions.
func parsePolicyCommandOptions(args []string, allowRestart bool) (policyCommandOptions, error) {
	var opts policyCommandOptions
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
		case arg == "--policy":
			v, err := value()
			if err != nil {
				return opts, err
			}
			opts.selector = v
		case strings.HasPrefix(arg, "--policy="):
			v, _ := value()
			opts.selector = v
		case arg == "--restart-riodb":
			if !allowRestart {
				return opts, fmt.Errorf("unexpected flag for policy action: %s", arg)
			}
			opts.restartRioDB = true
		default:
			return opts, fmt.Errorf("unexpected flag for policy action: %s", arg)
		}
	}
	return opts, nil
}

// policiesDeployCLI resolves a deployable catalog policy and applies it from
// the non-interactive command path.
func policiesDeployCLI(ctx context.Context, a *App, args []string) error {
	opts, err := parsePolicyCommandOptions(args, true)
	if err != nil {
		return err
	}
	policy, err := resolveCatalogPolicy(a, opts.selector, true)
	if err != nil {
		return err
	}
	return deployPolicy(ctx, a, policy, opts.restartRioDB)
}

// policiesRemoveCLI resolves an installed managed policy, confirms removal, and
// then removes it from RioDB's sql directory.
func policiesRemoveCLI(ctx context.Context, a *App, args []string) error {
	opts, err := parsePolicyCommandOptions(args, true)
	if err != nil {
		return err
	}
	policy, err := resolveCatalogPolicy(a, opts.selector, false)
	if err != nil {
		return err
	}
	ok, err := appConfirm(a, fmt.Sprintf("Remove policy %s now?", policy.Name))
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return errActionCancelled
	}
	return removePolicy(ctx, a, policy, opts.restartRioDB)
}

// policiesList prints the deployed managed policy catalog view for CLI users.
func policiesList(a *App, args []string) error {
	if len(args) > 0 {
		opts, err := parsePolicyCommandOptions(args, false)
		if err != nil {
			return err
		}
		if opts.selector != "" && opts.selector != "all" {
			return fmt.Errorf("--policy is not used with --policies-list; use --policies-remove or --policies-edit for one policy")
		}
	}
	policies, err := deployedManagedPolicies(a)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		a.Printf("No Proxyble managed policies are currently deployed in %s.\n", policySQLDir(a.Config))
		return nil
	}
	printPolicySummaryTable(a, "Policy", "Description", policies)
	return nil
}

// printPolicySummaryTable renders a compact two-column policy table for CLI
// listing output.
func printPolicySummaryTable(a *App, leftHeader, rightHeader string, policies []policyDefinition) {
	width := 32
	for _, policy := range policies {
		if w := displayWidth(policy.Name); w > width {
			width = min(w, 44)
		}
	}
	a.Printf("%-*s  %s\n", width, leftHeader, rightHeader)
	a.Printf("%-*s  %s\n", width, strings.Repeat("-", width), strings.Repeat("-", 40))
	for _, policy := range policies {
		a.Printf("%-*s  %s\n", width, clipDisplay(policy.Name, width), policy.Summary)
	}
}

// deployPolicyInteractive runs the wizard deploy flow: choose a compatible
// undeployed policy, review details, confirm, copy files, and offer RioDB restart.
func deployPolicyInteractive(ctx context.Context, a *App) error {
	policies, err := deployablePolicies(a)
	if err != nil {
		return err
	}
	mode, _ := a.Config.TrafficMode()
	items := policyMenuItems(policies, "No compatible undeployed policies are available")
	choice, err := choiceMenu("[proxyble] Policies -> Deploy", fmt.Sprintf("Policy                         Summary\nChoose policies to manage protection automatically.\nCurrent mode: %s", mode), items, "")
	if err != nil {
		return err
	}
	if choice == "back" {
		return errActionCancelled
	}
	policy, ok := selectPolicyByID(policies, choice)
	if !ok {
		return fmt.Errorf("selected policy was not found: %s", choice)
	}
	ok, err = confirmPolicyDeployInteractive(policy)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return errActionCancelled
	}
	return deployPolicy(ctx, a, policy, false)
}

// confirmPolicyDeployInteractive displays the expanded policy metadata before
// the operator commits to copying SQL files into RioDB.
func confirmPolicyDeployInteractive(policy policyDefinition) (bool, error) {
	clearScreen()
	banner(os.Stderr, "/var/log/proxyble/")
	pageHeader(os.Stderr, "[proxyble] Policies -> Deploy", "Review policy details before deployment.")
	printPolicyDeployDetails(os.Stderr, policy)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, colorBlueLight+"Deploy this policy now?"+colorReset)
	fmt.Fprintln(os.Stderr)
	if supportsArrowMenu() {
		ok, err := arrowConfirm("Yes", "")
		if err == nil {
			return ok, nil
		}
		if !errors.Is(err, errArrowMenuUnavailable) {
			return false, err
		}
	}
	return numberedConfirm("Yes", "")
}

// printPolicyDeployDetails writes the two-column detail block shown on the
// deploy confirmation page.
func printPolicyDeployDetails(w io.Writer, policy policyDefinition) {
	const labelWidth = 24
	bodyWidth := menuBodyWidth()
	valueWidth := bodyWidth - labelWidth - 7
	if valueWidth < 30 {
		valueWidth = 30
	}
	rows := [][2]string{
		{"Policy Name:", policy.Name},
		{"Policy Description:", policy.Summary},
		{"Threat:", policy.Threat},
		{"Detection Signals:", policy.DetectionSignals},
		{"Metrics Layer:", policy.MetricsLayer},
		{"Template file location:", policy.Path},
	}
	for _, row := range rows {
		value := strings.TrimSpace(row[1])
		if value == "" {
			value = "Not specified"
		}
		lines := wrapConfirmText(value, valueWidth)
		if len(lines) == 0 {
			lines = []string{""}
		}
		for i, line := range lines {
			label := row[0]
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(w, "%s     %-*s %s%s\n", colorBlueMedium, labelWidth, label, line, colorReset)
		}
	}
}

// viewDeployedPoliciesInteractive runs the wizard view/deactivate flow for
// deployed managed policies.
func viewDeployedPoliciesInteractive(ctx context.Context, a *App) error {
	for {
		policies, err := deployedManagedPolicies(a)
		if err != nil {
			return err
		}
		items := policyMenuItems(policies, "No policies currently deployed")
		if len(policies) > 0 {
			items[len(items)-1][1] = "Return without removing any policies"
		}
		choice, err := choiceMenu("[proxyble] Policies -> Deployed", "Policy                         Description\nSelect a deployed policy to deactivate.", items, "")
		if err != nil {
			return err
		}
		if choice == "back" {
			return nil
		}
		policy, ok := selectPolicyByID(policies, choice)
		if !ok {
			return fmt.Errorf("selected policy was not found: %s", choice)
		}
		confirmChoice, err := choiceMenu("[proxyble] Policies -> Remove", fmt.Sprintf("Remove policy %s now?", policy.Name), [][2]string{
			{"yes|Yes", "Remove this deployed policy"},
			{"cancel|Cancel", "Return without removing this policy"},
		}, "")
		if err != nil {
			return err
		}
		if confirmChoice != "yes" {
			continue
		}
		if err := removePolicy(ctx, a, policy, false); err != nil {
			return err
		}
		pause()
	}
}

// parsePolicyArgs parses policy selector and editor flags shared by view/edit.
func parsePolicyArgs(args []string, defaultSelector string) (selector, editor string, err error) {
	selector = defaultSelector
	editor = firstNonEmpty(os.Getenv("VISUAL"), os.Getenv("EDITOR"), "vi")
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
		case arg == "--policy":
			selector, err = value()
			if err != nil {
				return "", "", err
			}
		case strings.HasPrefix(arg, "--policy="):
			selector, _ = value()
		case arg == "--editor":
			editor, err = value()
			if err != nil {
				return "", "", err
			}
		case strings.HasPrefix(arg, "--editor="):
			editor, _ = value()
		default:
			return "", "", fmt.Errorf("unexpected flag for policy action: %s", arg)
		}
	}
	return selector, editor, nil
}

// resolvePolicyFile maps a CLI selector to one concrete policy file or to the
// internal "__all__" sentinel when allowed.
func resolvePolicyFile(c *Config, selector string, allowAll bool) (string, error) {
	files, err := loadPolicyFiles(c)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no installed Proxyble policy SQL files were found in %s", policySQLDir(c))
	}
	if selector == "" {
		if allowAll {
			return "__all__", nil
		}
		if len(files) == 1 {
			return files[0], nil
		}
		return "", fmt.Errorf("--policy is required when more than one policy is installed")
	}
	if selector == "all" {
		if allowAll {
			return "__all__", nil
		}
		return "", fmt.Errorf("--policy all is not valid for this action")
	}
	matches := []string{}
	for _, file := range files {
		if selector == file || selector == filepath.Base(file) {
			matches = append(matches, file)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("policy selector is ambiguous: %s", selector)
	}
	if strings.Contains(selector, "/") {
		if _, err := os.Stat(selector); err == nil && isPolicySQL(selector) {
			return selector, nil
		}
	}
	return "", fmt.Errorf("policy file not found: %s", selector)
}

// policiesView prints one selected policy or all installed policies.
func policiesView(a *App, args []string) error {
	selector, _, err := parsePolicyArgs(args, "all")
	if err != nil {
		return err
	}
	selected, err := resolvePolicyFile(a.Config, selector, true)
	if err != nil {
		return err
	}
	if selected == "__all__" {
		files, err := loadPolicyFiles(a.Config)
		if err != nil {
			return err
		}
		for _, file := range files {
			if err := printPolicyFile(a, file); err != nil {
				return err
			}
		}
		return nil
	}
	return printPolicyFile(a, selected)
}

// printPolicyFile prints a policy header and the file's exact SQL text.
func printPolicyFile(a *App, file string) error {
	a.Printf("%s\n", hr(79))
	a.Printf("Policy: %s\n", filepath.Base(file))
	a.Printf("Path  : %s\n", file)
	a.Printf("%s\n\n", hr(79))
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	a.Printf("%s", string(data))
	if len(data) == 0 || data[len(data)-1] != '\n' {
		a.Printf("\n")
	}
	a.Printf("\n")
	return nil
}

// policiesEdit opens one policy in the chosen terminal editor and restores
// secure ownership/permissions after the editor exits.
func policiesEdit(ctx context.Context, a *App, args []string) error {
	selector, editor, err := parsePolicyArgs(args, "")
	if err != nil {
		return err
	}
	if a.CommandLine && selector == "" {
		return fmt.Errorf("--policies-edit requires --policy")
	}
	selected, err := resolvePolicyFile(a.Config, selector, false)
	if err != nil {
		return err
	}
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		return fmt.Errorf("policy editing requires an interactive terminal")
	}
	editorCmd := strings.Fields(editor)
	if len(editorCmd) == 0 {
		editorCmd = []string{"vi"}
	}
	if !commandExists(editorCmd[0]) {
		return fmt.Errorf("editor not found: %s", editorCmd[0])
	}
	if err := a.PrepareLog("[proxyble] Policies -> Edit"); err != nil {
		return err
	}
	defer a.CloseLog()
	a.Printf("[INFO] Opening policy for editing: %s\n", selected)
	fmt.Fprintf(a.LogFile, "%s ACTION=POLICY_EDIT_START POLICY=%s EDITOR=%s\n", logTimestamp(), selected, editor)
	cmd := exec.CommandContext(ctx, editorCmd[0], append(editorCmd[1:], selected)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(a.LogFile, "%s ACTION=POLICY_EDIT_FAILED POLICY=%s ERROR=%q\n", logTimestamp(), selected, err.Error())
		return err
	}
	_ = chmodPath(selected, 0o600)
	_ = chownPath(selected, a.Config.Get("riodb", "user", "riodb"), a.Config.Get("riodb", "group", "riodb"))
	fmt.Fprintf(a.LogFile, "%s ACTION=POLICY_EDIT_COMPLETE POLICY=%s\n", logTimestamp(), selected)
	a.Printf("[OK] Policy edit complete. Full log: %s\n", a.LogPath)
	return nil
}

// logTimestamp returns the rule/policy audit timestamp format used in logs.
func logTimestamp() string {
	return timeNow().Format("2006/01/02 15:04:05")
}
