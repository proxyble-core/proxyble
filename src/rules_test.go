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

// rules_test.go covers regressions in manual rule CLI parsing and validation.
// Keep these tests focused on behavior that previously broke during the bash to
// Go conversion.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseRuleAddArgsAcceptsYesFlag ensures --rules-add accepts the global-like
// --yes flag when invoked from interactive flows.
func TestParseRuleAddArgsAcceptsYesFlag(t *testing.T) {
	fields, err := parseRuleAddArgs([]string{
		"--rule", "DROP",
		"--target", "10.10.10.10",
		"--expiration", "none",
		"--yes",
	})
	if err != nil {
		t.Fatalf("parseRuleAddArgs returned error: %v", err)
	}
	if fields["yes"] != "true" {
		t.Fatalf("expected --yes to be accepted and recorded, got %q", fields["yes"])
	}
}

func TestCommandLineRuleAddRequiresFlags(t *testing.T) {
	app := &App{CommandLine: true}
	err := addRule(context.Background(), app, nil)
	if err == nil || !strings.Contains(err.Error(), "--rules-add requires --rule, --target, and --expiration") {
		t.Fatalf("addRule command-line missing flags error = %v", err)
	}
}

func TestCommandLineCheckIPRequiresIP(t *testing.T) {
	app := &App{CommandLine: true}
	err := checkIP(context.Background(), app, nil)
	if err == nil || !strings.Contains(err.Error(), "--rules-check requires --ip") {
		t.Fatalf("checkIP command-line missing IP error = %v", err)
	}
}

func TestCommandLineResetRequiresTypeBeforeStateLookup(t *testing.T) {
	app := &App{
		CommandLine: true,
		Config: &Config{Data: map[string]map[string]string{
			"traffic":    {"mode": "tcp"},
			"rule_agent": {},
		}},
	}
	err := resetRules(context.Background(), app, nil)
	if err == nil || !strings.Contains(err.Error(), "--rules-reset requires --type") {
		t.Fatalf("resetRules command-line missing type error = %v", err)
	}
}

func TestPrepareRuleDraftAcceptsGlobalLimitConcurrent(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{
		"traffic": {"mode": "tcp"},
	}}
	draft, err := prepareRuleDraft(cfg, map[string]string{
		"rule":       "LIMIT_CONCURRENT",
		"target":     "0.0.0.0/0",
		"parameter":  "50",
		"expiration": "none",
	})
	if err != nil {
		t.Fatalf("prepareRuleDraft() error = %v", err)
	}
	if draft.Line != "LIMIT_CONCURRENT 0.0.0.0/0 50" {
		t.Fatalf("draft line = %q, want LIMIT_CONCURRENT 0.0.0.0/0 50", draft.Line)
	}
}

func TestPrepareRuleDraftNormalizesCIDRHostBits(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{
		"traffic": {"mode": "http"},
	}}
	tests := []struct {
		name       string
		fields     map[string]string
		wantTarget string
		wantLine   string
	}{
		{
			name: "limit bandwidth",
			fields: map[string]string{
				"rule":       "LIMIT_BANDWIDTH",
				"target":     "10.10.10.10/24",
				"parameter":  "10mb",
				"expiration": "none",
			},
			wantTarget: "10.10.10.0/24",
			wantLine:   "LIMIT_BANDWIDTH 10.10.10.0/24 10mb",
		},
		{
			name: "limit rate slow",
			fields: map[string]string{
				"rule":       "LIMIT_RATE_SLOW",
				"target":     "20.20.20.20/24",
				"expiration": "none",
			},
			wantTarget: "20.20.20.0/24",
			wantLine:   "LIMIT_RATE_SLOW 20.20.20.0/24",
		},
		{
			name: "reject",
			fields: map[string]string{
				"rule":       "REJECT",
				"target":     "30.30.30.30/24",
				"expiration": "10m",
			},
			wantTarget: "30.30.30.0/24",
			wantLine:   "REJECT 30.30.30.0/24 10m",
		},
		{
			name: "timeout",
			fields: map[string]string{
				"rule":       "TIMEOUT",
				"target":     "30.30.30.30/24",
				"parameter":  "5s",
				"expiration": "none",
			},
			wantTarget: "30.30.30.0/24",
			wantLine:   "TIMEOUT 30.30.30.0/24 5s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			draft, err := prepareRuleDraft(cfg, tt.fields)
			if err != nil {
				t.Fatalf("prepareRuleDraft() error = %v", err)
			}
			if draft.Target != tt.wantTarget {
				t.Fatalf("draft target = %q, want %q", draft.Target, tt.wantTarget)
			}
			if draft.Line != tt.wantLine {
				t.Fatalf("draft line = %q, want %q", draft.Line, tt.wantLine)
			}
		})
	}
}

// TestResetRuleMenuItemsEndsWithAllAndBack protects the interactive reset
// menu shape copied from the legacy bash wizard.
func TestResetRuleMenuItemsEndsWithAllAndBack(t *testing.T) {
	counts := map[string]int{"DROP": 3}
	items := resetRuleMenuItems(counts, 7)
	if len(items) != len(knownActions)+2 {
		t.Fatalf("resetRuleMenuItems length = %d, want %d", len(items), len(knownActions)+2)
	}
	if got := items[len(items)-2]; got[0] != "ALL" || got[1] != "       7" {
		t.Fatalf("second-to-last reset item = %#v, want ALL with total count", got)
	}
	if got, want := items[len(items)-1], [2]string{"back", "Return to previous menu"}; got != want {
		t.Fatalf("last reset item = %#v, want %#v", got, want)
	}
}

func TestDefaultRuleInboxUsesSpoolPath(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{
		"traffic":    {"mode": "tcp"},
		"rule_agent": {},
	}}
	paths := getRulePaths(cfg)
	if paths.WatchFile != defaultRuleInbox {
		t.Fatalf("default watch file = %q, want %q", paths.WatchFile, defaultRuleInbox)
	}
	body := readTestFile(t, filepath.Join("..", "templates", "RioSQL", mandatoryRuleQueueSQLFile))
	if !strings.Contains(body, "directory '/var/spool/proxyble/rules'") {
		t.Fatalf("RioDB rule queue SQL does not point at the default spool directory")
	}
}

func TestCheckedRuleRemovalPromptHidesEnforcementBackend(t *testing.T) {
	match := ruleMatch{
		System: "HAPROXY",
		Target: "10.10.10.10/32",
		Action: "BUSY_DEFLECTION",
	}
	got := checkedRuleRemovalPrompt(match)
	want := "Remove BUSY_DEFLECTION enforcement rule for source 10.10.10.10/32?"
	if got != want {
		t.Fatalf("checkedRuleRemovalPrompt = %q, want %q", got, want)
	}
	if strings.Contains(got, "HAPROXY") {
		t.Fatalf("checkedRuleRemovalPrompt should not expose enforcement backend: %q", got)
	}
}

func TestCheckedRuleRemovalCompleteMessageUsesFriendlySourceText(t *testing.T) {
	match := ruleMatch{
		System: "HAPROXY",
		Action: "BUSY_DEFLECTION",
	}
	got := checkedRuleRemovalCompleteMessage("10.10.10.10", match)
	want := "Removed BUSY_DEFLECTION enforcement rule for source 10.10.10.10."
	if got != want {
		t.Fatalf("checkedRuleRemovalCompleteMessage = %q, want %q", got, want)
	}
	if strings.Contains(got, "HAPROXY") {
		t.Fatalf("checkedRuleRemovalCompleteMessage should not expose enforcement backend: %q", got)
	}
}

func TestResetConfirmationPromptKeepsDestructiveKeywordMessage(t *testing.T) {
	got := resetConfirmationPrompt("all BUSY_DEFLECTION rules")
	if !strings.Contains(got, "This action is destructive.") {
		t.Fatalf("resetConfirmationPrompt should warn about destructive reset: %q", got)
	}
	if !strings.Contains(got, "Type RESET to confirm that all BUSY_DEFLECTION rules should be reset.") {
		t.Fatalf("resetConfirmationPrompt should preserve RESET keyword instruction: %q", got)
	}
}

func TestShouldFrameRuleResetCompletionOnlyForInteractiveReset(t *testing.T) {
	if !shouldFrameRuleResetCompletion(false, false) {
		t.Fatalf("interactive rule reset completion should be framed")
	}
	if shouldFrameRuleResetCompletion(true, false) {
		t.Fatalf("CLI rule reset with action args should not be framed")
	}
	if shouldFrameRuleResetCompletion(false, true) {
		t.Fatalf("assume-yes rule reset should not be framed")
	}
}

func TestCheckIPCancelInput(t *testing.T) {
	for _, input := range []string{"", "cancel", "q", "quit", " CANCEL "} {
		if !isCheckIPCancelInput(input) {
			t.Fatalf("isCheckIPCancelInput(%q) = false, want true", input)
		}
	}
	for _, input := range []string{"10.10.10.10", "192.0.2.1"} {
		if isCheckIPCancelInput(input) {
			t.Fatalf("isCheckIPCancelInput(%q) = true, want false", input)
		}
	}
}
