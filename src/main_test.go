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

// main_test.go covers menu gating behavior owned by main.go. These tests guard
// user-facing wizard state so future refactors do not expose service controls
// before Proxyble has enough runtime configuration to use them.

import (
	"strings"
	"testing"
)

func TestParseGlobalArgsVerboseOnlyKeepsWizardMode(t *testing.T) {
	app, help, err := parseGlobalArgs([]string{"--verbose"})
	if err != nil {
		t.Fatalf("parseGlobalArgs returned error: %v", err)
	}
	if help {
		t.Fatalf("help should be false")
	}
	if app.CommandLine {
		t.Fatalf("--verbose alone should not force command-line mode")
	}
	if app.Action != "" {
		t.Fatalf("action = %q, want empty", app.Action)
	}
}

func TestParseGlobalArgsNonVerboseFlagRequiresAction(t *testing.T) {
	if _, _, err := parseGlobalArgs([]string{"--yes"}); err == nil {
		t.Fatalf("--yes without an action should fail instead of opening the wizard")
	}
}

func TestParseGlobalArgsActionForcesCommandLineMode(t *testing.T) {
	app, help, err := parseGlobalArgs([]string{"--config-listener"})
	if err != nil {
		t.Fatalf("parseGlobalArgs returned error: %v", err)
	}
	if help {
		t.Fatalf("help should be false")
	}
	if !app.CommandLine {
		t.Fatalf("action flags should force command-line mode")
	}
	if app.Action != "--config-listener" {
		t.Fatalf("action = %q, want --config-listener", app.Action)
	}
}

func TestParseGlobalArgsRestartAliasMapsToStart(t *testing.T) {
	app, _, err := parseGlobalArgs([]string{"--config-restart"})
	if err != nil {
		t.Fatalf("parseGlobalArgs returned error: %v", err)
	}
	if app.Action != "--config-start" {
		t.Fatalf("action = %q, want --config-start", app.Action)
	}
}

func TestCLIInstallGateMatchesWizardHiddenAreas(t *testing.T) {
	blocked := []string{
		"--config-listener",
		"--config-backend",
		"--config-status",
		"--config-start",
		"--config-stop",
		"--installation-add-riodb",
		"--policies-deploy",
		"--policies-list",
		"--policies-remove",
		"--policies-view",
		"--policies-edit",
		"--rules-list",
		"--rules-add",
	}
	for _, action := range blocked {
		if !cliActionRequiresInstalledSoftware(action) {
			t.Fatalf("%s should require installed software", action)
		}
	}
	allowed := []string{
		"--install",
		"--installation-license",
		"--installation-list",
		"--installation-remove",
		"--internal-nft-init",
	}
	for _, action := range allowed {
		if cliActionRequiresInstalledSoftware(action) {
			t.Fatalf("%s should not be blocked by the installed-software gate", action)
		}
	}
}

func TestInstallProfileMenuOffersCoreFullAndExit(t *testing.T) {
	items := installProfileMenuItems()
	if len(items) != 3 {
		t.Fatalf("installProfileMenuItems length = %d, want 3", len(items))
	}
	for _, tag := range []string{"full", "core", "exit"} {
		if !hasMenuTag(items, tag) {
			t.Fatalf("install profile menu missing %s: %#v", tag, items)
		}
	}
	label, _ := menuDisplayTag(items[0][0])
	if label != "Automated protection" {
		t.Fatalf("first install profile label = %q, want Automated protection", label)
	}
	if !strings.Contains(items[0][1], "(Recommended)") || !strings.Contains(items[0][1], "always-free RioDB tier") || !strings.Contains(items[0][1], "automate rule workflows") {
		t.Fatalf("full install profile copy should recommend automation and mention the free RioDB tier: %#v", items[0])
	}
	label, _ = menuDisplayTag(items[1][0])
	if label != "Core only" {
		t.Fatalf("second install profile label = %q, want Core only", label)
	}
	if !strings.Contains(items[1][1], "Control rules manually") || !strings.Contains(items[1][1], "open-source (GPLv2)") || !strings.Contains(items[1][1], "automation can be added later") {
		t.Fatalf("core install profile copy should balance open-source core with later automation: %#v", items[1])
	}
	if hasMenuTag(items, "installation!") || hasMenuTag(items, "installation") {
		t.Fatalf("install profile gate should not include installation: %#v", items)
	}
}

func TestInstallAcceptanceMenuCombinesAcceptanceWithInstall(t *testing.T) {
	items := installAcceptanceMenuItems(installProfileFull)
	if len(items) != 2 {
		t.Fatalf("installAcceptanceMenuItems length = %d, want 2", len(items))
	}
	if !hasMenuTag(items, "install") {
		t.Fatalf("acceptance menu should include install action: %#v", items)
	}
	if !strings.Contains(items[0][0], "Accept notice/EULA and install Proxyble + RioDB now") {
		t.Fatalf("full acceptance action should accept EULA and install: %#v", items[0])
	}
}

func TestInstallationMenuRenamesInstallAfterInstalled(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{
		"riodb": {"enabled": "false"},
	}}
	items := installationMenuItems(cfg, true)
	label := ""
	description := ""
	for _, item := range items {
		if menuChoiceTag(item[0]) == "install" {
			label, _ = menuDisplayTag(item[0])
			description = item[1]
			break
		}
	}
	if label != "Repair / re-install" {
		t.Fatalf("installed install action label = %q, want Repair / re-install", label)
	}
	if !strings.Contains(description, "restore missing Proxyble components") {
		t.Fatalf("repair description should explain restore behavior: %q", description)
	}
	if !hasMenuTag(items, "add-riodb") || !hasMenuTag(items, "remove") {
		t.Fatalf("installed core menu should include add-riodb and remove: %#v", items)
	}
}

func TestInstallConfirmPromptUsesRepairCopyWhenInstalled(t *testing.T) {
	if got := installConfirmPrompt(installProfileCore, true); got != "Repair/re-install Proxyble Core components now?" {
		t.Fatalf("core repair prompt = %q", got)
	}
	if got := installConfirmPrompt(installProfileFull, true); got != "Repair/re-install Proxyble plus RioDB analytics now?" {
		t.Fatalf("full repair prompt = %q", got)
	}
	if got := installConfirmPrompt(installProfileCore, false); got != "Install Proxyble Core for manual rule enforcement now?" {
		t.Fatalf("core install prompt = %q", got)
	}
}

func TestLicenseAcceptanceMenuUsesExplicitAcceptDeclineText(t *testing.T) {
	items := licenseAcceptanceMenuItems()
	for _, tag := range []string{acceptLicenses, declineLicenses} {
		if !hasMenuTag(items, tag) {
			t.Fatalf("license acceptance menu missing %s: %#v", tag, items)
		}
	}
}

func TestOpenSourceNoticeAcceptanceMenuUsesExplicitText(t *testing.T) {
	items := openSourceNoticeAcceptanceMenuItems()
	for _, tag := range []string{acknowledgeNotices, declineLicenses} {
		if !hasMenuTag(items, tag) {
			t.Fatalf("open-source notice acceptance menu missing %s: %#v", tag, items)
		}
	}
}

func TestRioDBLicenseAcceptanceMenuMentionsJavaNoticeWhenShown(t *testing.T) {
	items := rioDBLicenseAcceptanceMenuItems(true)
	if !hasMenuTag(items, acceptRioDBJavaLicense) || !hasMenuTag(items, declineLicenses) {
		t.Fatalf("RioDB license acceptance menu missing expected choices: %#v", items)
	}
	if !strings.Contains(acceptRioDBJavaLicense, "Java notices") {
		t.Fatalf("RioDB acceptance text should mention Java notice: %q", acceptRioDBJavaLicense)
	}
}

func TestRioDBLicenseAcceptanceMenuOmitsJavaWhenNoticeHidden(t *testing.T) {
	items := rioDBLicenseAcceptanceMenuItems(false)
	if !hasMenuTag(items, acceptRioDBLicense) || !hasMenuTag(items, declineLicenses) {
		t.Fatalf("RioDB license acceptance menu missing expected choices: %#v", items)
	}
	if strings.Contains(acceptRioDBLicense, "Java") {
		t.Fatalf("RioDB-only acceptance text should not mention Java: %q", acceptRioDBLicense)
	}
}

func TestParseInstallOptionsProfiles(t *testing.T) {
	opts, err := parseInstallOptions([]string{"--core-only"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.profile != installProfileCore || !opts.profileSet || opts.acceptLicense {
		t.Fatalf("core install options = %#v", opts)
	}
	opts, err = parseInstallOptions([]string{"--with-riodb", "--accept-license"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.profile != installProfileFull || !opts.profileSet || !opts.acceptLicense {
		t.Fatalf("RioDB install options = %#v", opts)
	}
	if _, err := parseInstallOptions([]string{"--core-only", "--with-riodb"}); err == nil {
		t.Fatalf("conflicting install profiles should fail")
	}
}

func TestSelectedInstallProfileDefaultsToCoreForExistingCoreConfig(t *testing.T) {
	app := &App{
		ConfigFileExistedAtStart: true,
		Config: &Config{Data: map[string]map[string]string{
			"riodb": {"enabled": "false"},
		}},
	}
	if got := selectedInstallProfile(app); got != installProfileCore {
		t.Fatalf("selectedInstallProfile = %q, want %q", got, installProfileCore)
	}
	app.Config.Data["riodb"]["enabled"] = "true"
	if got := selectedInstallProfile(app); got != installProfileFull {
		t.Fatalf("selectedInstallProfile with RioDB enabled = %q, want %q", got, installProfileFull)
	}
}

// TestConfigMenuHidesServiceControlsUntilRuntimeConfigComplete verifies that
// start/stop appear only after listener and backend settings are complete.
func TestConfigMenuHidesServiceControlsUntilRuntimeConfigComplete(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{
		"traffic": {"mode": "tcp"},
		"haproxy": {
			"listener_port": "80",
			"timeout":       "60s",
		},
	}}
	if hasMenuTag(configMenuItems(cfg), "start") || hasMenuTag(configMenuItems(cfg), "stop") {
		t.Fatalf("start/stop should be hidden when backend is incomplete")
	}

	cfg.Data["haproxy"]["backend_primary_host"] = "10.0.0.5"
	cfg.Data["haproxy"]["backend_primary_port"] = "8080"
	if !hasMenuTag(configMenuItems(cfg), "start") || !hasMenuTag(configMenuItems(cfg), "stop") {
		t.Fatalf("start/stop should be shown when listener and backend are complete")
	}
}

// TestConfigMenuMarksIncompleteListenerAndBackend verifies the visual guidance
// hints that lead a new install toward the required setup steps.
func TestConfigMenuMarksIncompleteListenerAndBackend(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{
		"traffic": {"mode": "tcp"},
		"haproxy": {},
	}}
	if !hasMenuTag(configMenuItems(cfg), "listener!") || !hasMenuTag(configMenuItems(cfg), "backend!") {
		t.Fatalf("listener and backend should be marked when both are incomplete")
	}

	cfg.Data["haproxy"]["listener_port"] = "80"
	cfg.Data["haproxy"]["timeout"] = "60s"
	if !hasMenuTag(configMenuItems(cfg), "listener") || !hasMenuTag(configMenuItems(cfg), "backend!") {
		t.Fatalf("only backend should be marked after listener is complete")
	}
}

// TestMenuChoiceTagStripsWarningMarker keeps the red exclamation marker visual
// only, so switch statements still receive the base action tag.
func TestMenuChoiceTagStripsWarningMarker(t *testing.T) {
	if got := menuChoiceTag("config!"); got != "config" {
		t.Fatalf("menuChoiceTag(config!) = %q, want config", got)
	}
}

func TestConfigMenuMarksStartWhenServicesNeedAttention(t *testing.T) {
	cfg := completeRuntimeConfig()
	items := configMenuItemsForState(cfg, true)
	if !hasMenuTag(items, "start!") {
		t.Fatalf("start should be marked when services need attention: %#v", items)
	}
	if hasMenuTag(items, "restart") || hasMenuTag(items, "restart!") {
		t.Fatalf("restart should not be shown after menu rename: %#v", items)
	}
}

func TestMainMenuMarksConfigAndKeepsRuntimeAreasWhenServicesNeedAttention(t *testing.T) {
	items := mainMenuItems(completeRuntimeConfig(), true)
	if !hasMenuTag(items, "config!") {
		t.Fatalf("config should be marked when services need attention: %#v", items)
	}
	if !hasMenuTag(items, "rules") {
		t.Fatalf("rules should remain available when services need attention: %#v", items)
	}
	cfg := completeRuntimeConfig()
	cfg.Data["riodb"] = map[string]string{"enabled": "true"}
	items = mainMenuItems(cfg, true)
	if !hasMenuTag(items, "policies") || !hasMenuTag(items, "rules") {
		t.Fatalf("policies/rules should remain available when services need attention: %#v", items)
	}
}

func TestMainMenuHidesRuntimeAreasUntilRuntimeConfigComplete(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{
		"traffic": {"mode": "tcp"},
		"haproxy": {
			"listener_port": "80",
			"timeout":       "60s",
		},
		"riodb": {"enabled": "true"},
	}}
	items := mainMenuItems(cfg, false)
	if hasMenuTag(items, "policies") || hasMenuTag(items, "rules") {
		t.Fatalf("policies/rules should wait until listener and backend are complete: %#v", items)
	}
}

func TestMainMenuHidesPoliciesWhenRioDBDisabled(t *testing.T) {
	cfg := completeRuntimeConfig()
	items := mainMenuItems(cfg, false)
	if hasMenuTag(items, "policies") {
		t.Fatalf("policies should be hidden when RioDB analytics is disabled: %#v", items)
	}
	if !hasMenuTag(items, "rules") {
		t.Fatalf("manual rules should remain visible without RioDB: %#v", items)
	}
	cfg.Data["riodb"] = map[string]string{"enabled": "true"}
	items = mainMenuItems(cfg, false)
	if !hasMenuTag(items, "policies") || !hasMenuTag(items, "rules") {
		t.Fatalf("policies and rules should be visible with RioDB enabled: %#v", items)
	}
}

func TestRuntimeHealthUnitsFollowRioDBEnabled(t *testing.T) {
	cfg := completeRuntimeConfig()
	if hasString(proxybleRuntimeHealthUnits(cfg), "riodb.service") {
		t.Fatalf("RioDB unit should be skipped when RioDB analytics is disabled")
	}
	cfg.Data["riodb"] = map[string]string{"enabled": "true"}
	if !hasString(proxybleRuntimeHealthUnits(cfg), "riodb.service") {
		t.Fatalf("RioDB unit should be included when RioDB analytics is enabled")
	}
}

func completeRuntimeConfig() *Config {
	return &Config{Data: map[string]map[string]string{
		"traffic": {"mode": "tcp"},
		"haproxy": {
			"listener_port":        "80",
			"timeout":              "60s",
			"backend_primary_host": "10.0.0.5",
			"backend_primary_port": "8080",
		},
	}}
}

// hasMenuTag is a small assertion helper for menu item slices.
func hasMenuTag(items [][2]string, tag string) bool {
	want := menuChoiceTag(tag)
	for _, item := range items {
		if menuChoiceTag(item[0]) == want {
			return true
		}
	}
	return false
}

func hasString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
