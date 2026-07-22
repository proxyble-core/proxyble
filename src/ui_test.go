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

// ui_test.go covers terminal rendering helpers whose output affects banner and
// menu alignment. These tests are intentionally small because most UI behavior
// depends on real TTY input.

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestDisplayWidthCountsUnicodeGlyphsAsColumns protects the ASCII-art alignment
// math used by the Proxyble banner.
func TestDisplayWidthCountsUnicodeGlyphsAsColumns(t *testing.T) {
	text := "██████╗"
	if got, want := displayWidth(text), 7; got != want {
		t.Fatalf("displayWidth(%q) = %d, want %d", text, got, want)
	}
}

// TestConfirmOptionTextConvertsQuestionToActionLabel checks the text transform
// that turns old y/n prompts into menu choices.
func TestConfirmOptionTextConvertsQuestionToActionLabel(t *testing.T) {
	label, detail := confirmOptionText("Install Proxyble plus RioDB analytics now?")
	if label != "Install Proxyble plus RioDB analytics now" || detail != "" {
		t.Fatalf("confirmOptionText install prompt = (%q, %q)", label, detail)
	}
	label, detail = confirmOptionText("Also remove Java JDK? Only choose yes if Java is not used by other software.")
	if label != "Also remove Java JDK" || detail != "Only choose yes if Java is not used by other software." {
		t.Fatalf("confirmOptionText detail prompt = (%q, %q)", label, detail)
	}
}

func TestConfirmActionTextAlignsActionAndBackColumns(t *testing.T) {
	tests := []struct {
		label       string
		description string
	}{
		{"repair", "Re-install Proxyble Core components now"},
		{"install", "Enable RioDB analytics now"},
		{"remove", "Continue with Proxyble teardown"},
	}
	for _, tt := range tests {
		action := confirmActionText(tt.label, tt.description)
		if got, want := strings.Index(action, tt.description), confirmMenuLabelWidth; got != want {
			t.Fatalf("%s description column = %d, want %d in %q", tt.label, got, want, action)
		}
		lines := confirmMenuLines(action, "", 1)
		if !strings.Contains(lines[len(lines)-3], action) {
			t.Fatalf("%s confirmation row = %q, want action %q", tt.label, lines[len(lines)-3], action)
		}
	}
}

// TestMenuLabelWidthExpandsForLongRuleNames ensures reset-rule counts align
// when a rule type is longer than the default menu label column.
func TestMenuLabelWidthExpandsForLongRuleNames(t *testing.T) {
	items := [][2]string{
		{"DROP", "       1"},
		{"LIMIT_ENDPOINT_RATE", "       2"},
	}
	if got, want := menuLabelWidth(items), len("LIMIT_ENDPOINT_RATE"); got != want {
		t.Fatalf("menuLabelWidth = %d, want %d", got, want)
	}
}

func TestMenuTagsSupportStableChoicesAndDisplayLabels(t *testing.T) {
	label, warning := menuDisplayTag("full|Automated protection!")
	if label != "Automated protection" || !warning {
		t.Fatalf("menuDisplayTag = (%q, %t), want display label with warning", label, warning)
	}
	if got := menuChoiceTag("full|Automated protection!"); got != "full" {
		t.Fatalf("menuChoiceTag = %q, want full", got)
	}
	lines := menuDescriptionLines("First line\n  Second line  ")
	if len(lines) != 2 || lines[0] != "First line" || lines[1] != "Second line" {
		t.Fatalf("menuDescriptionLines trimmed multi-line description: %#v", lines)
	}
	lines = menuDescriptionLines("First line\n")
	if len(lines) != 2 || lines[0] != "First line" || lines[1] != "" {
		t.Fatalf("menuDescriptionLines should preserve intentional trailing spacer: %#v", lines)
	}
	lines = menuDescriptionLines("Alpha beta gamma delta", 12)
	if len(lines) != 2 || lines[0] != "Alpha beta" || lines[1] != "gamma delta" {
		t.Fatalf("menuDescriptionLines should wrap inside description column: %#v", lines)
	}
	if got, want := menuDescriptionWrapWidth(44, preferredMenuBodyWidth), 76; got != want {
		t.Fatalf("menuDescriptionWrapWidth with wide menu = %d, want %d", got, want)
	}
}

func TestUninstallExitPrompt(t *testing.T) {
	if got, want := uninstallExitPrompt(), "Press any key to exit."; got != want {
		t.Fatalf("uninstallExitPrompt = %q, want %q", got, want)
	}
}

func TestWizardReturnTipIsExactOnMenusAndConfirmations(t *testing.T) {
	if got, want := wizardReturnTip, "Press ESC key to return."; got != want {
		t.Fatalf("wizardReturnTip = %q, want %q", got, want)
	}
	if got, want := wizardReturnTipLine("Use Up/Down and Enter. "), "Use Up/Down and Enter. Press ESC key to return."; got != want {
		t.Fatalf("wizardReturnTipLine = %q, want %q", got, want)
	}
	lines := confirmMenuLines("Continue", "", 0)
	if got := lines[len(lines)-1]; !strings.Contains(got, wizardReturnTip) || strings.Contains(got, "Press q") {
		t.Fatalf("confirmation footer = %q, want exact ESC return tip", got)
	}
	if got := lines[len(lines)-2]; !strings.Contains(got, "back            Return to previous menu") {
		t.Fatalf("confirmation back row = %q, want consistent back option", got)
	}
}

func TestMenuCancelChoiceReturnsOneLevelOrExitsMainMenu(t *testing.T) {
	if got := menuCancelChoice([][2]string{{"child", ""}, {"back", ""}}); got != "back" {
		t.Fatalf("submenu ESC choice = %q, want back", got)
	}
	if got := menuCancelChoice([][2]string{{"yes", ""}, {"cancel", ""}}); got != "cancel" {
		t.Fatalf("confirmation ESC choice = %q, want cancel", got)
	}
	if got := menuCancelChoice([][2]string{{"config", ""}, {"exit", ""}}); got != "exit" {
		t.Fatalf("main-menu ESC choice = %q, want exit", got)
	}
}

func TestReadRawWizardLineEscapeReturnsWizardBack(t *testing.T) {
	var output bytes.Buffer
	value, err := readRawWizardLine(bytes.NewBufferString("443\x1b"), &output)
	if value != "" {
		t.Fatalf("value after ESC = %q, want empty", value)
	}
	if !errors.Is(err, errWizardBack) || !errors.Is(err, errActionCancelled) {
		t.Fatalf("ESC error = %v, want wizard-back action cancellation", err)
	}
}

func TestReadRawWizardLineSupportsBackspace(t *testing.T) {
	var output bytes.Buffer
	value, err := readRawWizardLine(bytes.NewBufferString("44\x7f3\r"), &output)
	if err != nil {
		t.Fatalf("readRawWizardLine error = %v", err)
	}
	if value != "43" {
		t.Fatalf("edited value = %q, want 43", value)
	}
}

func TestReadMenuKeyRecognizesLoneEscape(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{0x1b}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	key, err := readMenuKey(r)
	if err != nil {
		t.Fatalf("readMenuKey error = %v", err)
	}
	if key != "escape" {
		t.Fatalf("readMenuKey = %q, want escape", key)
	}
}
