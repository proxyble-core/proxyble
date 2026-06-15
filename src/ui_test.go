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

import "testing"

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
