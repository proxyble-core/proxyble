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

import (
	"strings"
	"testing"
)

func TestInterruptExitPromptUsesProductNameWithoutLogoBrackets(t *testing.T) {
	prompt := interruptExitPrompt()
	if !strings.Contains(prompt, "Exit Proxyble?") {
		t.Fatalf("interruptExitPrompt = %q, want product name without logo brackets", prompt)
	}
	if strings.Contains(prompt, "[proxyble]") {
		t.Fatalf("interruptExitPrompt should not use logo spelling in sentence text: %q", prompt)
	}
}

func TestInterruptReplyAction(t *testing.T) {
	tests := map[string]string{
		"y":                  "exit",
		"Y":                  "exit",
		"yes\n":              "exit",
		" n ":                "continue",
		"\n":                 "continue",
		"":                   "continue",
		string([]byte{0x03}): "force",
		"maybe":              "invalid",
	}
	for input, want := range tests {
		if got := interruptReplyAction(input); got != want {
			t.Fatalf("interruptReplyAction(%q) = %q, want %q", input, got, want)
		}
	}
}
