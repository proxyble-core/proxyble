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
