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

// ui.go provides the terminal user interface shared by the wizard and
// interactive prompts: banner rendering, page headers, confirmations, menus,
// raw-key arrow navigation, numbered fallbacks, scrollable viewers, and small
// terminal utilities. The UI deliberately avoids heavyweight dependencies so
// Proxyble can run on lightweight Linux distributions and later macOS builds.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ANSI color constants define the Proxyble terminal palette used throughout the
// wizard.
const (
	colorReset      = "\033[0m"
	colorBlueLight  = "\033[38;5;39m"
	colorBlueMedium = "\033[38;5;33m"
	colorBlueDark   = "\033[38;5;25m"
	colorRed        = "\033[38;5;196m"
	colorDim        = "\033[2m"
	colorBold       = "\033[1m"
	colorReverse    = "\033[7m"
	colorHighlight  = "\033[48;5;25m\033[38;5;231m"
)

const (
	minMenuBodyWidth       = 76
	preferredMenuBodyWidth = 120
	wizardReturnTip        = "Press ESC key to return."
	confirmMenuLabelWidth  = 16
)

// errWizardBack distinguishes an ESC request from an explicit cancellation
// choice while still matching errActionCancelled at top-level menu boundaries.
var errWizardBack = fmt.Errorf("%w: return to previous wizard menu", errActionCancelled)

// hr returns the blue horizontal rule used by CLI pages and logs.
func hr(width int) string {
	if width < 2 {
		width = 2
	}
	if width < 79 {
		return colorBlueLight + "╭" + strings.Repeat("─", width-1) + colorReset
	}
	return colorBlueLight + "╭" + strings.Repeat("─", width-2) + "╯" + colorReset
}

// printHR writes a horizontal rule plus a blank line to the target writer.
func printHR(w io.Writer, width int) {
	fmt.Fprintln(w, hr(width))
	fmt.Fprintln(w)
}

// banner renders the Proxyble ASCII art and current log path.
func banner(w io.Writer, logPath string) {
	const width = 77
	line := func(color, text string) {
		padding := width - displayWidth(text)
		if padding < 0 {
			padding = 0
		}
		fmt.Fprintf(w, "%s│%s%s%s%s│%s\n", colorBlueLight, color, text, strings.Repeat(" ", padding), colorBlueLight, colorReset)
	}
	fmt.Fprintf(w, "%s╭%s╮%s\n", colorBlueLight, strings.Repeat("─", width), colorReset)
	line(colorBlueLight, "")
	line(colorBlueLight, "     ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██████╗ ██╗     ███████╗")
	line(colorBlueLight, "     ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝██╔══██╗██║     ██╔════╝")
	line(colorBlueMedium, "     ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ██████╔╝██║     █████╗")
	line(colorBlueMedium, "     ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ██╔══██╗██║     ██╔══╝")
	line(colorBlueDark, "     ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ██████╔╝███████╗███████╗")
	line(colorBlueDark, "     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚══════╝╚══════╝")
	line(colorBlueDark, "")
	line(colorBlueDark, "      Real-time API protection for the agent-driven web.")
	line(colorBlueDark, "      [proxyble] Version 2026-6        log:"+logPath)
	fmt.Fprintf(w, "%s╰%s╯%s\n", colorBlueLight, strings.Repeat("─", width), colorReset)
}

// displayWidth estimates terminal columns for fixed-width banner/menu alignment.
func displayWidth(text string) int {
	width := 0
	for _, r := range text {
		if r == '\t' {
			width += 4
			continue
		}
		width++
	}
	return width
}

// pageHeader prints a page title, intro prompt, rule, and optional details.
func pageHeader(w io.Writer, title, prompt string) {
	fmt.Fprintf(w, "\n%s%s%s\n", colorBlueLight+colorBold, title, colorReset)
	prompt = normalizeIntroText(prompt)
	summary, details, hasDetails := strings.Cut(prompt, "\n\n")
	if strings.TrimSpace(summary) != "" {
		printIntroText(w, summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, hr(79))
	fmt.Fprintln(w)
	if hasDetails && strings.TrimSpace(details) != "" {
		printIntroText(w, details)
		fmt.Fprintln(w)
	}
}

// actionPage clears the terminal and draws the standard banner plus page header
// before an action prints prompts or progress.
func actionPage(title, prompt string) {
	clearScreen()
	banner(os.Stderr, "/var/log/proxyble/")
	pageHeader(os.Stderr, title, prompt)
}

// normalizeIntroText trims leading/trailing blank prompt lines without changing
// intentional internal paragraph breaks.
func normalizeIntroText(text string) string {
	lines := strings.Split(text, "\n")
	first := 0
	for first < len(lines) && strings.TrimSpace(lines[first]) == "" {
		first++
	}
	last := len(lines) - 1
	for last >= first && strings.TrimSpace(lines[last]) == "" {
		last--
	}
	out := make([]string, 0, max(0, last-first+1))
	for i := first; i <= last; i++ {
		out = append(out, strings.TrimSpace(lines[i]))
	}
	return strings.Join(out, "\n")
}

// printIntroText writes normalized intro text with the standard menu indentation.
func printIntroText(w io.Writer, text string) {
	for _, part := range strings.Split(text, "\n") {
		part = strings.TrimSpace(part)
		if part == "" {
			fmt.Fprintln(w)
			continue
		}
		fmt.Fprintf(w, "%s     %s%s\n", colorBlueMedium, part, colorReset)
	}
}

// confirm asks the operator to continue or return. Interactive terminals get the
// same arrow-key selection style as the main menus; non-interactive callers must
// still opt in with --yes so unattended runs cannot accidentally proceed.
func confirm(prompt string, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("confirmation required; re-run with --yes for non-interactive execution")
	}
	actionLabel, detail := confirmOptionText(prompt)
	if supportsArrowMenu() {
		ok, err := arrowConfirm(actionLabel, detail)
		if err == nil {
			return ok, nil
		}
		if !errors.Is(err, errArrowMenuUnavailable) {
			return false, err
		}
	}
	return numberedConfirm(actionLabel, detail)
}

// appConfirm keeps wizard confirmations on the arrow-key UI while command-line
// actions use plain y/N prompts suitable for scripts and automation wrappers.
func appConfirm(a *App, prompt string) (bool, error) {
	if a != nil && a.CommandLine {
		return commandLineConfirm(prompt, a.AssumeYes)
	}
	assumeYes := false
	if a != nil {
		assumeYes = a.AssumeYes
	}
	return confirm(prompt, assumeYes)
}

// appConfirmAction renders an explicit two-column action row in the wizard
// while preserving the full question-style prompt for command-line y/N input.
func appConfirmAction(a *App, actionLabel, actionDescription, prompt string) (bool, error) {
	if a != nil && a.CommandLine {
		return commandLineConfirm(prompt, a.AssumeYes)
	}
	assumeYes := false
	if a != nil {
		assumeYes = a.AssumeYes
	}
	return confirm(confirmActionText(actionLabel, actionDescription), assumeYes)
}

func confirmActionText(actionLabel, actionDescription string) string {
	return fmt.Sprintf("%-*s%s", confirmMenuLabelWidth, strings.TrimSpace(actionLabel), strings.TrimSpace(actionDescription))
}

// commandLineConfirm asks one confirmation question using typed y/N input.
func commandLineConfirm(prompt string, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("confirmation required; re-run with --yes for non-interactive execution")
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr, "%s [y/N]: ", strings.TrimSpace(prompt))
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		case "", "n", "no":
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "[NOTICE] Type y or n.")
		}
	}
}

// confirmOptionText converts a question-style prompt into a positive action
// label plus optional explanatory text for the confirmation menu.
func confirmOptionText(prompt string) (string, string) {
	text := strings.TrimSpace(prompt)
	label := text
	detail := ""
	if before, after, ok := strings.Cut(text, "?"); ok {
		label = strings.TrimSpace(before)
		detail = strings.TrimSpace(after)
	}
	label = strings.TrimSpace(strings.TrimSuffix(label, "."))
	if label == "" {
		label = "Continue"
	}
	return label, detail
}

// arrowConfirm renders a two-option in-place selector using raw terminal input.
func arrowConfirm(actionLabel, detail string) (bool, error) {
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		return false, errArrowMenuUnavailable
	}
	defer restore()
	fmt.Fprint(os.Stderr, "\033[?25l")
	defer fmt.Fprint(os.Stderr, "\033[?25h")
	selected := 0
	renderedLines := 0
	for {
		renderedLines = renderConfirmMenu(actionLabel, detail, selected, renderedLines)
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			clearRenderedLines(renderedLines)
			if errors.Is(err, io.EOF) {
				return false, errArrowMenuUnavailable
			}
			return false, err
		}
		switch key {
		case "up":
			if selected > 0 {
				selected--
			}
		case "down":
			if selected < 1 {
				selected++
			}
		case "enter":
			clearRenderedLines(renderedLines)
			return selected == 0, nil
		case "interrupt":
			handleInterruptRequest()
		case "escape":
			clearRenderedLines(renderedLines)
			return false, errWizardBack
		case "q":
			clearRenderedLines(renderedLines)
			return false, nil
		default:
			if n, ok := numericMenuChoice(key, 2); ok {
				clearRenderedLines(renderedLines)
				return n == 0, nil
			}
		}
	}
}

// numberedConfirm is the portable two-option fallback for terminals that cannot
// provide raw arrow-key input.
func numberedConfirm(actionLabel, detail string) (bool, error) {
	for {
		if strings.TrimSpace(detail) != "" {
			fmt.Fprintf(os.Stderr, "%s\n\n", strings.TrimSpace(detail))
		}
		fmt.Fprintf(os.Stderr, "  1. %s\n", actionLabel)
		fmt.Fprintf(os.Stderr, "  2. %-*s%s\n", confirmMenuLabelWidth, "back", "Return to previous menu")
		printWizardReturnTip(os.Stderr, "")
		fmt.Fprint(os.Stderr, "Select option: ")
		line, err := readWizardLine(os.Stdin)
		if errors.Is(err, errWizardBack) {
			return false, err
		}
		if err != nil && len(line) == 0 {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "1", strings.ToLower(actionLabel):
			return true, nil
		case "", "2", "back", "cancel", "q", "quit", "n", "no":
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "[NOTICE] Select 1 or 2.")
		}
	}
}

// renderConfirmMenu updates the in-place confirmation menu and returns how many
// terminal lines were rendered so the next refresh can overwrite them cleanly.
func renderConfirmMenu(actionLabel, detail string, selected, previousLines int) int {
	if previousLines > 0 {
		fmt.Fprintf(os.Stderr, "\033[%dA", previousLines)
	}
	lines := confirmMenuLines(actionLabel, detail, selected)
	for _, line := range lines {
		fmt.Fprintf(os.Stderr, "\r\033[2K%s\n", line)
	}
	return len(lines)
}

// confirmMenuLines builds the display rows for the two-option confirmation menu.
func confirmMenuLines(actionLabel, detail string, selected int) []string {
	var lines []string
	if strings.TrimSpace(detail) != "" {
		for _, line := range wrapConfirmText(detail, 72) {
			lines = append(lines, colorBlueMedium+"     "+line+colorReset)
		}
		lines = append(lines, "")
	}
	options := []string{actionLabel, fmt.Sprintf("%-*s%s", confirmMenuLabelWidth, "back", "Return to previous menu")}
	for i, option := range options {
		marker := " "
		if i == selected {
			marker = ">"
		}
		row := fmt.Sprintf("  %s %s", marker, clipDisplay(option, 72))
		if i == selected {
			padding := 76 - displayWidth(row)
			if padding < 0 {
				padding = 0
			}
			row = colorHighlight + row + strings.Repeat(" ", padding) + colorReset
		}
		lines = append(lines, row)
	}
	lines = append(lines, colorDim+wizardReturnTipLine("Use Up/Down and Enter. ")+colorReset)
	return lines
}

// clearRenderedLines erases a previously rendered in-place menu and leaves the
// cursor at the first cleared row for the next action output.
func clearRenderedLines(count int) {
	if count <= 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[%dA", count)
	for i := 0; i < count; i++ {
		fmt.Fprint(os.Stderr, "\r\033[2K")
		if i < count-1 {
			fmt.Fprint(os.Stderr, "\033[1B")
		}
	}
	if count > 1 {
		fmt.Fprintf(os.Stderr, "\033[%dA", count-1)
	}
}

// wrapConfirmText wraps explanatory confirmation detail so it does not disturb
// cursor math in the in-place selector.
func wrapConfirmText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := ""
	for _, word := range words {
		if line == "" {
			line = word
		} else if displayWidth(line)+1+displayWidth(word) <= width {
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

// clipDisplay shortens one menu label to fit within the fixed confirmation menu
// width.
func clipDisplay(value string, width int) string {
	if displayWidth(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	var b strings.Builder
	for _, r := range value {
		if displayWidth(b.String()+string(r)) > width-3 {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "..."
}

// confirmKeyword requires the operator to type an exact keyword for destructive
// actions.
func confirmKeyword(prompt, keyword string, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("confirmation required; re-run with --yes for non-interactive execution")
	}
	printWizardReturnTip(os.Stderr, "")
	fmt.Fprint(os.Stderr, prompt)
	line, err := readWizardLine(os.Stdin)
	if err != nil && len(line) == 0 {
		return false, err
	}
	return strings.TrimSpace(line) == keyword, nil
}

// promptValue reads one interactive text value, applying a default and required
// validation.
func promptValue(prompt, def string, required bool) (string, error) {
	if !isTerminal(os.Stdin) {
		return "", fmt.Errorf("interactive input is required")
	}
	for {
		printWizardReturnTip(os.Stderr, "")
		if def != "" {
			fmt.Fprintf(os.Stderr, "%s [%s]: ", prompt, def)
		} else {
			fmt.Fprintf(os.Stderr, "%s: ", prompt)
		}
		line, err := readWizardLine(os.Stdin)
		if err != nil && len(line) == 0 {
			return "", err
		}
		value := strings.TrimSpace(line)
		switch strings.ToLower(value) {
		case "cancel", "q", "quit":
			return "", errActionCancelled
		}
		if value == "" {
			value = def
		}
		if value != "" || !required {
			return value, nil
		}
		fmt.Fprintln(os.Stderr, "[ERROR] A value is required.")
	}
}

// wizardReturnTipLine keeps the final navigation sentence byte-for-byte
// identical on every wizard page while allowing a page-specific control hint.
func wizardReturnTipLine(prefix string) string {
	return prefix + wizardReturnTip
}

func printWizardReturnTip(w io.Writer, prefix string) {
	fmt.Fprintf(w, "\n%s%s%s\n\n", colorDim, wizardReturnTipLine(prefix), colorReset)
}

// readWizardLine reads an editable value while making a lone ESC immediately
// return to the previous wizard menu. Raw mode is used on supported terminals;
// limited-terminal fallbacks also recognize an ESC byte followed by Enter.
func readWizardLine(f *os.File) (string, error) {
	if isTerminal(f) {
		restore, err := makeTerminalRaw(f)
		if err == nil {
			defer restore()
			return readRawWizardLine(f, os.Stderr)
		}
	}
	line, err := bufio.NewReader(f).ReadString('\n')
	if strings.ContainsRune(line, '\x1b') {
		return "", errWizardBack
	}
	if err != nil && len(line) == 0 {
		return "", err
	}
	return line, nil
}

// readRawWizardLine provides the small amount of line editing needed by
// wizard forms without introducing a terminal UI dependency.
func readRawWizardLine(r io.Reader, w io.Writer) (string, error) {
	value := make([]byte, 0, 64)
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				if f, ok := r.(*os.File); ok && isTerminal(f) {
					continue
				}
			}
			if errors.Is(err, io.EOF) && len(value) > 0 {
				return string(value), nil
			}
			return "", err
		}
		if n == 0 {
			continue
		}
		b := one[0]
		switch b {
		case '\r', '\n':
			fmt.Fprintln(w)
			return string(value), nil
		case 0x1b:
			fmt.Fprintln(w)
			return "", errWizardBack
		case 0x03:
			handleInterruptRequest()
		case 0x04:
			if len(value) == 0 {
				return "", io.EOF
			}
		case 0x08, 0x7f:
			if len(value) == 0 {
				continue
			}
			_, size := utf8.DecodeLastRune(value)
			if size <= 0 {
				size = 1
			}
			value = value[:len(value)-size]
			fmt.Fprint(w, "\b \b")
		default:
			if b < 0x20 {
				continue
			}
			value = append(value, b)
			_, _ = w.Write(one[:])
		}
	}
}

// menu opens a required interactive menu without a preselected item.
func menu(title, prompt string, items [][2]string) (string, error) {
	if !isTerminal(os.Stdin) {
		return "", fmt.Errorf("interactive input is required")
	}
	return choiceMenu(title, prompt, items, "")
}

// choiceMenu selects arrow-key navigation when possible and falls back to a
// numbered menu for limited terminals.
func choiceMenu(title, prompt string, items [][2]string, selectedTag string, minimumLabelWidth ...int) (string, error) {
	if supportsArrowMenu() {
		choice, err := arrowMenu(title, prompt, items, selectedIndex(items, selectedTag), minimumLabelWidth...)
		if err == nil {
			return choice, nil
		}
		if !errors.Is(err, errArrowMenuUnavailable) {
			return "", err
		}
	}
	return numberedMenu(title, prompt, items, minimumLabelWidth...)
}

// errArrowMenuUnavailable signals that the caller should use the numbered menu
// fallback instead of treating raw terminal setup as fatal.
var errArrowMenuUnavailable = errors.New("arrow menu unavailable")

// supportsArrowMenu reports whether raw-key menus are likely to work.
func supportsArrowMenu() bool {
	term := strings.ToLower(strings.TrimSpace(os.Getenv("TERM")))
	return term != "" && term != "dumb" && isTerminal(os.Stdin) && isTerminal(os.Stderr)
}

// arrowMenu renders a highlighted menu controlled by arrow keys, Enter, and Escape.
func arrowMenu(title, prompt string, items [][2]string, selected int, minimumLabelWidth ...int) (string, error) {
	if len(items) == 0 {
		return "", fmt.Errorf("menu has no items")
	}
	if selected < 0 || selected >= len(items) {
		selected = 0
	}
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		return "", errArrowMenuUnavailable
	}
	defer restore()
	fmt.Fprint(os.Stderr, "\033[?25l")
	defer fmt.Fprint(os.Stderr, "\033[?25h")

	for {
		renderArrowMenu(title, prompt, items, selected, minimumLabelWidth...)
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", errArrowMenuUnavailable
			}
			return "", err
		}
		switch key {
		case "up":
			if selected > 0 {
				selected--
			}
		case "down":
			if selected < len(items)-1 {
				selected++
			}
		case "enter":
			clearScreen()
			return menuChoiceTag(items[selected][0]), nil
		case "interrupt":
			handleInterruptRequest()
		case "escape", "q":
			clearScreen()
			return menuCancelChoice(items), nil
		}
	}
}

// renderArrowMenu draws the current highlighted menu frame.
func renderArrowMenu(title, prompt string, items [][2]string, selected int, minimumLabelWidth ...int) {
	clearScreen()
	banner(os.Stderr, "/var/log/proxyble/")
	pageHeader(os.Stderr, title, prompt)
	bodyWidth := menuBodyWidth()
	labelWidth := menuLabelWidth(items, minimumLabelWidth...)
	descriptionPrefixWidth := labelWidth + 6
	descriptionWidth := menuDescriptionWrapWidth(descriptionPrefixWidth, bodyWidth)
	continuationPrefix := strings.Repeat(" ", descriptionPrefixWidth)
	for i, item := range items {
		marker := " "
		if i == selected {
			marker = ">"
		}
		label, warning := menuDisplayTag(item[0])
		warningMarker := " "
		if warning {
			warningMarker = "!"
		}
		description := menuDescriptionLines(item[1], descriptionWidth)
		row := fmt.Sprintf("  %s %-*s%s %s", marker, labelWidth, label, warningMarker, description[0])
		if i == selected {
			padding := bodyWidth - displayWidth(row)
			if padding < 0 {
				padding = 0
			}
			fmt.Fprintf(os.Stderr, "%s%s%s%s\n", colorHighlight, row, strings.Repeat(" ", padding), colorReset)
		} else {
			fmt.Fprintf(os.Stderr, "  %s %-*s", marker, labelWidth, label)
			if warning {
				fmt.Fprintf(os.Stderr, "%s!%s", colorRed, colorReset)
			} else {
				fmt.Fprint(os.Stderr, " ")
			}
			fmt.Fprintf(os.Stderr, " %s\n", description[0])
		}
		for _, line := range description[1:] {
			if line == "" {
				fmt.Fprintln(os.Stderr)
				continue
			}
			row := continuationPrefix + line
			if i == selected {
				padding := bodyWidth - displayWidth(row)
				if padding < 0 {
					padding = 0
				}
				fmt.Fprintf(os.Stderr, "%s%s%s%s\n", colorHighlight, row, strings.Repeat(" ", padding), colorReset)
			} else {
				fmt.Fprintf(os.Stderr, "%s%s\n", continuationPrefix, line)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s%s%s", colorDim, wizardReturnTipLine("Use Up/Down and Enter. "), colorReset)
}

// menuLabelWidth returns the label column width needed to keep menu descriptions
// aligned, including long rule names such as LIMIT_ENDPOINT_RATE.
func menuLabelWidth(items [][2]string, minimum ...int) int {
	width := 18
	if len(minimum) > 0 && minimum[0] >= 0 {
		width = minimum[0]
	}
	for _, item := range items {
		label, _ := menuDisplayTag(item[0])
		if w := displayWidth(label); w > width {
			width = w
		}
	}
	return width
}

// menuDescriptionLines keeps multi-line descriptions aligned under the
// description column without requiring each menu item to hard-code padding.
func menuDescriptionLines(description string, wrapWidth ...int) []string {
	if description == "" {
		return []string{""}
	}
	width := 0
	if len(wrapWidth) > 0 {
		width = wrapWidth[0]
	}
	trailingBlank := strings.HasSuffix(description, "\n")
	raw := strings.Split(strings.TrimRight(description, "\n"), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if width > 0 {
			wrapped := wrapConfirmText(line, width)
			if len(wrapped) > 0 {
				lines = append(lines, wrapped...)
				continue
			}
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	if trailingBlank {
		lines = append(lines, "")
	}
	return lines
}

func menuDescriptionWrapWidth(prefixWidth, bodyWidth int) int {
	width := bodyWidth - prefixWidth
	if width < 20 {
		return 20
	}
	return width
}

func menuBodyWidth() int {
	width := preferredMenuBodyWidth
	if columns := terminalColumns(os.Stderr); columns > 0 {
		width = min(width, columns-2)
	}
	if width < minMenuBodyWidth {
		return minMenuBodyWidth
	}
	return width
}

// menuDisplayTag splits a tag from its visual warning marker. A trailing "!"
// means the item needs attention. Tags may also use "choice|Label" to keep a
// stable dispatch value while rendering polished user-facing text.
func menuDisplayTag(tag string) (string, bool) {
	_, label, warning := menuTagParts(tag)
	return label, warning
}

func menuTagParts(tag string) (string, string, bool) {
	warning := false
	if strings.HasSuffix(tag, "!") {
		tag = strings.TrimSuffix(tag, "!")
		warning = true
	}
	choice := tag
	label := tag
	if left, right, ok := strings.Cut(tag, "|"); ok {
		choice = strings.TrimSpace(left)
		label = strings.TrimSpace(right)
		if choice == "" {
			choice = label
		}
		if label == "" {
			label = choice
		}
	}
	return choice, label, warning
}

// menuChoiceTag returns the dispatch value for a visual menu tag.
func menuChoiceTag(tag string) string {
	choice, _, _ := menuTagParts(tag)
	return choice
}

// readMenuKey translates raw terminal bytes into logical menu/navigation keys.
func readMenuKey(f *os.File) (string, error) {
	b, err := readRequiredByte(f)
	if err != nil {
		return "", err
	}
	switch b {
	case '\r', '\n':
		return "enter", nil
	case 'q', 'Q':
		return "q", nil
	case 0x03:
		return "interrupt", nil
	case 0x1b:
		first, ok, err := readOptionalByte(f)
		if err != nil {
			return "", err
		}
		if !ok {
			return "escape", nil
		}
		second, ok, err := readOptionalByte(f)
		if err != nil {
			return "", err
		}
		if ok && first == '[' {
			switch second {
			case 'A':
				return "up", nil
			case 'B':
				return "down", nil
			case 'H':
				return "home", nil
			case 'F':
				return "end", nil
			case '5', '6':
				if _, _, err := readOptionalByte(f); err != nil {
					return "", err
				}
				if second == '5' {
					return "pageup", nil
				}
				return "pagedown", nil
			}
		}
		return "escape", nil
	default:
		return string(b), nil
	}
}

// readRequiredByte blocks until exactly one byte can be read from the terminal.
func readRequiredByte(f *os.File) (byte, error) {
	var b [1]byte
	for {
		n, err := f.Read(b[:])
		if err != nil {
			if errors.Is(err, io.EOF) && isTerminal(f) {
				continue
			}
			return 0, err
		}
		if n == 1 {
			return b[0], nil
		}
	}
}

// readOptionalByte reads one byte when available and distinguishes EOF from an
// absent optional escape-sequence byte.
func readOptionalByte(f *os.File) (byte, bool, error) {
	var b [1]byte
	n, err := f.Read(b[:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, false, nil
		}
		return 0, false, err
	}
	if n != 1 {
		return 0, false, nil
	}
	return b[0], true, nil
}

// numericMenuChoice maps single-digit menu shortcuts to zero-based item indexes.
func numericMenuChoice(key string, count int) (int, bool) {
	if count > 9 {
		return 0, false
	}
	n, err := strconv.Atoi(key)
	if err != nil || n < 1 || n > count {
		return 0, false
	}
	return n - 1, true
}

// selectedIndex finds the starting index for a preselected menu tag.
func selectedIndex(items [][2]string, tag string) int {
	for i, item := range items {
		if menuChoiceTag(item[0]) == tag {
			return i
		}
	}
	return 0
}

// menuCancelChoice chooses the most context-appropriate return value for q or
// Escape.
func menuCancelChoice(items [][2]string) string {
	for _, item := range items {
		if menuChoiceTag(item[0]) == "back" {
			return "back"
		}
	}
	for _, item := range items {
		if menuChoiceTag(item[0]) == "cancel" {
			return "cancel"
		}
	}
	return "exit"
}

// numberedMenu is the portable fallback for terminals that cannot support raw
// arrow-key input.
func numberedMenu(title, prompt string, items [][2]string, minimumLabelWidth ...int) (string, error) {
	for {
		clearScreen()
		banner(os.Stderr, "/var/log/proxyble/")
		pageHeader(os.Stderr, title, prompt)
		bodyWidth := menuBodyWidth()
		labelWidth := menuLabelWidth(items, minimumLabelWidth...)
		descriptionPrefixWidth := labelWidth + 8
		descriptionWidth := menuDescriptionWrapWidth(descriptionPrefixWidth, bodyWidth)
		for i, item := range items {
			label, warning := menuDisplayTag(item[0])
			warningMarker := " "
			if warning {
				warningMarker = colorRed + "!" + colorReset
			}
			description := menuDescriptionLines(item[1], descriptionWidth)
			fmt.Fprintf(os.Stderr, "  %2d. %-*s%s %s\n", i+1, labelWidth, label, warningMarker, description[0])
			continuationPrefix := strings.Repeat(" ", descriptionPrefixWidth)
			for _, line := range description[1:] {
				if line == "" {
					fmt.Fprintln(os.Stderr)
					continue
				}
				fmt.Fprintf(os.Stderr, "%s%s\n", continuationPrefix, line)
			}
		}
		printWizardReturnTip(os.Stderr, "")
		fmt.Fprint(os.Stderr, "Select option: ")
		line, err := readWizardLine(os.Stdin)
		if errors.Is(err, errWizardBack) {
			clearScreen()
			return menuCancelChoice(items), nil
		}
		if err != nil && len(line) == 0 {
			return "", err
		}
		choice := strings.TrimSpace(line)
		if choice == "" {
			return "exit", nil
		}
		for i, item := range items {
			label, _ := menuDisplayTag(item[0])
			if strings.EqualFold(choice, menuChoiceTag(item[0])) || strings.EqualFold(choice, label) || choice == fmt.Sprint(i+1) {
				clearScreen()
				return menuChoiceTag(item[0]), nil
			}
		}
		fmt.Fprintf(os.Stderr, "[ERROR] Unknown selection: %s\n", choice)
		pause()
	}
}

// scrollableText opens long text such as the license and config file in a
// full-screen viewer with arrow/PageUp/PageDown navigation when available.
func scrollableText(title, prompt string, lines []string) error {
	if !supportsArrowMenu() {
		clearScreen()
		pageHeader(os.Stderr, title, prompt)
		for _, line := range lines {
			fmt.Fprintln(os.Stderr, line)
		}
		return waitForWizardReturn()
	}
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		clearScreen()
		pageHeader(os.Stderr, title, prompt)
		for _, line := range lines {
			fmt.Fprintln(os.Stderr, line)
		}
		return waitForWizardReturn()
	}
	defer restore()
	fmt.Fprint(os.Stderr, "\033[?25l")
	defer fmt.Fprint(os.Stderr, "\033[?25h")

	offset := 0
	for {
		contentRows := renderScrollableText(title, prompt, lines, offset)
		maxOffset := max(0, len(lines)-contentRows)
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			return err
		}
		switch key {
		case "up":
			offset = max(0, offset-1)
		case "down":
			offset = min(maxOffset, offset+1)
		case "pageup":
			offset = max(0, offset-contentRows)
		case "pagedown":
			offset = min(maxOffset, offset+contentRows)
		case "home":
			offset = 0
		case "end":
			offset = maxOffset
		case "enter", "escape", "q":
			clearScreen()
			return nil
		case "interrupt":
			handleInterruptRequest()
		}
	}
}

// scrollableTextRequiredEnd does not return until the operator reaches the end
// of the text. It is used for the license acceptance flow.
func scrollableTextRequiredEnd(title, prompt string, lines []string) error {
	if !supportsArrowMenu() {
		clearScreen()
		pageHeader(os.Stderr, title, prompt)
		for _, line := range lines {
			fmt.Fprintln(os.Stderr, line)
		}
		return waitForWizardReturn()
	}
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		clearScreen()
		pageHeader(os.Stderr, title, prompt)
		for _, line := range lines {
			fmt.Fprintln(os.Stderr, line)
		}
		return waitForWizardReturn()
	}
	defer restore()
	fmt.Fprint(os.Stderr, "\033[?25l")
	defer fmt.Fprint(os.Stderr, "\033[?25h")

	offset := 0
	for {
		contentRows := renderScrollableTextRequiredEnd(title, prompt, lines, offset)
		maxOffset := max(0, len(lines)-contentRows)
		atEnd := offset >= maxOffset
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			return err
		}
		switch key {
		case "up":
			offset = max(0, offset-1)
		case "down":
			offset = min(maxOffset, offset+1)
		case "pageup":
			offset = max(0, offset-contentRows)
		case "pagedown":
			offset = min(maxOffset, offset+contentRows)
		case "home":
			offset = 0
		case "end":
			offset = maxOffset
		case "escape", "q":
			clearScreen()
			return errWizardBack
		case "enter":
			if atEnd {
				clearScreen()
				return nil
			}
		case "interrupt":
			handleInterruptRequest()
		}
	}
}

// renderScrollableText draws one page of a long text viewer and returns the
// number of content rows available for scrolling math.
func renderScrollableText(title, prompt string, lines []string, offset int) int {
	clearScreen()
	pageHeader(os.Stderr, title, prompt)
	contentRows := terminalRows() - 7
	if contentRows < 8 {
		contentRows = 8
	}
	if offset > len(lines) {
		offset = len(lines)
	}
	end := min(len(lines), offset+contentRows)
	for i := offset; i < end; i++ {
		fmt.Fprintln(os.Stderr, lines[i])
	}
	for i := end - offset; i < contentRows; i++ {
		fmt.Fprintln(os.Stderr)
	}
	total := len(lines)
	if total == 0 {
		total = 1
	}
	from := min(offset+1, total)
	to := min(end, total)
	prefix := fmt.Sprintf("Showing lines %d-%d of %d. Use Up/Down or PageUp/PageDown. ", from, to, len(lines))
	fmt.Fprintf(os.Stderr, "\n%s%s%s", colorDim, wizardReturnTipLine(prefix), colorReset)
	return contentRows
}

func renderScrollableTextRequiredEnd(title, prompt string, lines []string, offset int) int {
	contentRows := renderScrollableText(title, prompt, lines, offset)
	maxOffset := max(0, len(lines)-contentRows)
	if offset >= maxOffset {
		fmt.Fprintf(os.Stderr, "\r\033[2K%s%s%s", colorDim, wizardReturnTipLine("End of license. Press Enter to continue. "), colorReset)
	} else {
		fmt.Fprintf(os.Stderr, "\r\033[2K%s%s%s", colorDim, wizardReturnTipLine("Showing license lines. Scroll to the end to continue. "), colorReset)
	}
	return contentRows
}

// terminalRows returns the terminal height from LINES or a conservative default.
func terminalRows() int {
	if v := strings.TrimSpace(os.Getenv("LINES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 12 {
			return n
		}
	}
	return 24
}

// min returns the smaller integer.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the larger integer.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// pause waits for ESC (or the legacy Enter/q shortcuts) so users can read
// action results before returning to the previous menu.
func pause() {
	_ = waitForWizardReturn()
}

func waitForWizardReturn() error {
	if !isTerminal(os.Stdin) {
		return nil
	}
	printWizardReturnTip(os.Stderr, "")
	restore, err := makeTerminalRaw(os.Stdin)
	if err != nil {
		line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.ContainsRune(line, '\x1b') {
			return errWizardBack
		}
		return readErr
	}
	defer restore()
	for {
		key, err := readMenuKey(os.Stdin)
		if err != nil {
			return err
		}
		switch key {
		case "escape":
			fmt.Fprintln(os.Stderr)
			return errWizardBack
		case "enter", "q":
			fmt.Fprintln(os.Stderr)
			return nil
		case "interrupt":
			handleInterruptRequest()
		}
	}
}

func pauseAnyKeyExit() {
	if !isTerminal(os.Stdin) {
		return
	}
	fmt.Fprint(os.Stderr, "\n"+uninstallExitPrompt())
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

func uninstallExitPrompt() string {
	return "Press any key to exit."
}

// clearScreen clears the terminal when stdout or stderr is interactive.
func clearScreen() {
	if isTerminal(os.Stdout) || isTerminal(os.Stderr) {
		fmt.Fprint(os.Stderr, "\033[H\033[2J")
	}
}
