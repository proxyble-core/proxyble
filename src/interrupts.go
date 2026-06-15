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

// interrupts.go implements Proxyble's guarded Ctrl+C behavior. The legacy bash
// wizard did not exit immediately on the first accidental Ctrl+C; it asked the
// user whether to quit and warned that a second Ctrl+C forces exit. This file
// keeps that behavior for cooked prompts and exposes a shared handler for raw
// arrow-key screens that receive Ctrl+C as a byte.

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
)

// installInterruptHandler catches Ctrl+C while the program is in ordinary
// cooked-terminal reads. Raw menus handle Ctrl+C through handleInterruptRequest.
func installInterruptHandler(silent bool) func() {
	if silent || !isTerminal(os.Stdin) || !isTerminal(os.Stderr) {
		return func() {}
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigCh:
				signal.Reset(os.Interrupt)
				if confirmInterruptExit() {
					exitFromInterrupt(false)
				}
				signal.Notify(sigCh, os.Interrupt)
			}
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}

// handleInterruptRequest is called by raw-key UI loops when Ctrl+C is read as
// byte 0x03 instead of delivered as a process signal.
func handleInterruptRequest() {
	if confirmInterruptExit() {
		exitFromInterrupt(false)
	}
}

// confirmInterruptExit prompts after the first Ctrl+C and returns true only when
// the user explicitly chooses to exit.
func confirmInterruptExit() bool {
	fmt.Fprintln(os.Stderr)
	for {
		fmt.Fprint(os.Stderr, interruptExitPrompt())
		reply, err := readInterruptReply()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return false
		}
		switch interruptReplyAction(reply) {
		case "force":
			exitFromInterrupt(true)
		case "exit":
			return true
		case "continue":
			return false
		default:
			fmt.Fprintln(os.Stderr, "[NOTICE] Please answer y or n.")
		}
	}
}

func interruptExitPrompt() string {
	return "[NOTICE] Exit Proxyble? Press y to exit, n to continue. Ctrl+C again forces exit. [y/N] "
}

func interruptReplyAction(reply string) string {
	trimmed := strings.TrimSpace(reply)
	if trimmed == string([]byte{0x03}) {
		return "force"
	}
	switch strings.ToLower(trimmed) {
	case "y", "yes":
		return "exit"
	case "", "n", "no":
		return "continue"
	default:
		return "invalid"
	}
}

// readInterruptReply reads one response, using raw mode when possible so
// the prompt behaves like the bash read -n 1 trap.
func readInterruptReply() (string, error) {
	if isTerminal(os.Stdin) {
		restore, err := makeTerminalRaw(os.Stdin)
		if err == nil {
			defer restore()
			b, err := readRequiredByte(os.Stdin)
			if err != nil {
				return "", err
			}
			return string([]byte{b}), nil
		}
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return line, nil
}

// exitFromInterrupt prints the final notice and exits with the conventional
// SIGINT status code.
func exitFromInterrupt(forced bool) {
	if forced {
		fmt.Fprintln(os.Stderr, "[NOTICE] Forced exit requested. Exiting Proxyble.")
	} else {
		fmt.Fprintln(os.Stderr, "[NOTICE] Exiting Proxyble.")
	}
	os.Exit(130)
}
