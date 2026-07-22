//go:build linux

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

// terminal_raw_linux.go contains the Linux raw-terminal implementation used by
// arrow-key menus and scrollable viewers. It is intentionally small and uses the
// standard library syscall package so the binary stays dependency-light for
// minimal distributions.

import (
	"os"
	"syscall"
	"unsafe"
)

// makeTerminalRaw disables canonical input, echo, and terminal-generated signals
// for one terminal file, then returns a restore function that must be deferred by
// the caller. Disabling ISIG lets raw UI screens handle Ctrl+C themselves. A
// short read timeout lets a lone ESC byte be distinguished from an arrow-key
// escape sequence without waiting for another keypress.
func makeTerminalRaw(f *os.File) (func(), error) {
	fd := f.Fd()
	var oldState syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&oldState))); errno != 0 {
		return nil, errno
	}
	newState := oldState
	newState.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG
	newState.Cc[syscall.VMIN] = 0
	newState.Cc[syscall.VTIME] = 1
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&newState))); errno != 0 {
		return nil, errno
	}
	return func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&oldState)))
	}, nil
}

func terminalColumns(f *os.File) int {
	var size struct {
		rows uint16
		cols uint16
		x    uint16
		y    uint16
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&size))); errno != 0 {
		return 0
	}
	return int(size.cols)
}
