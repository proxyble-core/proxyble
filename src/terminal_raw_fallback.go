//go:build !linux

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

// terminal_raw_fallback.go keeps non-Linux builds compiling while making it
// explicit that raw arrow-key menus are not available until a platform-specific
// implementation is added.

import (
	"errors"
	"os"
)

// makeTerminalRaw reports that this platform does not yet implement raw terminal
// input; callers fall back to numbered menus where possible.
func makeTerminalRaw(f *os.File) (func(), error) {
	return nil, errors.New("raw terminal mode is not implemented for this platform")
}

func terminalColumns(f *os.File) int {
	return 0
}
