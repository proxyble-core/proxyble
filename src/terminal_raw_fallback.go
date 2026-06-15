//go:build !linux

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
