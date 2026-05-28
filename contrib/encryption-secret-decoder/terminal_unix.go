// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var terminalStates sync.Map

// isTerminal reports whether file supports terminal mode operations.
func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}

	_, err := getTerminalState(file)

	return err == nil
}

// enableRawTerminal switches the terminal into a byte-oriented masked-input mode.
func enableRawTerminal(file *os.File) error {
	state, err := getTerminalState(file)
	if err != nil {
		return err
	}

	fd := int(file.Fd())
	raw := *state
	raw.Lflag &^= unix.ECHO | unix.ICANON
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0

	if err := setTerminalState(fd, &raw); err != nil {
		return err
	}

	terminalStates.Store(fd, state)

	return nil
}

// restoreTerminal restores a terminal state saved before masked input.
func restoreTerminal(file *os.File) {
	if file == nil {
		return
	}

	fd := int(file.Fd())

	state, ok := terminalStates.LoadAndDelete(fd)
	if !ok {
		return
	}

	if termios, ok := state.(*unix.Termios); ok {
		_ = setTerminalState(fd, termios)
	}
}

// getTerminalState reads the current terminal attributes.
func getTerminalState(file *os.File) (*unix.Termios, error) {
	return unix.IoctlGetTermios(int(file.Fd()), ioctlGetTermios)
}

// setTerminalState writes terminal attributes back to the file descriptor.
func setTerminalState(fd int, state *unix.Termios) error {
	return unix.IoctlSetTermios(fd, ioctlSetTermios, state)
}
