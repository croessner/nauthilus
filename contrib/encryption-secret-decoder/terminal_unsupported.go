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

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package main

import (
	"errors"
	"os"
)

// isTerminal reports unsupported terminal handling on non-Unix platforms.
func isTerminal(_ *os.File) bool {
	return false
}

// enableRawTerminal rejects masked input when terminal control is unavailable.
func enableRawTerminal(_ *os.File) error {
	return errors.New("masked terminal input is unsupported on this platform")
}

// restoreTerminal is a no-op when terminal control is unavailable.
func restoreTerminal(_ *os.File) {}
