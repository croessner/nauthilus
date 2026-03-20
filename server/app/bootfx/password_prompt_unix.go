//go:build unix

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

package bootfx

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"golang.org/x/sys/unix"
)

func readPasswordPrompt(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !isatty.IsTerminal(uintptr(fd)) {
		return nil, fmt.Errorf("stdin is not a terminal")
	}

	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, err
	}

	termState, err := unix.IoctlGetTermios(fd, passwordPromptReadTermiosRequest)
	if err != nil {
		return nil, err
	}

	updatedState := *termState
	updatedState.Lflag &^= unix.ECHO

	if err = unix.IoctlSetTermios(fd, passwordPromptWriteTermiosRequest, &updatedState); err != nil {
		return nil, err
	}

	restoreErr := error(nil)
	defer func() {
		if err := unix.IoctlSetTermios(fd, passwordPromptWriteTermiosRequest, termState); err != nil && restoreErr == nil {
			restoreErr = err
		}
	}()

	rawPassword, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if _, printErr := fmt.Fprintln(os.Stderr); printErr != nil && err == nil {
		err = printErr
	}

	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimRight(string(rawPassword), "\r\n")
	clear(rawPassword)

	if restoreErr != nil {
		return nil, restoreErr
	}

	return []byte(trimmed), nil
}
