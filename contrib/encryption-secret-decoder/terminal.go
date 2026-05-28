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

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var errPromptInterrupted = errors.New("secret prompt interrupted")

// openSecretTerminal returns a terminal suitable for hidden secret input.
func openSecretTerminal(stdin *os.File) (*os.File, bool, error) {
	if stdin != nil && isTerminal(stdin) {
		return stdin, false, nil
	}

	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, false, fmt.Errorf("open /dev/tty for secret prompt: %w", err)
	}

	if !isTerminal(terminal) {
		_ = terminal.Close()

		return nil, false, errors.New("/dev/tty is not a terminal")
	}

	return terminal, true, nil
}

// readMaskedLine reads one terminal line while masking each byte with an asterisk.
func readMaskedLine(input *os.File, output io.Writer, prompt string) ([]byte, error) {
	if err := enableRawTerminal(input); err != nil {
		return nil, err
	}
	defer restoreTerminal(input)

	if _, err := fmt.Fprint(output, prompt); err != nil {
		return nil, err
	}

	value, err := readMaskedBytes(input, output)
	if err != nil {
		return nil, err
	}

	if _, err := fmt.Fprintln(output); err != nil {
		return nil, err
	}

	return value, nil
}

// readMaskedBytes consumes raw terminal bytes until enter, EOF, or interruption.
func readMaskedBytes(input *os.File, output io.Writer) ([]byte, error) {
	var value []byte

	buffer := make([]byte, 1)

	for {
		n, err := input.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) && len(value) > 0 {
				return value, nil
			}

			return nil, err
		}

		if n == 0 {
			continue
		}

		done, err := handleMaskedByte(&value, buffer[0], output)
		if err != nil {
			return nil, err
		}

		if done {
			return value, nil
		}
	}
}

// handleMaskedByte updates the buffered value for one raw terminal byte.
func handleMaskedByte(value *[]byte, next byte, output io.Writer) (bool, error) {
	switch next {
	case '\r', '\n':
		return true, nil
	case 0x03:
		return false, errPromptInterrupted
	case 0x04:
		return true, nil
	case 0x7f, '\b':
		eraseMaskedByte(value, output)

		return false, nil
	default:
		*value = append(*value, next)
		_, err := fmt.Fprint(output, "*")

		return false, err
	}
}

// eraseMaskedByte removes one buffered byte and erases one displayed asterisk.
func eraseMaskedByte(value *[]byte, output io.Writer) {
	if len(*value) == 0 {
		return
	}

	*value = (*value)[:len(*value)-1]
	_, _ = fmt.Fprint(output, "\b \b")
}

// readPlainLine reads one line from a terminal input while leaving echo unchanged.
func readPlainLine(input *os.File) ([]byte, error) {
	var value []byte

	buffer := make([]byte, 1)

	for {
		n, err := input.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) && len(value) > 0 {
				return value, nil
			}

			return nil, err
		}

		if n == 0 {
			continue
		}

		if buffer[0] == '\r' || buffer[0] == '\n' {
			return value, nil
		}

		value = append(value, buffer[0])
	}
}
