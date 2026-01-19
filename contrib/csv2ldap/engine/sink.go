// Copyright (C) 2024 Christian Rößner
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

package engine

import (
	"bufio"
	"os"
)

// LDIFFileSink writes LDIF entries to a file using a buffered writer.
type LDIFFileSink struct {
	f *os.File
	w *bufio.Writer
}

// NewLDIFFileSink creates or truncates the output file.
func NewLDIFFileSink(outPath string) (*LDIFFileSink, error) {
	f, err := os.Create(outPath)
	if err != nil {
		return nil, err
	}

	return &LDIFFileSink{f: f, w: bufio.NewWriter(f)}, nil
}

// WriteEntry writes a single LDIF entry as-is.
func (s *LDIFFileSink) WriteEntry(entry string) error {
	if _, err := s.w.WriteString(entry); err != nil {
		return err
	}

	return nil
}

// Close flushes and closes the underlying file.
func (s *LDIFFileSink) Close() error {
	if s.w != nil {
		_ = s.w.Flush()
	}

	if s.f != nil {
		return s.f.Close()
	}

	return nil
}
