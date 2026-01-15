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
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

// CSVSource implements RecordSource backed by a CSV file.
type CSVSource struct {
	f   *os.File
	r   *csv.Reader
	idx map[string]int // lower-cased header -> column index
	cfg Config
}

// NewCSVSource opens the CSV and prepares header index mapping.
func NewCSVSource(cfg Config) (*CSVSource, error) {
	f, err := os.Open(cfg.InCSVPath)
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(bufio.NewReader(f))
	r.FieldsPerRecord = -1 // allow variable fields
	r.LazyQuotes = true

	header, err := r.Read()
	if err != nil {
		_ = f.Close()

		return nil, err
	}

	idx := map[string]int{}
	for i, h := range header {
		k := strings.ToLower(strings.TrimSpace(h))
		if _, exists := idx[k]; !exists {
			idx[k] = i
		}
	}

	must := []string{cfg.ColUsername, cfg.ColPassword, cfg.ColProtocol, cfg.ColExpectedOK}
	for _, m := range must {
		if _, ok := idx[strings.ToLower(m)]; !ok {
			_ = f.Close()

			return nil, fmt.Errorf("missing column %q", m)
		}
	}

	return &CSVSource{f: f, r: r, idx: idx, cfg: cfg}, nil
}

// Next returns the next record; it propagates io.EOF when done.
func (c *CSVSource) Next() (*Record, error) {
	row, err := c.r.Read()
	if err != nil {
		return nil, err
	}

	get := func(col string) string {
		i := c.idx[strings.ToLower(col)]
		if i < 0 || i >= len(row) {
			return ""
		}

		return strings.TrimSpace(row[i])
	}

	rec := &Record{
		Username:   get(c.cfg.ColUsername),
		Password:   get(c.cfg.ColPassword),
		Protocol:   strings.ToLower(get(c.cfg.ColProtocol)),
		ExpectedOK: strings.EqualFold(strings.TrimSpace(get(c.cfg.ColExpectedOK)), c.cfg.ExpectTrueValue),
	}

	return rec, nil
}

// Close releases file resources.
func (c *CSVSource) Close() error {
	return c.f.Close()
}
