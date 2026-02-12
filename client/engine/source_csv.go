package engine

import (
	"encoding/csv"
	"io"
	"math/rand/v2"
	"os"
	"strings"
)

type CSVSource struct {
	rows    []Row
	current int
}

func NewCSVSource(path string, delim rune, maxRows int, shuffle bool) (*CSVSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	if delim != 0 {
		reader.Comma = delim
	} else {
		// Auto-detect delimiter logic from main.go if needed, or just use default
		// For now, let's keep it simple or copy from main.go
	}

	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	var rows []Row
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		fields := make(map[string]string)
		for i, h := range header {
			if i < len(record) {
				fields[h] = record[i]
			}
		}

		row := Row{
			Username:  resolveUsername(fields),
			Password:  fields["password"],
			IP:        fields["ip"],
			RawFields: fields,
		}
		if val, ok := fields["expected_ok"]; ok {
			row.ExpectOK = strings.ToLower(val) == "true" || val == "1"
		} else {
			row.ExpectOK = true // Default
		}

		rows = append(rows, row)
		if maxRows > 0 && len(rows) >= maxRows {
			break
		}
	}

	if shuffle {
		rand.Shuffle(len(rows), func(i, j int) {
			rows[i], rows[j] = rows[j], rows[i]
		})
	}

	return &CSVSource{rows: rows}, nil
}

func resolveUsername(fields map[string]string) string {
	if u, ok := fields["username"]; ok && u != "" {
		return u
	}
	if u, ok := fields["user"]; ok && u != "" {
		return u
	}
	if u, ok := fields["login"]; ok && u != "" {
		return u
	}
	return ""
}

func (s *CSVSource) Next() (Row, bool) {
	if s.current >= len(s.rows) {
		return Row{}, false
	}
	row := s.rows[s.current]
	s.current++
	return row, true
}

func (s *CSVSource) Reset() {
	s.current = 0
}

func (s *CSVSource) Total() int {
	return len(s.rows)
}
