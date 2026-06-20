package engine

import (
	"encoding/csv"
	"io"
	"math/rand/v2"
	"os"
	"strings"
)

// CSVSource describes the exported CSVSource type.
type CSVSource struct {
	rows    []Row
	current int
}

// NewCSVSource provides the exported NewCSVSource function.
func NewCSVSource(path string, delim rune, maxRows int, shuffle bool) (*CSVSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	reader := newCSVReader(f, delim)

	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	rows, err := readCSVRows(reader, header, maxRows)
	if err != nil {
		return nil, err
	}

	if shuffle {
		shuffleRows(rows)
	}

	return &CSVSource{rows: rows}, nil
}

// newCSVReader creates a CSV reader with the requested delimiter override.
func newCSVReader(reader io.Reader, delim rune) *csv.Reader {
	csvReader := csv.NewReader(reader)
	if delim != 0 {
		csvReader.Comma = delim
	}

	return csvReader
}

// readCSVRows consumes records until EOF or the configured row limit.
func readCSVRows(reader *csv.Reader, header []string, maxRows int) ([]Row, error) {
	var rows []Row

	for {
		row, ok, err := readCSVRow(reader, header)
		if err != nil {
			return nil, err
		}

		if !ok {
			return rows, nil
		}

		rows = append(rows, row)
		if maxRows > 0 && len(rows) >= maxRows {
			return rows, nil
		}
	}
}

// readCSVRow converts one CSV record into a Row and reports EOF separately.
func readCSVRow(reader *csv.Reader, header []string) (Row, bool, error) {
	record, err := reader.Read()
	if err == io.EOF {
		return Row{}, false, nil
	}

	if err != nil {
		return Row{}, false, err
	}

	return rowFromCSVRecord(header, record), true, nil
}

// rowFromCSVRecord maps a CSV record onto the engine Row structure.
func rowFromCSVRecord(header []string, record []string) Row {
	fields := fieldsFromCSVRecord(header, record)

	return Row{
		Username:  resolveUsername(fields),
		Password:  fields[csvFieldPassword],
		IP:        fields["ip"],
		ExpectOK:  expectedOKFromFields(fields),
		RawFields: fields,
	}
}

// fieldsFromCSVRecord builds a header-keyed field map from a CSV record.
func fieldsFromCSVRecord(header []string, record []string) map[string]string {
	fields := make(map[string]string)

	for i, h := range header {
		if i < len(record) {
			fields[h] = record[i]
		}
	}

	return fields
}

// expectedOKFromFields returns the expected authentication result encoded by the CSV row.
func expectedOKFromFields(fields map[string]string) bool {
	val, ok := fields[csvFieldExpectedOK]
	if !ok {
		return true
	}

	return strings.ToLower(val) == csvValueTrue || val == "1"
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

// shuffleRows randomizes rows in place before the source is exposed.
func shuffleRows(rows []Row) {
	rand.Shuffle(len(rows), func(i, j int) {
		rows[i], rows[j] = rows[j], rows[i]
	})
}

// Next provides the exported Next method.
func (s *CSVSource) Next() (Row, bool) {
	if s.current >= len(s.rows) {
		return Row{}, false
	}

	row := s.rows[s.current]
	s.current++

	return row, true
}

// Reset provides the exported Reset method.
func (s *CSVSource) Reset() {
	s.current = 0
}

// Total provides the exported Total method.
func (s *CSVSource) Total() int {
	return len(s.rows)
}
