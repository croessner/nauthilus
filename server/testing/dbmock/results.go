// Copyright (C) 2026 Christian Roessner
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

package dbmock

// ExecResult represents an exec operation result.
type ExecResult struct {
	RowsAffected int64
	LastInsertID int64
}

// Rows is a simple query result container for tests.
type Rows struct {
	Columns []string
	Data    [][]any
}

// NewRows initializes rows with a fixed column list.
func NewRows(columns ...string) Rows {
	copiedColumns := make([]string, len(columns))
	copy(copiedColumns, columns)

	return Rows{
		Columns: copiedColumns,
		Data:    make([][]any, 0),
	}
}

// AddRow appends a row and returns the updated Rows value.
func (r Rows) AddRow(values ...any) Rows {
	row := make([]any, len(values))
	copy(row, values)
	r.Data = append(r.Data, row)

	return r
}

// Clone returns a deep copy safe for test assertions.
func (r Rows) Clone() Rows {
	columns := make([]string, len(r.Columns))
	copy(columns, r.Columns)

	data := make([][]any, len(r.Data))
	for i := range r.Data {
		row := make([]any, len(r.Data[i]))
		copy(row, r.Data[i])
		data[i] = row
	}

	return Rows{
		Columns: columns,
		Data:    data,
	}
}
