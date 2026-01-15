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

// Record represents one logical login record parsed from CSV.
type Record struct {
	Username   string
	Password   string
	Protocol   string
	ExpectedOK bool
}

// RecordSource yields records sequentially and must be closed when done.
type RecordSource interface {
	Next() (*Record, error) // returns io.EOF when exhausted
	Close() error
}

// RecordFilter decides whether a record should be processed.
type RecordFilter interface {
	Allow(r *Record) bool
}

// Renderer produces an LDIF entry text for a record.
type Renderer interface {
	Render(r *Record) (string, error)
}

// Sink consumes rendered entries.
type Sink interface {
	WriteEntry(entry string) error
	Close() error
}
