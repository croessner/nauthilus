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

import "time"

// CallKind identifies the database operation class.
type CallKind string

const (
	// CallExec is an exported package constant.
	CallExec CallKind = "exec"
	// CallQuery is an exported package constant.
	CallQuery = "query"
	// CallPrepare identifies a prepared statement operation.
	CallPrepare CallKind = "prepare"
	// CallBegin identifies a transaction begin operation.
	CallBegin CallKind = "begin"
	// CallCommit identifies a transaction commit operation.
	CallCommit CallKind = "commit"
	// CallRollback identifies a transaction rollback operation.
	CallRollback CallKind = "rollback"
)

// Call is a normalized representation of an intercepted DB operation.
type Call struct {
	Kind      CallKind
	Prepared  bool
	Query     string
	Args      []any
	Timestamp time.Time
}

// NewCall builds a Call with copied args and an initialized timestamp.
func NewCall(kind CallKind, query string, args ...any) Call {
	callArgs := make([]any, len(args))
	copy(callArgs, args)

	return Call{
		Kind:      kind,
		Prepared:  false,
		Query:     query,
		Args:      callArgs,
		Timestamp: time.Now().UTC(),
	}
}

// NewPreparedCall builds a Call for a prepared statement operation.
func NewPreparedCall(kind CallKind, query string, args ...any) Call {
	call := NewCall(kind, query, args...)
	call.Prepared = true

	return call
}
