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

import "errors"

var (
	ErrUnexpectedCall             = errors.New("unexpected call")
	ErrKindMismatch               = errors.New("call kind mismatch")
	ErrPreparedModeMismatch       = errors.New("prepared mode mismatch")
	ErrSQLMismatch                = errors.New("sql mismatch")
	ErrArgCountMismatch           = errors.New("argument count mismatch")
	ErrArgMismatch                = errors.New("argument mismatch")
	ErrPlaceholderCountMismatch   = errors.New("placeholder count mismatch")
	ErrExpectationAlreadyConsumed = errors.New("expectation already consumed")
	ErrEmptyExpectationQueue      = errors.New("expectation queue is empty")
	ErrStatementClosed            = errors.New("statement is closed")
	ErrTransactionDone            = errors.New("transaction is already finalized")
)
