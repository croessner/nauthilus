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

package supporthistory

import "errors"

// ErrorCode is a stable, transport-independent error code of the history service.
type ErrorCode string

const (
	// CodeInvalidRequest marks a malformed or inconsistent request.
	CodeInvalidRequest ErrorCode = "INVALID_REQUEST"

	// CodeWindowTooLarge marks a time window above the shared maximum.
	CodeWindowTooLarge ErrorCode = "WINDOW_TOO_LARGE"

	// CodeInvalidCursor marks a cursor that is malformed or bound to another filter.
	CodeInvalidCursor ErrorCode = "INVALID_CURSOR"

	// CodeInvalidAttemptID marks a malformed diagnostic attempt id.
	CodeInvalidAttemptID ErrorCode = "INVALID_ATTEMPT_ID"

	// CodeForbidden marks a caller without the required history permission.
	CodeForbidden ErrorCode = "FORBIDDEN"

	// CodeQueryTooBroad marks a read that exceeded the server-side budget; narrow the window or add filters.
	CodeQueryTooBroad ErrorCode = "QUERY_TOO_BROAD"

	// CodeBusy marks a rejected call because the shared concurrency gate is full.
	CodeBusy ErrorCode = "HISTORY_BUSY"

	// CodeNotConfigured marks a host without a configured ClickHouse history source.
	CodeNotConfigured ErrorCode = "HISTORY_NOT_CONFIGURED"

	// CodeSourceUnavailable marks a failed or incomplete read of the primary history source.
	CodeSourceUnavailable ErrorCode = "HISTORY_SOURCE_UNAVAILABLE"

	// CodeReaderUnsafe marks a reader account that is writable or does not enforce the read budget.
	CodeReaderUnsafe ErrorCode = "HISTORY_READER_UNSAFE"

	// CodeTimeout marks an operation that exceeded the shared time budget.
	CodeTimeout ErrorCode = "HISTORY_TIMEOUT"

	// CodeInternal marks an unexpected service failure.
	CodeInternal ErrorCode = "INTERNAL_ERROR"
)

// errorMessages holds the only texts ever returned with an error; internal causes are never published.
var errorMessages = map[ErrorCode]string{
	CodeInvalidRequest:    "The request is malformed or inconsistent.",
	CodeWindowTooLarge:    "The time window exceeds the maximum of 31 days.",
	CodeInvalidCursor:     "The cursor is malformed or belongs to another query.",
	CodeInvalidAttemptID:  "The attempt id is malformed.",
	CodeForbidden:         "The caller lacks the required history permission.",
	CodeQueryTooBroad:     "The query exceeded the read budget; narrow the time window or add filters.",
	CodeBusy:              "Too many history queries are running; retry later.",
	CodeNotConfigured:     "No history source is configured on this instance.",
	CodeSourceUnavailable: "The history source could not be read completely.",
	CodeReaderUnsafe:      "The history reader account is not read-only or does not enforce read budgets.",
	CodeTimeout:           "The history query exceeded its time budget.",
	CodeInternal:          "The history query failed unexpectedly.",
}

// Error is a service error with a stable code and a fixed message.
type Error struct {
	cause error
	Code  ErrorCode
}

// newError wraps an internal cause under a stable code without publishing the cause.
func newError(code ErrorCode, cause error) *Error {
	return &Error{Code: code, cause: cause}
}

// Error returns the fixed message of the code.
func (e *Error) Error() string {
	return e.Message()
}

// Message returns the fixed public text of the code.
func (e *Error) Message() string {
	if message, ok := errorMessages[e.Code]; ok {
		return message
	}

	return errorMessages[CodeInternal]
}

// Unwrap exposes the internal cause for logging inside the host only.
func (e *Error) Unwrap() error {
	return e.cause
}

// AsError returns the service error carried by err, mapping anything else to an internal error.
func AsError(err error) *Error {
	var serviceErr *Error
	if errors.As(err, &serviceErr) {
		return serviceErr
	}

	return newError(CodeInternal, err)
}
