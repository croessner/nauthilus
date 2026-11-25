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

package supportops

import "github.com/croessner/nauthilus/v4/server/supportaccess"

// ErrorCode is a stable error code of the diagnostics service (shared support error type).
type ErrorCode = supportaccess.ErrorCode

// Error is a diagnostics service error (shared support error type).
type Error = supportaccess.Error

const (
	// CodeInvalidRequest marks a malformed or inconsistent request.
	CodeInvalidRequest ErrorCode = "INVALID_REQUEST"

	// CodeWindowTooLarge marks a time window above the service maximum.
	CodeWindowTooLarge ErrorCode = "WINDOW_TOO_LARGE"

	// CodeInvalidCursor marks a page cursor that is malformed or belongs to another query.
	CodeInvalidCursor ErrorCode = "INVALID_CURSOR"

	// CodeForbidden marks a caller without the operations permission.
	CodeForbidden ErrorCode = "FORBIDDEN"

	// CodeBusy marks a rejected call because the concurrency gate is full.
	CodeBusy ErrorCode = "OPERATIONS_BUSY"

	// CodeNotConfigured marks a host without the diagnostics service.
	CodeNotConfigured ErrorCode = "OPERATIONS_NOT_CONFIGURED"

	// CodeInternal marks an unexpected service failure.
	CodeInternal ErrorCode = "INTERNAL_ERROR"
)

// errorMessages holds the only texts ever returned with an error.
var errorMessages = map[ErrorCode]string{
	CodeInvalidRequest: "The request is malformed or inconsistent.",
	CodeWindowTooLarge: "The time window exceeds the maximum of 24 hours.",
	CodeInvalidCursor:  "The page cursor is malformed or belongs to another query.",
	CodeForbidden:      "The caller lacks the required operations permission.",
	CodeBusy:           "Too many diagnostics calls are running; retry later.",
	CodeNotConfigured:  "Operational diagnostics are not configured on this instance.",
	CodeInternal:       "The diagnostics call failed unexpectedly.",
}

// ErrorMessage returns the fixed public text of a diagnostics code.
func ErrorMessage(code ErrorCode) string {
	if message, ok := errorMessages[code]; ok {
		return message
	}

	return errorMessages[CodeInternal]
}

// newError wraps an internal cause under a stable code without publishing the cause.
func newError(code ErrorCode, cause error) *Error {
	return supportaccess.NewError(code, ErrorMessage(code), cause)
}

// AsError returns the service error carried by err, mapping anything else to an internal error.
func AsError(err error) *Error {
	return supportaccess.AsError(err, func(cause error) *Error { return newError(CodeInternal, cause) })
}
