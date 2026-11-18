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

package supportaccess

import "errors"

// ErrorCode is a stable, transport-independent error code of a support service.
type ErrorCode string

// Error is a support service error with a stable code and a fixed public message. The internal cause is kept for
// host-side logging only and never reaches a caller.
type Error struct {
	cause   error
	Code    ErrorCode
	message string
}

// NewError wraps an internal cause under a stable code and its fixed public message.
func NewError(code ErrorCode, message string, cause error) *Error {
	return &Error{Code: code, message: message, cause: cause}
}

// Error returns the fixed public message.
func (e *Error) Error() string {
	return e.Message()
}

// Message returns the fixed public text of the code.
func (e *Error) Message() string {
	if e == nil {
		return ""
	}

	return e.message
}

// Unwrap exposes the internal cause for logging inside the host only.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// AsError returns the support service error carried by err, or wraps err with fallback, which supplies the service's
// internal-error code and message.
func AsError(err error, fallback func(cause error) *Error) *Error {
	var serviceErr *Error
	if errors.As(err, &serviceErr) {
		return serviceErr
	}

	return fallback(err)
}
