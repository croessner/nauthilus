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

package errors

import "errors"

// ErrTokenValidationUnavailable reports that a token could not be validated
// because authoritative token state or signing key material was unreachable.
//
// It is never a verdict about the token. Callers must answer with a temporary
// failure and must not count it as a failed caller authentication: counting it
// would lock out every caller that shares the source address as soon as the
// token store degrades.
var ErrTokenValidationUnavailable = errors.New("token validation unavailable")

// tokenValidationUnavailableError keeps the technical cause reachable for
// errors.Is and errors.As while classifying the whole chain as unavailable.
type tokenValidationUnavailableError struct {
	cause error
}

// Error renders the classification followed by the technical cause.
func (e *tokenValidationUnavailableError) Error() string {
	return ErrTokenValidationUnavailable.Error() + ": " + e.cause.Error()
}

// Unwrap exposes both the classification sentinel and the technical cause.
func (e *tokenValidationUnavailableError) Unwrap() []error {
	return []error{ErrTokenValidationUnavailable, e.cause}
}

// NewTokenValidationUnavailable marks cause as a technical token validation
// failure. It returns nil for a nil cause and leaves already marked errors
// unchanged, so repeated classification along a call chain stays idempotent.
func NewTokenValidationUnavailable(cause error) error {
	if cause == nil || errors.Is(cause, ErrTokenValidationUnavailable) {
		return cause
	}

	return &tokenValidationUnavailableError{cause: cause}
}

// IsTokenValidationUnavailable reports whether err means that token validation
// could not reach a decision, as opposed to a token that was rejected.
func IsTokenValidationUnavailable(err error) bool {
	return err != nil && errors.Is(err, ErrTokenValidationUnavailable)
}
