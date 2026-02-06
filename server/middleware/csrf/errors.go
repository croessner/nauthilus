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

package csrf

import "errors"

// Errors returned by CSRF validation.
var (
	// ErrNoReferer is returned when a secure request has no Referer header.
	ErrNoReferer = errors.New("csrf: secure request contained no Referer or its value was malformed")

	// ErrBadReferer is returned when the Referer header doesn't match the request origin.
	ErrBadReferer = errors.New("csrf: Referer comes from a different origin")

	// ErrBadOrigin is returned when the Origin header doesn't match the request origin.
	ErrBadOrigin = errors.New("csrf: Origin header specifies a disallowed origin")

	// ErrBadToken is returned when the CSRF token doesn't match.
	ErrBadToken = errors.New("csrf: token in cookie doesn't match the one in form/header")

	// ErrNoToken is returned when no CSRF token is found in the request.
	ErrNoToken = errors.New("csrf: no token found in request")

	// ErrInvalidTokenLength is returned when the token has an invalid length.
	ErrInvalidTokenLength = errors.New("csrf: invalid token length")

	// errNoOrigin is an internal error when Origin header is not present.
	errNoOrigin = errors.New("csrf: Origin header was not present")
)
