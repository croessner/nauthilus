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

package idp

import "strings"

// AuthFailureStatus carries policy-selected status metadata across IdP auth boundaries.
type AuthFailureStatus struct {
	// StatusMessage is the safe fallback text selected by policy.
	StatusMessage string

	// I18NKey is the stable localization key selected by policy.
	I18NKey string

	// ResponseLanguage is the optional policy-selected response language.
	ResponseLanguage string

	// PolicyTerminal reports that a configured policy selected a terminal deny or tempfail.
	PolicyTerminal bool
}

// HasI18NStatus reports whether the failure carries a stable localization key.
func (s AuthFailureStatus) HasI18NStatus() bool {
	return strings.TrimSpace(s.I18NKey) != ""
}

// AuthFailureError wraps an authentication failure with response-boundary status metadata.
type AuthFailureError struct {
	err error

	// Status contains the policy-selected response metadata for this failure.
	Status AuthFailureStatus
}

// NewAuthFailureError creates a typed authentication failure.
func NewAuthFailureError(err error, status AuthFailureStatus) *AuthFailureError {
	return &AuthFailureError{
		err:    err,
		Status: status,
	}
}

// Error returns the underlying failure message.
func (e *AuthFailureError) Error() string {
	if e == nil || e.err == nil {
		return "authentication failed"
	}

	return e.err.Error()
}

// Unwrap returns the underlying authentication failure.
func (e *AuthFailureError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.err
}
