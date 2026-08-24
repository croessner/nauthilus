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

// Package admission compiles and enforces generation-owned Policy caller profiles.
package admission

import (
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

var (
	// ErrConfiguration identifies an invalid immutable caller-admission generation.
	ErrConfiguration = errors.New("invalid policy caller admission configuration")

	// ErrAdmission identifies a rejected authenticated Policy caller request.
	ErrAdmission = errors.New("policy caller admission rejected")

	// ErrPermissionDenied identifies a caller, target, field, or diagnostics permission failure.
	ErrPermissionDenied = errors.New("policy caller permission denied")

	// ErrInvalidRequest identifies trusted-evidence mismatch or selected-schema failure.
	ErrInvalidRequest = errors.New("invalid admitted policy request")

	// ErrLimitExceeded identifies request size, fact count, concurrency, or rate exhaustion.
	ErrLimitExceeded = errors.New("policy caller admission limit exceeded")

	// ErrRequestLimitExceeded identifies profile request-size or submitted-fact limits.
	ErrRequestLimitExceeded = fmt.Errorf("%w: request", ErrLimitExceeded)

	// ErrCapacityLimitExceeded identifies profile concurrency or rate exhaustion.
	ErrCapacityLimitExceeded = fmt.Errorf("%w: capacity", ErrLimitExceeded)
)

// Configuration contains every caller-admission profile captured by one runtime generation.
type Configuration struct {
	Profiles     []Profile
	GlobalLimits Limits
}

// Profile binds one exact authenticated principal to request authority and limits.
type Profile struct {
	AuthenticationKinds          []string
	References                   []registry.ClientAdmissionReference
	AllowedSubjectAttributes     []string
	AllowedResourceAttributes    []string
	AllowedEnvironmentAttributes []string
	AllowedInputAttributes       []string
	Principal                    string
	Limits                       Limits
	Diagnostics                  bool
	Internal                     bool
}

// Limits contains bounded per-profile admission controls.
type Limits struct {
	MaxRequestBytes   int
	MaxFacts          int
	MaxConcurrency    int
	RequestsPerSecond int
}

type classifiedError struct {
	primary  error
	category error
	reason   string
}

// Error returns a secret-free stable failure description.
func (e *classifiedError) Error() string {
	if e == nil {
		return "<nil>"
	}

	return fmt.Sprintf("%s: %s", e.primary, e.reason)
}

// Unwrap exposes the broad boundary and stable detailed category.
func (e *classifiedError) Unwrap() []error {
	if e == nil {
		return nil
	}

	return []error{e.primary, e.category}
}

// configurationError constructs one safe preparation failure.
func configurationError(reason string) error {
	return &classifiedError{primary: ErrConfiguration, category: ErrConfiguration, reason: reason}
}

// admissionError constructs one safe request-time admission failure.
func admissionError(category error, reason string) error {
	return &classifiedError{primary: ErrAdmission, category: category, reason: reason}
}
