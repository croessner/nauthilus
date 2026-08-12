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

package decision

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidTarget identifies an invalid namespace/action pair.
	ErrInvalidTarget = errors.New("invalid policy target")

	// ErrInvalidValue identifies a malformed or ambiguous typed value.
	ErrInvalidValue = errors.New("invalid policy value")

	// ErrInvalidFact identifies a malformed policy fact.
	ErrInvalidFact = errors.New("invalid policy fact")

	// ErrReservedFact identifies caller ownership of a trusted fact family.
	ErrReservedFact = errors.New("reserved policy fact")

	// ErrFactSource identifies a fact whose canonical family does not match its source.
	ErrFactSource = errors.New("invalid policy fact source")

	// ErrFactCollision identifies duplicate ownership of one canonical fact.
	ErrFactCollision = errors.New("policy fact collision")

	// ErrInvalidCaller identifies malformed trusted caller context.
	ErrInvalidCaller = errors.New("invalid policy caller")

	// ErrInvalidRequest identifies a malformed internal decision request.
	ErrInvalidRequest = errors.New("invalid policy decision request")

	// ErrInvalidResponse identifies a malformed internal decision response.
	ErrInvalidResponse = errors.New("invalid policy decision response")

	// ErrCorrelationOnly identifies an attempt to use a request or decision ID as authority.
	ErrCorrelationOnly = errors.New("policy ID is correlation only")
)

// ErrorCode is a stable machine-readable contract failure category.
type ErrorCode string

const (
	// ErrorCodeInvalidTarget reports invalid target identity.
	ErrorCodeInvalidTarget ErrorCode = "invalid_target"

	// ErrorCodeInvalidValue reports strict typed-value failure.
	ErrorCodeInvalidValue ErrorCode = "invalid_value"

	// ErrorCodeInvalidFact reports malformed fact identity or metadata.
	ErrorCodeInvalidFact ErrorCode = "invalid_fact"

	// ErrorCodeReservedFact reports caller access to a trusted fact family.
	ErrorCodeReservedFact ErrorCode = "reserved_fact"

	// ErrorCodeFactSource reports source/fact-family ownership mismatch.
	ErrorCodeFactSource ErrorCode = "invalid_fact_source"

	// ErrorCodeFactCollision reports duplicate canonical fact ownership.
	ErrorCodeFactCollision ErrorCode = "fact_collision"

	// ErrorCodeInvalidCaller reports malformed trusted caller context.
	ErrorCodeInvalidCaller ErrorCode = "invalid_caller"

	// ErrorCodeInvalidRequest reports malformed request structure.
	ErrorCodeInvalidRequest ErrorCode = "invalid_request"

	// ErrorCodeInvalidResponse reports malformed response structure.
	ErrorCodeInvalidResponse ErrorCode = "invalid_response"

	// ErrorCodeCorrelationOnly reports forbidden authority or metric use of an ID.
	ErrorCodeCorrelationOnly ErrorCode = "correlation_only"
)

// ContractError carries a stable code and safe field-level reason.
type ContractError struct {
	cause  error
	field  string
	reason string
	code   ErrorCode
}

// Error returns the safe contract error text.
func (e *ContractError) Error() string {
	if e.field == "" {
		return fmt.Sprintf("%s: %s", e.code, e.reason)
	}

	return fmt.Sprintf("%s: %s: %s", e.code, e.field, e.reason)
}

// Unwrap exposes the stable sentinel category for errors.Is.
func (e *ContractError) Unwrap() error {
	return e.cause
}

// Code returns the stable machine-readable failure code.
func (e *ContractError) Code() ErrorCode {
	return e.code
}

// Field returns the safe public-shaped field path when applicable.
func (e *ContractError) Field() string {
	return e.field
}

// Reason returns the stable safe validation reason.
func (e *ContractError) Reason() string {
	return e.reason
}

// newContractError constructs one stable contract error.
func newContractError(cause error, code ErrorCode, field string, reason string) error {
	return &ContractError{
		cause:  cause,
		field:  field,
		reason: reason,
		code:   code,
	}
}
