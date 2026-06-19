// Copyright (C) 2025 Christian Rößner
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

package flow

import "errors"

var (
	// ErrEmptyFlowID is an exported package value.
	ErrEmptyFlowID = errors.New("empty flow id")
	// ErrFlowNotFound is an exported package value.
	ErrFlowNotFound = errors.New("flow not found")
	// ErrInvalidFlowType reports an unsupported flow type.
	ErrInvalidFlowType = errors.New("invalid flow type")
	// ErrInvalidProtocol reports an unsupported flow protocol.
	ErrInvalidProtocol = errors.New("invalid protocol")
	// ErrInvalidStep reports an unsupported flow step.
	ErrInvalidStep = errors.New("invalid step")
	// ErrInvalidAction reports an unsupported flow action.
	ErrInvalidAction = errors.New("invalid action")
	// ErrInvalidAuthOutcome reports an unsupported auth outcome marker.
	ErrInvalidAuthOutcome = errors.New("invalid auth outcome")
)

// TransitionError reports invalid transitions for a specific flow/step pair.
type TransitionError struct {
	Type   Type
	From   Step
	To     Step
	Action Action
}

// Error returns the transition violation as a stable diagnostic string.
func (e TransitionError) Error() string {
	return "invalid transition: flow=" + string(e.Type) + " from=" + string(e.From) + " to=" + string(e.To) + " action=" + string(e.Action)
}
