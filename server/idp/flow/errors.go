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
	ErrEmptyFlowID        = errors.New("empty flow id")
	ErrFlowNotFound       = errors.New("flow not found")
	ErrInvalidFlowType    = errors.New("invalid flow type")
	ErrInvalidProtocol    = errors.New("invalid protocol")
	ErrInvalidStep        = errors.New("invalid step")
	ErrInvalidAction      = errors.New("invalid action")
	ErrInvalidAuthOutcome = errors.New("invalid auth outcome")
)

// TransitionError reports invalid transitions for a specific flow/step pair.
type TransitionError struct {
	FlowType FlowType
	From     FlowStep
	To       FlowStep
	Action   FlowAction
}

// Error returns the transition violation as a stable diagnostic string.
func (e TransitionError) Error() string {
	return "invalid transition: flow=" + string(e.FlowType) + " from=" + string(e.From) + " to=" + string(e.To) + " action=" + string(e.Action)
}
