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

import "github.com/croessner/nauthilus/v3/server/policy/internal/identifier"

// Target identifies one exact policy namespace/action pair.
type Target struct {
	namespace string
	action    string
}

// NewTarget validates and constructs an exact target identity.
func NewTarget(namespace string, action string) (Target, error) {
	if !validNamespace(namespace) {
		return Target{}, newContractError(
			ErrInvalidTarget,
			ErrorCodeInvalidTarget,
			"target.namespace",
			"must contain lowercase ASCII segments separated by dots",
		)
	}

	if !validAction(action) {
		return Target{}, newContractError(
			ErrInvalidTarget,
			ErrorCodeInvalidTarget,
			"target.action",
			"must contain lowercase ASCII words separated by hyphens or underscores",
		)
	}

	return Target{namespace: namespace, action: action}, nil
}

// Namespace returns the exact target namespace.
func (t Target) Namespace() string {
	return t.namespace
}

// Action returns the exact target action.
func (t Target) Action() string {
	return t.action
}

// String returns the stable qualified target identity.
func (t Target) String() string {
	return t.namespace + "/" + t.action
}

// valid reports whether the target was constructor-validated.
func (t Target) valid() bool {
	return validNamespace(t.namespace) && validAction(t.action)
}

// validNamespace enforces the target namespace grammar.
func validNamespace(value string) bool {
	return identifier.Namespace(value)
}

// validAction enforces the target action grammar.
func validAction(value string) bool {
	return identifier.Action(value)
}
