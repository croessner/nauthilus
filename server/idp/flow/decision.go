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

// DecisionType defines the resulting operation from flow domain logic.
type DecisionType string

const (
	DecisionTypeRedirect DecisionType = "redirect"
	DecisionTypeError    DecisionType = "error"
)

// Decision is a transport-agnostic description of what should happen next.
type Decision struct {
	Model       map[string]any `json:"model,omitzero"`
	Type        DecisionType   `json:"type"`
	Template    string         `json:"template,omitzero"`
	RedirectURI string         `json:"redirect_uri,omitzero"`
	Reason      string         `json:"reason,omitzero"`
}
