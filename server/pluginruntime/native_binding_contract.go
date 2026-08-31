// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import "github.com/croessner/nauthilus/v4/server/policy/nativebinding"

var (
	// ErrInvalidDecisionBinding identifies a configured selection outside frozen native capabilities.
	ErrInvalidDecisionBinding = nativebinding.ErrInvalidDecisionBinding
)

// CallRecord is the compatibility name for one bounded native method observation.
type CallRecord = nativebinding.CallRecord

// Observer is the compatibility name for the inward native call observer contract.
type Observer = nativebinding.Observer

// DecisionFactBindingInput is the compatibility name for one configured native fact selection.
type DecisionFactBindingInput = nativebinding.DecisionFactBindingInput

// DecisionEffectBindingInput is the compatibility name for one configured native effect selection.
type DecisionEffectBindingInput = nativebinding.DecisionEffectBindingInput

// DecisionBindingInput is the compatibility name for exact native candidate selections.
type DecisionBindingInput = nativebinding.DecisionBindingInput

// DecisionBindings is the compatibility name for prepared generation-local native adapters.
type DecisionBindings = nativebinding.DecisionBindings

var _ nativebinding.DecisionBindingPreparer = (*GenerationBindings)(nil)
