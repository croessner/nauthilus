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

// Package enforcement defines the internal policy enforcement handoff boundary.
package enforcement

import (
	"context"

	"github.com/croessner/nauthilus/v3/server/policy"
)

// Decision is the minimal enforcement handoff for later adapters.
type Decision struct {
	Effect         policy.Decision
	ResponseMarker string
	FSMEventMarker string
}

// Adapter applies a policy decision to a response surface.
type Adapter interface {
	Apply(context.Context, Decision) (Decision, error)
}

// NoopAdapter preserves the current decision without side effects.
type NoopAdapter struct{}

// Apply returns the decision unchanged.
func (NoopAdapter) Apply(_ context.Context, decision Decision) (Decision, error) {
	return decision, nil
}
