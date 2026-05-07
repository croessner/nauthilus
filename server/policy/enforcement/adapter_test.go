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

package enforcement

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/policy"
)

func TestNoopAdapterPreservesDecision(t *testing.T) {
	decision := Decision{
		Effect:         policy.DecisionDeny,
		ResponseMarker: "auth.response.fail",
		FSMEventMarker: "auth.fsm.event.auth_deny",
	}

	got, err := NoopAdapter{}.Apply(context.Background(), decision)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	if got != decision {
		t.Fatalf("decision = %#v, want %#v", got, decision)
	}
}
