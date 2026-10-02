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

package registry

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// TestBuiltinStandardAuthEmptyCredentialRulesKeepTheirFSMEvents pins the builtin markers whose events the host-driven
// auth FSM keeps distinct from ordinary credential results.
func TestBuiltinStandardAuthEmptyCredentialRulesKeepTheirFSMEvents(t *testing.T) {
	rules, err := builtinFixedStandardAuthRules()
	if err != nil {
		t.Fatalf("builtinFixedStandardAuthRules() error = %v", err)
	}

	want := map[string]struct {
		marker   string
		decision decision.Effect
	}{
		"standard_empty_username": {marker: policy.FSMEventMarkerAuthEmptyUser, decision: decision.EffectIndeterminate},
		"standard_empty_password": {marker: policy.FSMEventMarkerAuthEmptyPass, decision: decision.EffectDeny},
	}

	for _, rule := range rules {
		expected, ok := want[rule.Name()]
		if !ok {
			continue
		}

		if rule.FSMEventMarker() != expected.marker || rule.Decision() != expected.decision {
			t.Fatalf("%s marker/decision = %s/%s, want %s/%s", rule.Name(), rule.FSMEventMarker(), rule.Decision(),
				expected.marker, expected.decision)
		}

		delete(want, rule.Name())
	}

	if len(want) != 0 {
		t.Fatalf("builtin empty-credential rules missing: %v", want)
	}
}
