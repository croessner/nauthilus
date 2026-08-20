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

package definitions

import "testing"

func TestPolicyAuthenticationAudience(t *testing.T) {
	if AudiencePolicyAPI != "nauthilus:policy" {
		t.Fatalf("AudiencePolicyAPI = %q, want %q", AudiencePolicyAPI, "nauthilus:policy")
	}

	if AudiencePolicyAPI == AudienceBackchannelAPI {
		t.Fatal("Policy and backchannel audiences must remain distinct")
	}
}

func TestPolicyAuthenticationScopes(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  string
	}{
		{name: "evaluate", scope: ScopePolicyEvaluate, want: "nauthilus:policy_evaluate"},
		{name: "diagnostics", scope: ScopePolicyDiagnostics, want: "nauthilus:policy_diagnostics"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.scope != test.want {
				t.Fatalf("scope = %q, want %q", test.scope, test.want)
			}

			if test.scope == ScopeAdmin {
				t.Fatal("Policy scope must remain distinct from the administrative scope")
			}
		})
	}

	if ScopePolicyEvaluate == ScopePolicyDiagnostics {
		t.Fatal("Policy evaluate and diagnostics scopes must remain distinct")
	}
}
