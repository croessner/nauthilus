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

package policy

import "testing"

func TestPolicyCallerAuthenticationKindsRemainDistinct(t *testing.T) {
	tests := []struct {
		name string
		kind string
		want string
	}{
		{name: "Bearer", kind: CallerAuthenticationKindBearer, want: "oidc_bearer"},
		{name: "Basic", kind: CallerAuthenticationKindBasic, want: "basic"},
		{name: "internal", kind: CallerAuthenticationKindInternal, want: "internal"},
	}

	seen := make(map[string]struct{}, len(tests))
	for _, test := range tests {
		if test.kind != test.want {
			t.Fatalf("%s authentication kind = %q, want %q", test.name, test.kind, test.want)
		}

		if _, duplicate := seen[test.kind]; duplicate {
			t.Fatalf("authentication kind %q is not distinct", test.kind)
		}

		seen[test.kind] = struct{}{}
	}
}
