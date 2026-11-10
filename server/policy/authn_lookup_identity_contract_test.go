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

import (
	"slices"
	"testing"
)

// The default identity-lookup plan must not schedule TLS or RBL: both are opt-in
// through an explicit domain-plan provider, so high lookup volumes cost no RBL quota.
func TestAuthnLookupIdentityDefaultPreAuthScheduleOmitsHostControls(t *testing.T) {
	got := AuthnBuiltinCheckpointProviderIDs(OperationLookupIdentity, StagePreAuth)
	want := []string{AuthnProviderEnvironment}

	if !slices.Equal(got, want) {
		t.Fatalf("lookup_identity pre_auth schedule = %v, want %v", got, want)
	}
}

func TestAuthnBuiltinProviderSkipsLookupIdentity(t *testing.T) {
	tests := []struct {
		identity string
		want     bool
	}{
		{identity: AuthnProviderTLSEncryption, want: false},
		{identity: AuthnProviderRBL, want: false},
		{identity: AuthnProviderEnvironment, want: false},
		{identity: AuthnProviderBackend, want: false},
		{identity: AuthnProviderRelayDomains, want: true},
		{identity: AuthnProviderBruteForce, want: true},
	}

	for _, test := range tests {
		t.Run(test.identity, func(t *testing.T) {
			if got := AuthnBuiltinProviderSkipsLookupIdentity(test.identity); got != test.want {
				t.Fatalf("AuthnBuiltinProviderSkipsLookupIdentity(%q) = %v, want %v", test.identity, got, test.want)
			}
		})
	}
}
