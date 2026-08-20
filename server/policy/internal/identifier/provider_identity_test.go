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

package identifier

import "testing"

func TestProviderIdentityAcceptsCanonicalProviderForms(t *testing.T) {
	tests := []string{
		"authn/builtin/brute_force",
		"authn/plugin.example.environment",
		"authn/plugin.example.subject.local",
		"authn/lua_environment_name",
	}

	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			if !ProviderIdentity(value) {
				t.Fatalf("ProviderIdentity(%q) = false, want true", value)
			}
		})
	}
}

func TestProviderIdentityRejectsNonCanonicalProviderForms(t *testing.T) {
	tests := []string{
		"brute_force",
		"authn/",
		"/builtin/brute_force",
		"authn//brute_force",
		"authn/builtin/",
		"authn/builtin//brute_force",
		"authn/plugin..environment",
		"authn/plugin.example/subject.local",
		"Authn/builtin/brute_force",
		"authn/plugin.Example.environment",
		"authn/plugin.*.environment",
		"authn\\builtin\\brute_force",
	}

	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			if ProviderIdentity(value) {
				t.Fatalf("ProviderIdentity(%q) = true, want false", value)
			}
		})
	}
}

func TestQualifiedIdentityRemainsNamespaceLocalOnly(t *testing.T) {
	if Qualified("authn/builtin/brute_force") {
		t.Fatal("Qualified() accepted a provider-specific nested identity")
	}

	if !Qualified("authn/standard_auth") {
		t.Fatal("Qualified() rejected an exact namespace/local identity")
	}
}
