// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policy

import "testing"

func TestPolicyMigrationAuthnProviderObserveSafetyDefaults(t *testing.T) {
	tests := []struct {
		use             string
		defaultSafe     bool
		allowsAssertion bool
		known           bool
	}{
		{use: AuthnProviderBruteForce, known: true},
		{use: AuthnProviderTLSEncryption, defaultSafe: true, known: true},
		{use: AuthnProviderRelayDomains, defaultSafe: true, known: true},
		{use: AuthnProviderRBL, known: true},
		{use: AuthnNamespace + "/lua_environment_risk", allowsAssertion: true, known: true},
		{use: AuthnNamespace + "/plugin.example.environment", allowsAssertion: true, known: true},
		{use: AuthnProviderLDAPBackend, known: true},
		{use: AuthnProviderLuaBackend, allowsAssertion: true, known: true},
		{use: AuthnProviderPluginBackendOrder, allowsAssertion: true, known: true},
		{use: AuthnNamespace + "/lua_subject_profile", allowsAssertion: true, known: true},
		{use: AuthnNamespace + "/plugin.example.subject.profile", allowsAssertion: true, known: true},
		{use: AuthnProviderAccount, known: true},
		{use: AuthnNamespace + "/custom"},
	}

	for _, test := range tests {
		t.Run(test.use, func(t *testing.T) {
			defaultSafe, allowsAssertion, known := AuthnProviderObserveSafety(test.use)
			if defaultSafe != test.defaultSafe || allowsAssertion != test.allowsAssertion || known != test.known {
				t.Fatalf(
					"AuthnProviderObserveSafety(%q) = (%t, %t, %t), want (%t, %t, %t)",
					test.use,
					defaultSafe,
					allowsAssertion,
					known,
					test.defaultSafe,
					test.allowsAssertion,
					test.known,
				)
			}
		})
	}
}

func TestPolicyMigrationBuiltinProviderIdentitiesRemainExact(t *testing.T) {
	for instance, want := range authnBuiltinProviderIdentities {
		got, exists := AuthnBuiltinProviderIdentity(instance)
		if !exists || got != want {
			t.Fatalf("AuthnBuiltinProviderIdentity(%q) = %q, %t; want %q, true", instance, got, exists, want)
		}

		if !IsAuthnBuiltinProviderIdentity(want) {
			t.Fatalf("IsAuthnBuiltinProviderIdentity(%q) = false", want)
		}
	}

	if IsAuthnBuiltinProviderIdentity(AuthnNamespace + "/builtin/missing") {
		t.Fatal("unknown builtin provider identity was accepted")
	}
}
