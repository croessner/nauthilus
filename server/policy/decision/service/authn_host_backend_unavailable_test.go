// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"testing"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// backendUnavailableTestProvider is one captured host provider with a fixed kind.
type backendUnavailableTestProvider struct {
	id   string
	kind string
}

// ID returns the exact provider identity.
func (p backendUnavailableTestProvider) ID() string { return p.id }

// Kind returns the captured host provider kind.
func (p backendUnavailableTestProvider) Kind() string { return p.kind }

// TestSkipBackendDependentDirectiveSkipsOnlySubjectProviders proves that a missing backend result skips every subject
// provider family, keeps earlier skip reasons, and leaves other host providers runnable.
func TestSkipBackendDependentDirectiveSkipsOnlySubjectProviders(t *testing.T) {
	providers := map[string]policyruntime.AuthnHostProvider{}
	for id, kind := range map[string]string{
		"authn/plugin.example.subject.risk":     AuthnHostProviderKindNativeSubject,
		"authn/lua_subject_geoip":               AuthnHostProviderKindLuaSubject,
		"authn/plugin.example.environment":      AuthnHostProviderKindNativeEnvironment,
		"authn/lua_environment_policy_gate":     AuthnHostProviderKindLuaEnvironment,
		"authn/plugin.example.subject.disabled": AuthnHostProviderKindNativeSubject,
	} {
		providers[id] = backendUnavailableTestProvider{id: id, kind: kind}
	}

	session := &decisionSession{generation: &runtimeGeneration{authnHostProviders: providers}}

	testCases := []struct {
		use         string
		disposition AuthnHostDisposition
		reason      string
		want        AuthnHostDisposition
		wantReason  string
	}{
		{"authn/plugin.example.subject.risk", AuthnHostDispositionRun, AuthnHostReasonScheduled,
			AuthnHostDispositionSkipped, AuthnHostReasonBackendUnavailable},
		{"authn/lua_subject_geoip", AuthnHostDispositionRun, AuthnHostReasonScheduled,
			AuthnHostDispositionSkipped, AuthnHostReasonBackendUnavailable},
		{policy.AuthnProviderSubject, AuthnHostDispositionRun, AuthnHostReasonScheduled,
			AuthnHostDispositionSkipped, AuthnHostReasonBackendUnavailable},
		{"authn/plugin.example.environment", AuthnHostDispositionRun, AuthnHostReasonScheduled,
			AuthnHostDispositionRun, AuthnHostReasonScheduled},
		{"authn/lua_environment_policy_gate", AuthnHostDispositionRun, AuthnHostReasonScheduled,
			AuthnHostDispositionRun, AuthnHostReasonScheduled},
		{policy.AuthnProviderBackend, AuthnHostDispositionRun, AuthnHostReasonScheduled,
			AuthnHostDispositionRun, AuthnHostReasonScheduled},
		{"authn/plugin.example.subject.disabled", AuthnHostDispositionSkipped, AuthnHostReasonAuthState,
			AuthnHostDispositionSkipped, AuthnHostReasonAuthState},
	}

	for _, testCase := range testCases {
		directive := session.skipBackendDependentDirective(AuthnHostDirective{
			instance:    CheckpointProviderInstance{name: "instance", use: testCase.use},
			disposition: testCase.disposition,
			reason:      testCase.reason,
		})

		if directive.Disposition() != testCase.want || directive.Reason() != testCase.wantReason {
			t.Fatalf(
				"skipBackendDependentDirective(%s) = %s/%s, want %s/%s",
				testCase.use, directive.Disposition(), directive.Reason(), testCase.want, testCase.wantReason,
			)
		}
	}
}
