// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
)

// countingToleration counts toleration accounting calls.
type countingToleration struct {
	tolerate.Tolerate
	calls int
}

// SetIPAddress counts one call.
func (c *countingToleration) SetIPAddress(context.Context, string, string, bool) {
	c.calls++
}

// TestTolerationVerdictAccountsOnlyHostVerifiedCredentialOutcomes pins the mapping of answered decisions and frozen
// credential verdicts onto toleration observations.
func TestTolerationVerdictAccountsOnlyHostVerifiedCredentialOutcomes(t *testing.T) {
	testCases := []struct {
		name          string
		decision      AuthDecision
		credential    definitions.AuthResult
		repeated      bool
		authenticated bool
		accounted     bool
	}{
		{name: "verified success", decision: AuthDecisionOK, credential: definitions.AuthResultOK, authenticated: true, accounted: true},
		{name: "rejected credential", decision: AuthDecisionFail, credential: definitions.AuthResultFail, accounted: true},
		{name: "repeated wrong password", decision: AuthDecisionFail, credential: definitions.AuthResultFail, repeated: true},
		{name: "verified success clears a stale RWP candidate", decision: AuthDecisionOK, credential: definitions.AuthResultOK, repeated: true, authenticated: true, accounted: true},
		{name: "policy deny of a verified credential", decision: AuthDecisionFail, credential: definitions.AuthResultOK},
		{name: "pre-auth deny without credential check", decision: AuthDecisionFail, credential: definitions.AuthResultUnset},
		{name: "tempfail", decision: AuthDecisionTempFail, credential: definitions.AuthResultTempFail},
		{name: "unbacked permit", decision: AuthDecisionOK, credential: definitions.AuthResultUnset},
	}

	for _, testCase := range testCases {
		authenticated, accounted := tolerationVerdict(testCase.decision, testCase.credential, testCase.repeated)
		if authenticated != testCase.authenticated || accounted != testCase.accounted {
			t.Fatalf("%s: verdict = %v/%v, want %v/%v", testCase.name, authenticated, accounted,
				testCase.authenticated, testCase.accounted)
		}
	}
}

// TestTolerationOutcomeSkipsLookupsAndNoAuth pins that identity lookups and no-auth requests never feed toleration.
func TestTolerationOutcomeSkipsLookupsAndNoAuth(t *testing.T) {
	result := authnApplicationResult{auth: &AuthOutcome{Decision: AuthDecisionOK}}

	for name, mutate := range map[string]func(*authnCandidateExecution){
		"lookup":  func(e *authnCandidateExecution) { e.operation = policy.OperationLookupIdentity },
		"no-auth": func(e *authnCandidateExecution) { e.auth.Request.NoAuth = true },
	} {
		toleration := &countingToleration{}
		execution := &authnCandidateExecution{auth: &AuthState{deps: AuthDeps{Tolerate: toleration}},
			operation: policy.OperationAuthenticate}
		execution.hostEvidence.credential = definitions.AuthResultOK
		mutate(execution)

		if _, observed := execution.tolerationObservation(result); observed {
			t.Fatalf("%s: toleration outcome observed, want none", name)
		}
	}
}
