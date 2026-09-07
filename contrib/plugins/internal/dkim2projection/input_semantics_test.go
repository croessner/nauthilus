// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dkim2projection

import (
	"slices"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

func TestVerifierProjectionRejectsImpossibleAggregateFlagStates(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		value string
	}{
		{name: "modify satisfied", id: FactDoNotModifyState, value: "satisfied"},
		{name: "modify violated", id: FactDoNotModifyState, value: "violated"},
		{name: "explode satisfied", id: FactDoNotExplodeState, value: "satisfied"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), test.id, test.value)
			if _, err := Decode(request); err == nil {
				t.Fatalf("Decode() error = nil for %s=%q", test.id, test.value)
			}
		})
	}
}

func TestVerifierProjectionRejectsAggregateFlagContradictions(t *testing.T) {
	tests := []struct {
		name              string
		DoNotModify       bool
		DoNotExplode      bool
		DoNotModifyState  string
		DoNotExplodeState string
		wantError         bool
	}{
		{
			name: "explode request cannot be aggregate not requested", DoNotExplode: true,
			DoNotModifyState: StateNotRequested, DoNotExplodeState: StateNotRequested, wantError: true,
		},
		{
			name: "modify request cannot be aggregate not requested", DoNotModify: true,
			DoNotModifyState: StateNotRequested, DoNotExplodeState: StateNotRequested, wantError: true,
		},
		{
			name: "explode request may remain indeterminate", DoNotExplode: true,
			DoNotModifyState: StateNotRequested, DoNotExplodeState: StateIndeterminate,
		},
		{
			name: "modify request may remain indeterminate", DoNotModify: true,
			DoNotModifyState: StateIndeterminate, DoNotExplodeState: StateNotRequested,
		},
		{
			name:             "unrequested flags require aggregate not requested",
			DoNotModifyState: StateIndeterminate, DoNotExplodeState: StateNotRequested, wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := testDecisionRequestWithFlagStates(
				t, "192.0.2.25", test.DoNotModify, test.DoNotExplode,
				test.DoNotModifyState, test.DoNotExplodeState,
			)

			_, err := Decode(request)
			if (err != nil) != test.wantError {
				t.Fatalf("Decode() error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestVerifierProjectionAcceptsExactRspamdScanActions(t *testing.T) {
	want := []string{
		"no action", "accept", "add header", "rewrite subject", "greylist",
		"soft reject", "reject", "quarantine", "discard",
	}
	if !slices.Equal(RspamdScanActions, want) {
		t.Fatalf("RspamdScanActions = %v, want exact adapter vocabulary %v", RspamdScanActions, want)
	}

	for _, action := range want {
		t.Run(action, func(t *testing.T) {
			request := replaceRequestStringFact(
				t, testDecisionRequest(t, "192.0.2.25"), FactScanAction, action,
			)
			if _, err := Decode(request); err != nil {
				t.Fatalf("Decode() error = %v for admitted action %q", err, action)
			}
		})
	}
}

func TestVerifierProjectionRejectsUnknownRspamdScanAction(t *testing.T) {
	request := replaceRequestStringFact(
		t, testDecisionRequest(t, "192.0.2.25"), FactScanAction, "ACCEPT",
	)
	if _, err := Decode(request); err == nil {
		t.Fatal("Decode() error = nil for unknown case-variant action")
	}
}

// replaceRequestStringFact rebuilds one immutable request with an exact string fact replacement.
func replaceRequestStringFact(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	id string,
	value string,
) pluginapi.DecisionFactRequest {
	t.Helper()

	return replaceRequestFact(t, request, id, testStringValue(t, value))
}
