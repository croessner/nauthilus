// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"slices"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestVerifierProjectionRejectsImpossibleAggregateFlagStates(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		value string
	}{
		{name: "modify satisfied", id: factDoNotModifyState, value: "satisfied"},
		{name: "modify violated", id: factDoNotModifyState, value: "violated"},
		{name: "explode satisfied", id: factDoNotExplodeState, value: "satisfied"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), test.id, test.value)
			if _, err := decodeVerifierProjection(request); err == nil {
				t.Fatalf("decodeVerifierProjection() error = nil for %s=%q", test.id, test.value)
			}
		})
	}
}

func TestVerifierProjectionRejectsAggregateFlagContradictions(t *testing.T) {
	tests := []struct {
		name              string
		doNotModify       bool
		doNotExplode      bool
		doNotModifyState  string
		doNotExplodeState string
		wantError         bool
	}{
		{
			name: "explode request cannot be aggregate not requested", doNotExplode: true,
			doNotModifyState: stateNotRequested, doNotExplodeState: stateNotRequested, wantError: true,
		},
		{
			name: "modify request cannot be aggregate not requested", doNotModify: true,
			doNotModifyState: stateNotRequested, doNotExplodeState: stateNotRequested, wantError: true,
		},
		{
			name: "explode request may remain indeterminate", doNotExplode: true,
			doNotModifyState: stateNotRequested, doNotExplodeState: stateIndeterminate,
		},
		{
			name: "modify request may remain indeterminate", doNotModify: true,
			doNotModifyState: stateIndeterminate, doNotExplodeState: stateNotRequested,
		},
		{
			name:             "unrequested flags require aggregate not requested",
			doNotModifyState: stateIndeterminate, doNotExplodeState: stateNotRequested, wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := testDecisionRequestWithFlagStates(
				t, "192.0.2.25", test.doNotModify, test.doNotExplode,
				test.doNotModifyState, test.doNotExplodeState,
			)

			_, err := decodeVerifierProjection(request)
			if (err != nil) != test.wantError {
				t.Fatalf("decodeVerifierProjection() error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestVerifierProjectionAcceptsExactRspamdScanActions(t *testing.T) {
	want := []string{
		"no action", "accept", "add header", "rewrite subject", "greylist",
		"soft reject", "reject", "quarantine", "discard",
	}
	if !slices.Equal(rspamdScanActions, want) {
		t.Fatalf("rspamdScanActions = %v, want exact adapter vocabulary %v", rspamdScanActions, want)
	}

	for _, action := range want {
		t.Run(action, func(t *testing.T) {
			request := replaceRequestStringFact(
				t, testDecisionRequest(t, "192.0.2.25"), factScanAction, action,
			)
			if _, err := decodeVerifierProjection(request); err != nil {
				t.Fatalf("decodeVerifierProjection() error = %v for admitted action %q", err, action)
			}
		})
	}
}

func TestVerifierProjectionRejectsUnknownRspamdScanAction(t *testing.T) {
	request := replaceRequestStringFact(
		t, testDecisionRequest(t, "192.0.2.25"), factScanAction, "ACCEPT",
	)
	if _, err := decodeVerifierProjection(request); err == nil {
		t.Fatal("decodeVerifierProjection() error = nil for unknown case-variant action")
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
