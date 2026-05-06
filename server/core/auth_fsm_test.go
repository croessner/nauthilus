// Copyright (C) 2024 Christian Rößner
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

package core

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
)

func TestNextAuthFSMState_AllowedTransitions(t *testing.T) {
	tests := []struct {
		name    string
		current authFSMState
		event   authFSMEvent
		next    authFSMState
	}{
		{
			name:    "InitParseOK",
			current: authFSMStateInit,
			event:   authFSMEventParseOK,
			next:    authFSMStateInputParsed,
		},
		{
			name:    "InitParseFail",
			current: authFSMStateInit,
			event:   authFSMEventParseFail,
			next:    authFSMStateAborted,
		},
		{
			name:    "InputBasicAuthOK",
			current: authFSMStateInputParsed,
			event:   authFSMEventBasicAuthOK,
			next:    authFSMStateAuthOK,
		},
		{
			name:    "InputBasicAuthFail",
			current: authFSMStateInputParsed,
			event:   authFSMEventBasicAuthFail,
			next:    authFSMStateAuthFail,
		},
		{
			name:    "InputPreAuthOK",
			current: authFSMStateInputParsed,
			event:   authFSMEventPreAuthOK,
			next:    authFSMStatePreAuthChecked,
		},
		{
			name:    "PreAuthAuthEvaluated",
			current: authFSMStatePreAuthChecked,
			event:   authFSMEventAuthEvaluated,
			next:    authFSMStateAuthChecked,
		},
		{
			name:    "PreAuthDeny",
			current: authFSMStateInputParsed,
			event:   authFSMEventPreAuthDeny,
			next:    authFSMStateAuthFail,
		},
		{
			name:    "PreAuthTempFail",
			current: authFSMStateInputParsed,
			event:   authFSMEventPreAuthTempFail,
			next:    authFSMStateAuthTempFail,
		},
		{
			name:    "PreAuthAbort",
			current: authFSMStateInputParsed,
			event:   authFSMEventPreAuthAbort,
			next:    authFSMStateAborted,
		},
		{
			name:    "PreAuthBasicAuthOK",
			current: authFSMStatePreAuthChecked,
			event:   authFSMEventBasicAuthOK,
			next:    authFSMStateAuthOK,
		},
		{
			name:    "PreAuthBasicAuthFail",
			current: authFSMStatePreAuthChecked,
			event:   authFSMEventBasicAuthFail,
			next:    authFSMStateAuthFail,
		},
		{
			name:    "AuthCheckedPermit",
			current: authFSMStateAuthChecked,
			event:   authFSMEventAuthPermit,
			next:    authFSMStateAuthOK,
		},
		{
			name:    "AuthCheckedDeny",
			current: authFSMStateAuthChecked,
			event:   authFSMEventAuthDeny,
			next:    authFSMStateAuthFail,
		},
		{
			name:    "AuthCheckedTempFail",
			current: authFSMStateAuthChecked,
			event:   authFSMEventAuthTempFail,
			next:    authFSMStateAuthTempFail,
		},
		{
			name:    "AuthCheckedEmptyUser",
			current: authFSMStateAuthChecked,
			event:   authFSMEventAuthEmptyUser,
			next:    authFSMStateAuthTempFail,
		},
		{
			name:    "AuthCheckedEmptyPass",
			current: authFSMStateAuthChecked,
			event:   authFSMEventAuthEmptyPass,
			next:    authFSMStateAuthFail,
		},
		{
			name:    "PreAuthAccountProviderEvaluated",
			current: authFSMStatePreAuthChecked,
			event:   authFSMEventAccountProviderEvaluated,
			next:    authFSMStateAccountProviderChecked,
		},
		{
			name:    "AccountProviderPermit",
			current: authFSMStateAccountProviderChecked,
			event:   authFSMEventAuthPermit,
			next:    authFSMStateAuthOK,
		},
		{
			name:    "AbortFromInput",
			current: authFSMStateInputParsed,
			event:   authFSMEventAbort,
			next:    authFSMStateAborted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next, err := nextAuthFSMState(tc.current, tc.event)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if next != tc.next {
				t.Fatalf("expected next=%s, got %s", tc.next, next)
			}
		})
	}
}

func TestNextAuthFSMState_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name    string
		current authFSMState
		event   authFSMEvent
	}{
		{
			name:    "InvalidEventFromInit",
			current: authFSMStateInit,
			event:   authFSMEventAuthPermit,
		},
		{
			name:    "InvalidAuthEventFromInputParsed",
			current: authFSMStateInputParsed,
			event:   authFSMEventAuthDeny,
		},
		{
			name:    "InvalidDirectAuthEventFromPreAuthChecked",
			current: authFSMStatePreAuthChecked,
			event:   authFSMEventAuthPermit,
		},
		{
			name:    "NoTransitionsFromTerminal",
			current: authFSMStateAuthOK,
			event:   authFSMEventAbort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := nextAuthFSMState(tc.current, tc.event)
			if err == nil {
				t.Fatal("expected transition error, got nil")
			}
		})
	}
}

type authFSMResultMappingCase struct {
	name    string
	result  definitions.AuthResult
	wantEvt authFSMEvent
	wantOK  bool
}

func preAuthFSMEventMappingCases() []authFSMResultMappingCase {
	return []authFSMResultMappingCase{
		{
			name:    "PreAuthTLS",
			result:  definitions.AuthResultPreAuthTLS,
			wantEvt: authFSMEventPreAuthTempFail,
			wantOK:  true,
		},
		{
			name:    "PreAuthRelayDomain",
			result:  definitions.AuthResultPreAuthRelayDomain,
			wantEvt: authFSMEventPreAuthDeny,
			wantOK:  true,
		},
		{
			name:    "ControlRBL",
			result:  definitions.AuthResultPreAuthRBL,
			wantEvt: authFSMEventPreAuthDeny,
			wantOK:  true,
		},
		{
			name:    "ControlLua",
			result:  definitions.AuthResultLuaEnvironment,
			wantEvt: authFSMEventPreAuthDeny,
			wantOK:  true,
		},
		{
			name:    "PreAuthTempFail",
			result:  definitions.AuthResultTempFail,
			wantEvt: authFSMEventPreAuthTempFail,
			wantOK:  true,
		},
		{
			name:    "PreAuthOK",
			result:  definitions.AuthResultOK,
			wantEvt: authFSMEventPreAuthOK,
			wantOK:  true,
		},
		{
			name:    "PreAuthUnset",
			result:  definitions.AuthResultUnset,
			wantEvt: authFSMEventPreAuthAbort,
			wantOK:  true,
		},
		{
			name:   "Unsupported",
			result: definitions.AuthResultEmptyUsername,
			wantOK: false,
		},
	}
}

func TestMapPreAuthResultToFSMEvent(t *testing.T) {
	for _, tc := range preAuthFSMEventMappingCases() {
		t.Run(tc.name, func(t *testing.T) {
			gotEvt, gotOK := mapPreAuthResultToFSMEvent(tc.result)
			if gotOK != tc.wantOK {
				t.Fatalf("expected ok=%t, got %t", tc.wantOK, gotOK)
			}

			if tc.wantOK && gotEvt != tc.wantEvt {
				t.Fatalf("expected event=%s, got %s", tc.wantEvt, gotEvt)
			}
		})
	}
}

func TestMapAuthPasswordResultToFSMEvent(t *testing.T) {
	tests := []struct {
		name    string
		result  definitions.AuthResult
		wantEvt authFSMEvent
		wantOK  bool
	}{
		{
			name:    "PasswordOK",
			result:  definitions.AuthResultOK,
			wantEvt: authFSMEventAuthPermit,
			wantOK:  true,
		},
		{
			name:    "PasswordFail",
			result:  definitions.AuthResultFail,
			wantEvt: authFSMEventAuthDeny,
			wantOK:  true,
		},
		{
			name:    "PasswordTempFail",
			result:  definitions.AuthResultTempFail,
			wantEvt: authFSMEventAuthTempFail,
			wantOK:  true,
		},
		{
			name:    "PasswordEmptyUsername",
			result:  definitions.AuthResultEmptyUsername,
			wantEvt: authFSMEventAuthEmptyUser,
			wantOK:  true,
		},
		{
			name:    "PasswordEmptyPassword",
			result:  definitions.AuthResultEmptyPassword,
			wantEvt: authFSMEventAuthEmptyPass,
			wantOK:  true,
		},
		{
			name:   "Unsupported",
			result: definitions.AuthResultPreAuthTLS,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotEvt, gotOK := mapAuthPasswordResultToFSMEvent(tc.result)
			if gotOK != tc.wantOK {
				t.Fatalf("expected ok=%t, got %t", tc.wantOK, gotOK)
			}

			if tc.wantOK && gotEvt != tc.wantEvt {
				t.Fatalf("expected event=%s, got %s", tc.wantEvt, gotEvt)
			}
		})
	}
}

func TestAuthFSMEventValuesAreTargetMarkers(t *testing.T) {
	tests := []struct {
		name  string
		event authFSMEvent
		want  string
	}{
		{name: "parse ok", event: authFSMEventParseOK, want: policy.FSMEventMarkerParseOK},
		{name: "pre auth ok", event: authFSMEventPreAuthOK, want: policy.FSMEventMarkerPreAuthOK},
		{name: "pre auth deny", event: authFSMEventPreAuthDeny, want: policy.FSMEventMarkerPreAuthDeny},
		{name: "auth evaluated", event: authFSMEventAuthEvaluated, want: policy.FSMEventMarkerAuthEvaluated},
		{name: "auth permit", event: authFSMEventAuthPermit, want: policy.FSMEventMarkerAuthPermit},
		{name: "account provider evaluated", event: authFSMEventAccountProviderEvaluated, want: policy.FSMEventMarkerAccountProviderEvaluated},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if string(testCase.event) != testCase.want {
				t.Fatalf("event = %q, want %q", testCase.event, testCase.want)
			}
		})
	}
}
