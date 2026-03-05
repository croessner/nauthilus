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
			name:    "InputFeaturesOK",
			current: authFSMStateInputParsed,
			event:   authFSMEventFeaturesOK,
			next:    authFSMStateFeaturesChecked,
		},
		{
			name:    "FeaturesPasswordEvaluated",
			current: authFSMStateFeaturesChecked,
			event:   authFSMEventPasswordEvaluated,
			next:    authFSMStatePasswordChecked,
		},
		{
			name:    "FeaturesBasicAuthOK",
			current: authFSMStateFeaturesChecked,
			event:   authFSMEventBasicAuthOK,
			next:    authFSMStateAuthOK,
		},
		{
			name:    "FeaturesBasicAuthFail",
			current: authFSMStateFeaturesChecked,
			event:   authFSMEventBasicAuthFail,
			next:    authFSMStateAuthFail,
		},
		{
			name:    "PasswordCheckedPasswordOK",
			current: authFSMStatePasswordChecked,
			event:   authFSMEventPasswordOK,
			next:    authFSMStateAuthOK,
		},
		{
			name:    "PasswordCheckedPasswordEmptyUser",
			current: authFSMStatePasswordChecked,
			event:   authFSMEventPasswordEmptyUser,
			next:    authFSMStateAuthTempFail,
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
			event:   authFSMEventPasswordOK,
		},
		{
			name:    "InvalidPasswordEventFromInputParsed",
			current: authFSMStateInputParsed,
			event:   authFSMEventPasswordFail,
		},
		{
			name:    "InvalidDirectPasswordEventFromFeaturesChecked",
			current: authFSMStateFeaturesChecked,
			event:   authFSMEventPasswordOK,
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

func TestMapAuthFeatureResultToFSMEvent(t *testing.T) {
	tests := []struct {
		name    string
		result  definitions.AuthResult
		wantEvt authFSMEvent
		wantOK  bool
	}{
		{
			name:    "FeatureTLS",
			result:  definitions.AuthResultFeatureTLS,
			wantEvt: authFSMEventFeaturesTempFail,
			wantOK:  true,
		},
		{
			name:    "FeatureRelayDomain",
			result:  definitions.AuthResultFeatureRelayDomain,
			wantEvt: authFSMEventFeaturesFail,
			wantOK:  true,
		},
		{
			name:    "FeatureOK",
			result:  definitions.AuthResultOK,
			wantEvt: authFSMEventFeaturesOK,
			wantOK:  true,
		},
		{
			name:    "FeatureUnset",
			result:  definitions.AuthResultUnset,
			wantEvt: authFSMEventFeaturesUnset,
			wantOK:  true,
		},
		{
			name:   "Unsupported",
			result: definitions.AuthResultEmptyUsername,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotEvt, gotOK := mapAuthFeatureResultToFSMEvent(tc.result)
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
			wantEvt: authFSMEventPasswordOK,
			wantOK:  true,
		},
		{
			name:    "PasswordFail",
			result:  definitions.AuthResultFail,
			wantEvt: authFSMEventPasswordFail,
			wantOK:  true,
		},
		{
			name:    "PasswordTempFail",
			result:  definitions.AuthResultTempFail,
			wantEvt: authFSMEventPasswordTempFail,
			wantOK:  true,
		},
		{
			name:    "PasswordEmptyUsername",
			result:  definitions.AuthResultEmptyUsername,
			wantEvt: authFSMEventPasswordEmptyUser,
			wantOK:  true,
		},
		{
			name:    "PasswordEmptyPassword",
			result:  definitions.AuthResultEmptyPassword,
			wantEvt: authFSMEventPasswordEmptyPass,
			wantOK:  true,
		},
		{
			name:   "Unsupported",
			result: definitions.AuthResultFeatureTLS,
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

func TestMapBasicAuthCheckToFSMEvent(t *testing.T) {
	if got := mapBasicAuthCheckToFSMEvent(true); got != authFSMEventBasicAuthOK {
		t.Fatalf("expected %s, got %s", authFSMEventBasicAuthOK, got)
	}

	if got := mapBasicAuthCheckToFSMEvent(false); got != authFSMEventBasicAuthFail {
		t.Fatalf("expected %s, got %s", authFSMEventBasicAuthFail, got)
	}
}
