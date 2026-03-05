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

package hook

import "testing"

func TestNextHookAuthzFSMState_AllowedTransitions(t *testing.T) {
	tests := []struct {
		name    string
		current hookAuthzFSMState
		event   hookAuthzFSMEvent
		next    hookAuthzFSMState
	}{
		{
			name:    "StartNoScopes",
			current: hookAuthzStateStart,
			event:   hookAuthzEventNoScopes,
			next:    hookAuthzStateAuthorized,
		},
		{
			name:    "StartScopesRequired",
			current: hookAuthzStateStart,
			event:   hookAuthzEventScopesRequired,
			next:    hookAuthzStateScopesChecked,
		},
		{
			name:    "ScopesCheckedValidatorMissing",
			current: hookAuthzStateScopesChecked,
			event:   hookAuthzEventValidatorMissing,
			next:    hookAuthzStateUnauthorized,
		},
		{
			name:    "ScopesCheckedTokenMissing",
			current: hookAuthzStateScopesChecked,
			event:   hookAuthzEventTokenMissing,
			next:    hookAuthzStateUnauthorized,
		},
		{
			name:    "ScopesCheckedTokenInvalid",
			current: hookAuthzStateScopesChecked,
			event:   hookAuthzEventTokenInvalid,
			next:    hookAuthzStateUnauthorized,
		},
		{
			name:    "ScopesCheckedTokenValid",
			current: hookAuthzStateScopesChecked,
			event:   hookAuthzEventTokenValid,
			next:    hookAuthzStateTokenChecked,
		},
		{
			name:    "TokenCheckedScopeMatch",
			current: hookAuthzStateTokenChecked,
			event:   hookAuthzEventScopeMatch,
			next:    hookAuthzStateAuthorized,
		},
		{
			name:    "TokenCheckedScopeMiss",
			current: hookAuthzStateTokenChecked,
			event:   hookAuthzEventScopeMiss,
			next:    hookAuthzStateForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next, err := nextHookAuthzFSMState(tc.current, tc.event)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if next != tc.next {
				t.Fatalf("expected next=%s, got %s", tc.next, next)
			}
		})
	}
}

func TestNextHookAuthzFSMState_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name    string
		current hookAuthzFSMState
		event   hookAuthzFSMEvent
	}{
		{
			name:    "InvalidEventFromStart",
			current: hookAuthzStateStart,
			event:   hookAuthzEventTokenValid,
		},
		{
			name:    "InvalidEventFromScopesChecked",
			current: hookAuthzStateScopesChecked,
			event:   hookAuthzEventScopeMatch,
		},
		{
			name:    "NoTransitionsFromTerminal",
			current: hookAuthzStateAuthorized,
			event:   hookAuthzEventScopeMiss,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := nextHookAuthzFSMState(tc.current, tc.event)
			if err == nil {
				t.Fatal("expected transition error, got nil")
			}
		})
	}
}
