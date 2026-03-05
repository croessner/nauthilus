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

import "fmt"

type hookAuthzFSMState string

type hookAuthzFSMEvent string

const (
	hookAuthzStateStart         hookAuthzFSMState = "start"
	hookAuthzStateScopesChecked hookAuthzFSMState = "scopes_checked"
	hookAuthzStateTokenChecked  hookAuthzFSMState = "token_checked"
	hookAuthzStateAuthorized    hookAuthzFSMState = "authorized"
	hookAuthzStateUnauthorized  hookAuthzFSMState = "unauthorized"
	hookAuthzStateForbidden     hookAuthzFSMState = "forbidden"
)

const (
	hookAuthzEventNoScopes         hookAuthzFSMEvent = "no_scopes"
	hookAuthzEventScopesRequired   hookAuthzFSMEvent = "scopes_required"
	hookAuthzEventValidatorMissing hookAuthzFSMEvent = "validator_missing"
	hookAuthzEventTokenMissing     hookAuthzFSMEvent = "token_missing"
	hookAuthzEventTokenValid       hookAuthzFSMEvent = "token_valid"
	hookAuthzEventTokenInvalid     hookAuthzFSMEvent = "token_invalid"
	hookAuthzEventScopeMatch       hookAuthzFSMEvent = "scope_match"
	hookAuthzEventScopeMiss        hookAuthzFSMEvent = "scope_miss"
)

func isHookAuthzTerminal(state hookAuthzFSMState) bool {
	switch state {
	case hookAuthzStateAuthorized, hookAuthzStateUnauthorized, hookAuthzStateForbidden:
		return true
	default:
		return false
	}
}

func nextHookAuthzFSMState(current hookAuthzFSMState, event hookAuthzFSMEvent) (hookAuthzFSMState, error) {
	if isHookAuthzTerminal(current) {
		return "", fmt.Errorf("invalid hook authz transition from terminal state: state=%s event=%s", current, event)
	}

	switch current {
	case hookAuthzStateStart:
		switch event {
		case hookAuthzEventNoScopes:
			return hookAuthzStateAuthorized, nil
		case hookAuthzEventScopesRequired:
			return hookAuthzStateScopesChecked, nil
		}
	case hookAuthzStateScopesChecked:
		switch event {
		case hookAuthzEventValidatorMissing, hookAuthzEventTokenMissing, hookAuthzEventTokenInvalid:
			return hookAuthzStateUnauthorized, nil
		case hookAuthzEventTokenValid:
			return hookAuthzStateTokenChecked, nil
		}
	case hookAuthzStateTokenChecked:
		switch event {
		case hookAuthzEventScopeMatch:
			return hookAuthzStateAuthorized, nil
		case hookAuthzEventScopeMiss:
			return hookAuthzStateForbidden, nil
		}
	}

	return "", fmt.Errorf("invalid hook authz transition: state=%s event=%s", current, event)
}
