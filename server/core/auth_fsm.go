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
	"github.com/croessner/nauthilus/v3/server/policy"
	policyfsm "github.com/croessner/nauthilus/v3/server/policy/fsm"
)

type authFSMState string

type authFSMEvent string

const (
	authFSMStateInit                   authFSMState = authFSMState(policyfsm.StateInit)
	authFSMStateInputParsed            authFSMState = authFSMState(policyfsm.StateInputParsed)
	authFSMStatePreAuthChecked         authFSMState = authFSMState(policyfsm.StatePreAuthChecked)
	authFSMStateAuthChecked            authFSMState = authFSMState(policyfsm.StateAuthChecked)
	authFSMStateAccountProviderChecked authFSMState = authFSMState(policyfsm.StateAccountProviderChecked)
	authFSMStateAuthOK                 authFSMState = authFSMState(policyfsm.StateAuthOK)
	authFSMStateAuthFail               authFSMState = authFSMState(policyfsm.StateAuthFail)
	authFSMStateAuthTempFail           authFSMState = authFSMState(policyfsm.StateAuthTempFail)
	authFSMStateAborted                authFSMState = authFSMState(policyfsm.StateAborted)
)

const (
	authFSMEventParseOK                  authFSMEvent = policy.FSMEventMarkerParseOK
	authFSMEventParseFail                authFSMEvent = policy.FSMEventMarkerParseFail
	authFSMEventPreAuthOK                authFSMEvent = policy.FSMEventMarkerPreAuthOK
	authFSMEventPreAuthDeny              authFSMEvent = policy.FSMEventMarkerPreAuthDeny
	authFSMEventPreAuthTempFail          authFSMEvent = policy.FSMEventMarkerPreAuthTempFail
	authFSMEventPreAuthAbort             authFSMEvent = policy.FSMEventMarkerPreAuthAbort
	authFSMEventAuthEvaluated            authFSMEvent = policy.FSMEventMarkerAuthEvaluated
	authFSMEventAccountProviderEvaluated authFSMEvent = policy.FSMEventMarkerAccountProviderEvaluated
	authFSMEventAuthPermit               authFSMEvent = policy.FSMEventMarkerAuthPermit
	authFSMEventAuthDeny                 authFSMEvent = policy.FSMEventMarkerAuthDeny
	authFSMEventAuthTempFail             authFSMEvent = policy.FSMEventMarkerAuthTempFail
	authFSMEventAuthEmptyUser            authFSMEvent = policy.FSMEventMarkerAuthEmptyUser
	authFSMEventAuthEmptyPass            authFSMEvent = policy.FSMEventMarkerAuthEmptyPass
	authFSMEventBasicAuthOK              authFSMEvent = policy.FSMEventMarkerBasicAuthOK
	authFSMEventBasicAuthFail            authFSMEvent = policy.FSMEventMarkerBasicAuthFail
	authFSMEventAbort                    authFSMEvent = policy.FSMEventMarkerAbort
)

func isAuthFSMTerminal(state authFSMState) bool {
	return policyfsm.IsTerminal(string(state))
}

func nextAuthFSMState(current authFSMState, event authFSMEvent) (authFSMState, error) {
	next, err := policyfsm.NextState(string(current), string(event))
	if err != nil {
		return "", err
	}

	return authFSMState(next), nil
}
