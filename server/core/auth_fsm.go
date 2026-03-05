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

import "fmt"

type authFSMState string

type authFSMEvent string

const (
	authFSMStateInit            authFSMState = "init"
	authFSMStateInputParsed     authFSMState = "input_parsed"
	authFSMStateFeaturesChecked authFSMState = "features_checked"
	authFSMStatePasswordChecked authFSMState = "password_checked"
	authFSMStateAuthOK          authFSMState = "auth_ok"
	authFSMStateAuthFail        authFSMState = "auth_fail"
	authFSMStateAuthTempFail    authFSMState = "auth_tempfail"
	authFSMStateAborted         authFSMState = "aborted"
)

const (
	authFSMEventParseOK           authFSMEvent = "parse_ok"
	authFSMEventParseFail         authFSMEvent = "parse_fail"
	authFSMEventFeaturesOK        authFSMEvent = "features_ok"
	authFSMEventFeaturesFail      authFSMEvent = "features_fail"
	authFSMEventFeaturesTempFail  authFSMEvent = "features_tempfail"
	authFSMEventFeaturesUnset     authFSMEvent = "features_unset"
	authFSMEventPasswordEvaluated authFSMEvent = "password_evaluated"
	authFSMEventPasswordOK        authFSMEvent = "password_ok"
	authFSMEventPasswordFail      authFSMEvent = "password_fail"
	authFSMEventPasswordTempFail  authFSMEvent = "password_tempfail"
	authFSMEventPasswordEmptyUser authFSMEvent = "password_empty_user"
	authFSMEventPasswordEmptyPass authFSMEvent = "password_empty_pass"
	authFSMEventBasicAuthOK       authFSMEvent = "basic_auth_ok"
	authFSMEventBasicAuthFail     authFSMEvent = "basic_auth_fail"
	authFSMEventAbort             authFSMEvent = "abort"
)

func isAuthFSMTerminal(state authFSMState) bool {
	switch state {
	case authFSMStateAuthOK, authFSMStateAuthFail, authFSMStateAuthTempFail, authFSMStateAborted:
		return true
	default:
		return false
	}
}

func nextAuthFSMState(current authFSMState, event authFSMEvent) (authFSMState, error) {
	if isAuthFSMTerminal(current) {
		return "", fmt.Errorf("invalid auth fsm transition from terminal state: state=%s event=%s", current, event)
	}

	if event == authFSMEventAbort {
		return authFSMStateAborted, nil
	}

	switch current {
	case authFSMStateInit:
		switch event {
		case authFSMEventParseOK:
			return authFSMStateInputParsed, nil
		case authFSMEventParseFail:
			return authFSMStateAborted, nil
		}
	case authFSMStateInputParsed:
		switch event {
		case authFSMEventBasicAuthOK:
			return authFSMStateAuthOK, nil
		case authFSMEventBasicAuthFail:
			return authFSMStateAuthFail, nil
		case authFSMEventFeaturesOK:
			return authFSMStateFeaturesChecked, nil
		case authFSMEventFeaturesFail:
			return authFSMStateAuthFail, nil
		case authFSMEventFeaturesTempFail:
			return authFSMStateAuthTempFail, nil
		case authFSMEventFeaturesUnset:
			return authFSMStateAborted, nil
		}
	case authFSMStateFeaturesChecked:
		switch event {
		case authFSMEventBasicAuthOK:
			return authFSMStateAuthOK, nil
		case authFSMEventBasicAuthFail:
			return authFSMStateAuthFail, nil
		case authFSMEventPasswordEvaluated:
			return authFSMStatePasswordChecked, nil
		}
	case authFSMStatePasswordChecked:
		switch event {
		case authFSMEventPasswordOK:
			return authFSMStateAuthOK, nil
		case authFSMEventPasswordFail:
			return authFSMStateAuthFail, nil
		case authFSMEventPasswordTempFail:
			return authFSMStateAuthTempFail, nil
		case authFSMEventPasswordEmptyUser:
			return authFSMStateAuthTempFail, nil
		case authFSMEventPasswordEmptyPass:
			return authFSMStateAuthFail, nil
		}
	}

	return "", fmt.Errorf("invalid auth fsm transition: state=%s event=%s", current, event)
}
