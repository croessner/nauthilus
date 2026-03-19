// Copyright (C) 2025 Christian Rößner
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

package flow

import "github.com/croessner/nauthilus/server/definitions"

type keyManager interface {
	Delete(key string)
}

var idPFlowStateKeys = [...]string{
	definitions.SessionKeyIdPFlowType,
	definitions.SessionKeyIdPFlowID,
	definitions.SessionKeyIdPAuthOutcome,
	definitions.SessionKeyIdPAuthOutcomeHMAC,
	definitions.SessionKeyOIDCGrantType,
	definitions.SessionKeyIdPClientID,
	definitions.SessionKeyIdPRedirectURI,
	definitions.SessionKeyIdPScope,
	definitions.SessionKeyIdPState,
	definitions.SessionKeyIdPNonce,
	definitions.SessionKeyIdPResponseType,
	definitions.SessionKeyIdPPrompt,
	definitions.SessionKeyIdPCodeChallenge,
	definitions.SessionKeyIdPCodeChallengeMethod,
	definitions.SessionKeyDeviceCode,
	definitions.SessionKeyIdPSAMLRequest,
	definitions.SessionKeyIdPSAMLRelayState,
	definitions.SessionKeyIdPSAMLEntityID,
	definitions.SessionKeyIdPOriginalURL,
	definitions.SessionKeyRequireMFAFlow,
	definitions.SessionKeyRequireMFAPending,
	definitions.SessionKeyRequireMFAParentFlowID,
}

var mfaStateKeys = [...]string{
	definitions.SessionKeyUsername,
	definitions.SessionKeyUniqueUserID,
	definitions.SessionKeyAuthResult,
	definitions.SessionKeyAuthResultHMAC,
	definitions.SessionKeyMFAMulti,
	definitions.SessionKeyMFAMethod,
	definitions.SessionKeyMFACompleted,
	definitions.SessionKeyRegistration,
}

// CleanupIdPState removes all temporary IdP flow keys from session storage.
func CleanupIdPState(mgr keyManager) {
	if mgr == nil {
		return
	}

	for _, key := range idPFlowStateKeys {
		mgr.Delete(key)
	}
}

// CleanupMFAState removes temporary MFA flow keys from session storage.
func CleanupMFAState(mgr keyManager) {
	if mgr == nil {
		return
	}

	for _, key := range mfaStateKeys {
		mgr.Delete(key)
	}
}
