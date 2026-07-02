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

// Package flow provides flow functionality.
package flow

import "github.com/croessner/nauthilus/v3/server/definitions"

type keyManager interface {
	Delete(key string)
}

var idPFlowStateKeys = [...]string{
	definitions.SessionKeyIDPFlowType,
	definitions.SessionKeyIDPFlowID,
	definitions.SessionKeyIDPAuthOutcome,
	definitions.SessionKeyIDPAuthOutcomeHMAC,
	definitions.SessionKeyIDPAuthStatusMessage,
	definitions.SessionKeyIDPAuthStatusI18NKey,
	definitions.SessionKeyIDPAuthStatusLanguage,
	definitions.SessionKeyOIDCGrantType,
	definitions.SessionKeyIDPClientID,
	definitions.SessionKeyIDPRedirectURI,
	definitions.SessionKeyIDPScope,
	definitions.SessionKeyIDPState,
	definitions.SessionKeyIDPNonce,
	definitions.SessionKeyIDPResponseType,
	definitions.SessionKeyIDPPrompt,
	definitions.SessionKeyIDPCodeChallenge,
	definitions.SessionKeyIDPCodeChallengeMethod,
	definitions.SessionKeyDeviceCode,
	definitions.SessionKeyIDPSAMLRequest,
	definitions.SessionKeyIDPSAMLRelayState,
	definitions.SessionKeyIDPSAMLEntityID,
	definitions.SessionKeyIDPOriginalURL,
	definitions.SessionKeyIDPResumeFallbackURL,
	definitions.SessionKeyIDPResumeFallbackAt,
	definitions.SessionKeyRequireMFAFlow,
	definitions.SessionKeyRequireMFAPending,
	definitions.SessionKeyRequireMFAParentFlowID,
}

var mfaStateKeys = [...]string{
	definitions.SessionKeyUsername,
	definitions.SessionKeyMFAAccount,
	definitions.SessionKeyMFADisplayName,
	definitions.SessionKeyMFAFactorAccount,
	definitions.SessionKeyMFAFactorUniqueUserID,
	definitions.SessionKeyMFAFactorDisplayName,
	definitions.SessionKeyMFAFactorRemoteBackendRefType,
	definitions.SessionKeyMFAFactorRemoteBackendRefName,
	definitions.SessionKeyMFAFactorRemoteBackendRefProtocol,
	definitions.SessionKeyMFAFactorRemoteBackendRefAuthority,
	definitions.SessionKeyMFAFactorRemoteBackendRefToken,
	definitions.SessionKeyUniqueUserID,
	definitions.SessionKeyAuthResult,
	definitions.SessionKeyAuthResultHMAC,
	definitions.SessionKeyMFAMulti,
	definitions.SessionKeyMFAMethod,
	definitions.SessionKeyMFACompleted,
	definitions.SessionKeyRegistration,
}

// CleanupIDPState removes all temporary IDP flow keys from session storage.
func CleanupIDPState(mgr keyManager) {
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
