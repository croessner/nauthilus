// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import "github.com/croessner/nauthilus/v3/server/definitions"

// Owner is the sole future persistence owner of legacy browser-session state.
type Owner string

// Owner values name the exclusive durable owner for each legacy field.
const (
	OwnerEnvelope         Owner = "envelope"
	OwnerSessionAnchor    Owner = "session_anchor"
	OwnerOIDCFlow         Owner = "oidc_flow"
	OwnerSAMLFlow         Owner = "saml_flow"
	OwnerSelfServiceFlow  Owner = "self_service_flow"
	OwnerEnrollment       Owner = "required_mfa_enrollment"
	OwnerStepUp           Owner = "step_up"
	OwnerWebAuthnCeremony Owner = "webauthn_ceremony"
	OwnerTOTPRecovery     Owner = "totp_recovery"
	OwnerConsent          Owner = "consent_logout_indexes"
	OwnerProtocolSession  Owner = "protocol_session"
	OwnerDeletion         Owner = "deletion"
)

// LegacyCookieKeyCount is the audited number of legacy primary-cookie fields.
const LegacyCookieKeyCount = 84

// LegacyCookieItem gives one legacy field exactly one future persistence owner.
type LegacyCookieItem struct {
	Name  string
	Key   string
	Owner Owner
}

// LegacyCookieInventory returns the complete audited primary-cookie ownership map.
func LegacyCookieInventory() []LegacyCookieItem {
	items := make([]LegacyCookieItem, 0, LegacyCookieKeyCount)
	items = append(items, identityCookieInventory()...)
	items = append(items, mfaMaterialCookieInventory()...)
	items = append(items, protocolFlowCookieInventory()...)
	items = append(items, stepUpCookieInventory()...)

	return items
}

// identityCookieInventory classifies identity, affinity, and login-session fields.
func identityCookieInventory() []LegacyCookieItem {
	return []LegacyCookieItem{
		{"SessionKeyAccount", definitions.SessionKeyAccount, OwnerSessionAnchor},
		{"SessionKeyHaveTOTP", definitions.SessionKeyHaveTOTP, OwnerSessionAnchor},
		{"SessionKeyHaveWebAuthn", definitions.SessionKeyHaveWebAuthn, OwnerSessionAnchor},
		{"SessionKeyHaveRecoveryCodes", definitions.SessionKeyHaveRecoveryCodes, OwnerSessionAnchor},
		{"SessionKeyTOTPURL", definitions.SessionKeyTOTPURL, OwnerTOTPRecovery},
		{"SessionKeyUserBackend", definitions.SessionKeyUserBackend, OwnerSessionAnchor},
		{"SessionKeyUserBackendName", definitions.SessionKeyUserBackendName, OwnerSessionAnchor},
		{"SessionKeyRemoteBackendRefType", definitions.SessionKeyRemoteBackendRefType, OwnerSessionAnchor},
		{"SessionKeyRemoteBackendRefName", definitions.SessionKeyRemoteBackendRefName, OwnerSessionAnchor},
		{"SessionKeyRemoteBackendRefProtocol", definitions.SessionKeyRemoteBackendRefProtocol, OwnerSessionAnchor},
		{"SessionKeyRemoteBackendRefAuthority", definitions.SessionKeyRemoteBackendRefAuthority, OwnerSessionAnchor},
		{"SessionKeyRemoteBackendRefToken", definitions.SessionKeyRemoteBackendRefToken, OwnerSessionAnchor},
		{"SessionKeyMFAFactorRemoteBackendRefType", definitions.SessionKeyMFAFactorRemoteBackendRefType, OwnerStepUp},
		{"SessionKeyMFAFactorRemoteBackendRefName", definitions.SessionKeyMFAFactorRemoteBackendRefName, OwnerStepUp},
		{"SessionKeyMFAFactorRemoteBackendRefProtocol", definitions.SessionKeyMFAFactorRemoteBackendRefProtocol, OwnerStepUp},
		{"SessionKeyMFAFactorRemoteBackendRefAuthority", definitions.SessionKeyMFAFactorRemoteBackendRefAuthority, OwnerStepUp},
		{"SessionKeyMFAFactorRemoteBackendRefToken", definitions.SessionKeyMFAFactorRemoteBackendRefToken, OwnerStepUp},
		{"SessionKeyUniqueUserID", definitions.SessionKeyUniqueUserID, OwnerSessionAnchor},
		{"SessionKeyDisplayName", definitions.SessionKeyDisplayName, OwnerSessionAnchor},
		{"SessionKeyLang", definitions.SessionKeyLang, OwnerDeletion},
		{"SessionKeyUsername", definitions.SessionKeyUsername, OwnerProtocolSession},
		{"SessionKeyMFAAccount", definitions.SessionKeyMFAAccount, OwnerStepUp},
		{"SessionKeyMFADisplayName", definitions.SessionKeyMFADisplayName, OwnerStepUp},
		{"SessionKeyMFAFactorAccount", definitions.SessionKeyMFAFactorAccount, OwnerStepUp},
		{"SessionKeyMFAFactorUniqueUserID", definitions.SessionKeyMFAFactorUniqueUserID, OwnerStepUp},
		{"SessionKeyMFAFactorDisplayName", definitions.SessionKeyMFAFactorDisplayName, OwnerStepUp},
		{"SessionKeyAuthResult", definitions.SessionKeyAuthResult, OwnerSessionAnchor},
		{"SessionKeyAuthResultHMAC", definitions.SessionKeyAuthResultHMAC, OwnerSessionAnchor},
		{"SessionKeyLoginError", definitions.SessionKeyLoginError, OwnerProtocolSession},
		{"SessionKeyIDPAuthStatusMessage", definitions.SessionKeyIDPAuthStatusMessage, OwnerProtocolSession},
		{"SessionKeyIDPAuthStatusI18NKey", definitions.SessionKeyIDPAuthStatusI18NKey, OwnerProtocolSession},
		{"SessionKeyIDPAuthStatusLanguage", definitions.SessionKeyIDPAuthStatusLanguage, OwnerProtocolSession},
		{"SessionKeySubject", definitions.SessionKeySubject, OwnerOIDCFlow},
		{"SessionKeyRememberTTL", definitions.SessionKeyRememberTTL, OwnerSessionAnchor},
	}
}

// mfaMaterialCookieInventory classifies MFA material, consent, and shared flow fields.
func mfaMaterialCookieInventory() []LegacyCookieItem {
	return []LegacyCookieItem{
		{"SessionKeyMFAMulti", definitions.SessionKeyMFAMulti, OwnerStepUp},
		{"SessionKeyRegistration", definitions.SessionKeyRegistration, OwnerWebAuthnCeremony},
		{"SessionKeyWebAuthnCeremony", definitions.SessionKeyWebAuthnCeremony, OwnerWebAuthnCeremony},
		{"SessionKeyTOTPSecret", definitions.SessionKeyTOTPSecret, OwnerTOTPRecovery},
		{"SessionKeyTOTPPendingRegistration", definitions.SessionKeyTOTPPendingRegistration, OwnerTOTPRecovery},
		{"SessionKeyTOTPOperationID", definitions.SessionKeyTOTPOperationID, OwnerTOTPRecovery},
		{"SessionKeyRecoveryCodes", definitions.SessionKeyRecoveryCodes, OwnerTOTPRecovery},
		{"SessionKeyRecoveryCodesRemoteGenerated", definitions.SessionKeyRecoveryCodesRemoteGenerated, OwnerTOTPRecovery},
		{"SessionKeyRecoveryOperationID", definitions.SessionKeyRecoveryOperationID, OwnerTOTPRecovery},
		{"SessionKeyRecoveryCodesSaved", definitions.SessionKeyRecoveryCodesSaved, OwnerTOTPRecovery},
		{"SessionKeyProtocol", definitions.SessionKeyProtocol, OwnerProtocolSession},
		{"SessionKeyOIDCClients", definitions.SessionKeyOIDCClients, OwnerConsent},
		{"SessionKeyOIDCConsentExpiries", definitions.SessionKeyOIDCConsentExpiries, OwnerConsent},
		{"SessionKeyIDPFlowType", definitions.SessionKeyIDPFlowType, OwnerProtocolSession},
		{"SessionKeyIDPFlowID", definitions.SessionKeyIDPFlowID, OwnerProtocolSession},
		{"SessionKeyIDPAuthOutcome", definitions.SessionKeyIDPAuthOutcome, OwnerProtocolSession},
		{"SessionKeyIDPAuthOutcomeHMAC", definitions.SessionKeyIDPAuthOutcomeHMAC, OwnerProtocolSession},
	}
}

// protocolFlowCookieInventory classifies OIDC, SAML, and protocol-resume fields.
func protocolFlowCookieInventory() []LegacyCookieItem {
	return []LegacyCookieItem{
		{"SessionKeyIDPClientID", definitions.SessionKeyIDPClientID, OwnerOIDCFlow},
		{"SessionKeyIDPRequiredMFALevel", definitions.SessionKeyIDPRequiredMFALevel, OwnerOIDCFlow},
		{"SessionKeyIDPRedirectURI", definitions.SessionKeyIDPRedirectURI, OwnerOIDCFlow},
		{"SessionKeyIDPScope", definitions.SessionKeyIDPScope, OwnerOIDCFlow},
		{"SessionKeyIDPState", definitions.SessionKeyIDPState, OwnerOIDCFlow},
		{"SessionKeyIDPNonce", definitions.SessionKeyIDPNonce, OwnerOIDCFlow},
		{"SessionKeyIDPResponseType", definitions.SessionKeyIDPResponseType, OwnerOIDCFlow},
		{"SessionKeyIDPPrompt", definitions.SessionKeyIDPPrompt, OwnerOIDCFlow},
		{"SessionKeyIDPCodeChallenge", definitions.SessionKeyIDPCodeChallenge, OwnerOIDCFlow},
		{"SessionKeyIDPCodeChallengeMethod", definitions.SessionKeyIDPCodeChallengeMethod, OwnerOIDCFlow},
		{"SessionKeyIDPSAMLRequest", definitions.SessionKeyIDPSAMLRequest, OwnerSAMLFlow},
		{"SessionKeyIDPSAMLRelayState", definitions.SessionKeyIDPSAMLRelayState, OwnerSAMLFlow},
		{"SessionKeyIDPSAMLEntityID", definitions.SessionKeyIDPSAMLEntityID, OwnerSAMLFlow},
		{"SessionKeyIDPOriginalURL", definitions.SessionKeyIDPOriginalURL, OwnerProtocolSession},
		{"SessionKeyIDPResumeFallbackURL", definitions.SessionKeyIDPResumeFallbackURL, OwnerProtocolSession},
		{"SessionKeyIDPResumeFallbackAt", definitions.SessionKeyIDPResumeFallbackAt, OwnerProtocolSession},
		{"SessionKeyDeviceCode", definitions.SessionKeyDeviceCode, OwnerOIDCFlow},
		{"SessionKeyOIDCGrantType", definitions.SessionKeyOIDCGrantType, OwnerOIDCFlow},
	}
}

// stepUpCookieInventory classifies dynamic assurance, enrollment, and self-service fields.
func stepUpCookieInventory() []LegacyCookieItem {
	return []LegacyCookieItem{
		{"SessionKeyMFACompleted", definitions.SessionKeyMFACompleted, OwnerStepUp},
		{"SessionKeyMFAMethod", definitions.SessionKeyMFAMethod, OwnerStepUp},
		{"SessionKeyMFAAssuranceAt", definitions.SessionKeyMFAAssuranceAt, OwnerStepUp},
		{"SessionKeyMFAAssuranceMethod", definitions.SessionKeyMFAAssuranceMethod, OwnerStepUp},
		{"SessionKeyMFAAssuranceLevel", definitions.SessionKeyMFAAssuranceLevel, OwnerStepUp},
		{"SessionKeyMFAAssuranceScope", definitions.SessionKeyMFAAssuranceScope, OwnerStepUp},
		{"SessionKeyRequireMFAFlow", definitions.SessionKeyRequireMFAFlow, OwnerEnrollment},
		{"SessionKeyRequireMFAPending", definitions.SessionKeyRequireMFAPending, OwnerEnrollment},
		{"SessionKeyRequireMFAParentFlowID", definitions.SessionKeyRequireMFAParentFlowID, OwnerEnrollment},
		{"sessionKeyMFASelfServiceStepUpAction", "mfa_self_service_step_up_action", OwnerStepUp},
		{"sessionKeyMFASelfServiceStepUpReturn", "mfa_self_service_step_up_return", OwnerStepUp},
		{"sessionKeyMFASelfServiceStepUpAt", "mfa_self_service_step_up_at", OwnerStepUp},
		{"sessionKeyMFASelfServiceStepUpAccount", "mfa_self_service_step_up_account", OwnerStepUp},
		{"sessionKeyMFASelfServiceStepUpWebAuthnCredentialID", "mfa_self_service_step_up_webauthn_credential_id", OwnerStepUp},
		{"sessionKeyMFASelfServiceStepUpWebAuthnDeviceName", "mfa_self_service_step_up_webauthn_device_name", OwnerStepUp},
	}
}
