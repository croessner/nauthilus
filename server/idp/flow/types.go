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

// FlowType identifies the functional flow that is orchestrated in the IdP.
type FlowType string

const (
	// FlowTypeUnknown marks an unclassified or invalid flow type.
	FlowTypeUnknown FlowType = "unknown"
	// FlowTypeOIDCAuthorization is the OIDC authorization-code browser flow.
	FlowTypeOIDCAuthorization FlowType = "oidc_authorization_code"
	// FlowTypeOIDCDeviceCode is the OIDC device-code user-verification flow.
	FlowTypeOIDCDeviceCode FlowType = "oidc_device_code"
	// FlowTypeSAML is the SAML SSO browser flow.
	FlowTypeSAML FlowType = "saml"
	// FlowTypeRequireMFA is the internal mandatory-MFA completion flow.
	FlowTypeRequireMFA FlowType = "require_mfa"
)

// Valid reports whether the flow type is a known value.
func (f FlowType) Valid() bool {
	switch f {
	case FlowTypeOIDCAuthorization, FlowTypeOIDCDeviceCode, FlowTypeSAML, FlowTypeRequireMFA:
		return true
	default:
		return false
	}
}

// FlowProtocol identifies the protocol class a flow belongs to.
type FlowProtocol string

const (
	// FlowProtocolUnknown marks an unclassified or invalid protocol.
	FlowProtocolUnknown FlowProtocol = "unknown"
	// FlowProtocolOIDC denotes an OpenID Connect based flow.
	FlowProtocolOIDC FlowProtocol = "oidc"
	// FlowProtocolSAML denotes a SAML based flow.
	FlowProtocolSAML FlowProtocol = "saml"
	// FlowProtocolInternal denotes an internal, non-external-protocol flow.
	FlowProtocolInternal FlowProtocol = "internal"
)

// Valid reports whether the protocol is a known value.
func (p FlowProtocol) Valid() bool {
	switch p {
	case FlowProtocolOIDC, FlowProtocolSAML, FlowProtocolInternal:
		return true
	default:
		return false
	}
}

// FlowAction identifies a user/system action on a step.
type FlowAction string

const (
	// FlowActionStart initializes a new flow instance.
	FlowActionStart FlowAction = "start"
	// FlowActionAdvance transitions forward to the next step.
	FlowActionAdvance FlowAction = "advance"
	// FlowActionResume reconstructs the next redirect for an existing step.
	FlowActionResume FlowAction = "resume"
	// FlowActionBack transitions to a previous allowed step.
	FlowActionBack FlowAction = "back"
	// FlowActionCancel terminates the flow by user/system cancellation.
	FlowActionCancel FlowAction = "cancel"
	// FlowActionComplete finalizes a successful flow.
	FlowActionComplete FlowAction = "complete"
	// FlowActionAbort forcefully terminates the flow due to errors or policy.
	FlowActionAbort FlowAction = "abort"
)

// Valid reports whether the action is a known value.
func (a FlowAction) Valid() bool {
	switch a {
	case FlowActionStart, FlowActionAdvance, FlowActionResume, FlowActionBack, FlowActionCancel, FlowActionComplete, FlowActionAbort:
		return true
	default:
		return false
	}
}

// FlowStep identifies one abstract step in a flow.
type FlowStep string

const (
	// FlowStepStart is the initial pre-authentication step.
	FlowStepStart FlowStep = "start"
	// FlowStepLogin is the primary credential authentication step.
	FlowStepLogin FlowStep = "login"
	// FlowStepRegistration is the optional account registration step.
	FlowStepRegistration FlowStep = "registration"
	// FlowStepMFA is the multi-factor authentication step.
	FlowStepMFA FlowStep = "mfa"
	// FlowStepConsent is the user consent step.
	FlowStepConsent FlowStep = "consent"
	// FlowStepDeviceVerification is the user verification step for device code.
	FlowStepDeviceVerification FlowStep = "device_verification"
	// FlowStepRequireMFAChallenge is the enforced MFA registration/challenge step.
	FlowStepRequireMFAChallenge FlowStep = "require_mfa_challenge"
	// FlowStepCallback is the protocol callback/response preparation step.
	FlowStepCallback FlowStep = "callback"
	// FlowStepDone is the terminal state after successful completion.
	FlowStepDone FlowStep = "done"
)

// Valid reports whether the step is a known value.
func (s FlowStep) Valid() bool {
	switch s {
	case FlowStepStart,
		FlowStepLogin,
		FlowStepRegistration,
		FlowStepMFA,
		FlowStepConsent,
		FlowStepDeviceVerification,
		FlowStepRequireMFAChallenge,
		FlowStepCallback,
		FlowStepDone:
		return true
	default:
		return false
	}
}
