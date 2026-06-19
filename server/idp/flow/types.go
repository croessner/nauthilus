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

// Type identifies the functional flow that is orchestrated in the IDP.
type Type string

const (
	// FlowTypeUnknown marks an unclassified or invalid flow type.
	FlowTypeUnknown Type = "unknown"
	// FlowTypeOIDCAuthorization is the OIDC authorization-code browser flow.
	FlowTypeOIDCAuthorization Type = "oidc_authorization_code"
	// FlowTypeOIDCDeviceCode is the OIDC device-code user-verification flow.
	FlowTypeOIDCDeviceCode Type = "oidc_device_code"
	// FlowTypeSAML is the SAML SSO browser flow.
	FlowTypeSAML Type = "saml"
	// FlowTypeRequireMFA is the internal mandatory-MFA completion flow.
	FlowTypeRequireMFA Type = "require_mfa"
)

// Valid reports whether the flow type is a known value.
func (f Type) Valid() bool {
	switch f {
	case FlowTypeOIDCAuthorization, FlowTypeOIDCDeviceCode, FlowTypeSAML, FlowTypeRequireMFA:
		return true
	default:
		return false
	}
}

// Protocol identifies the protocol class a flow belongs to.
type Protocol string

const (
	// FlowProtocolUnknown marks an unclassified or invalid protocol.
	FlowProtocolUnknown Protocol = "unknown"
	// FlowProtocolOIDC denotes an OpenID Connect based flow.
	FlowProtocolOIDC Protocol = "oidc"
	// FlowProtocolSAML denotes a SAML based flow.
	FlowProtocolSAML Protocol = "saml"
	// FlowProtocolInternal denotes an internal, non-external-protocol flow.
	FlowProtocolInternal Protocol = "internal"
)

// Valid reports whether the protocol is a known value.
func (p Protocol) Valid() bool {
	switch p {
	case FlowProtocolOIDC, FlowProtocolSAML, FlowProtocolInternal:
		return true
	default:
		return false
	}
}

// Action identifies a user/system action on a step.
type Action string

const (
	// FlowActionStart initializes a new flow instance.
	FlowActionStart Action = "start"
	// FlowActionAdvance transitions forward to the next step.
	FlowActionAdvance Action = "advance"
	// FlowActionResume reconstructs the next redirect for an existing step.
	FlowActionResume Action = "resume"
	// FlowActionBack transitions to a previous allowed step.
	FlowActionBack Action = "back"
	// FlowActionCancel terminates the flow by user/system cancellation.
	FlowActionCancel Action = "cancel"
	// FlowActionComplete finalizes a successful flow.
	FlowActionComplete Action = "complete"
	// FlowActionAbort forcefully terminates the flow due to errors or policy.
	FlowActionAbort Action = "abort"
)

// Valid reports whether the action is a known value.
func (a Action) Valid() bool {
	switch a {
	case FlowActionStart, FlowActionAdvance, FlowActionResume, FlowActionBack, FlowActionCancel, FlowActionComplete, FlowActionAbort:
		return true
	default:
		return false
	}
}

// Step identifies one abstract step in a flow.
type Step string

const (
	// FlowStepStart is the initial pre-authentication step.
	FlowStepStart Step = "start"
	// FlowStepLogin is the primary credential authentication step.
	FlowStepLogin Step = "login"
	// FlowStepRegistration is the optional account registration step.
	FlowStepRegistration Step = "registration"
	// FlowStepMFA is the multi-factor authentication step.
	FlowStepMFA Step = "mfa"
	// FlowStepConsent is the user consent step.
	FlowStepConsent Step = "consent"
	// FlowStepDeviceVerification is the user verification step for device code.
	FlowStepDeviceVerification Step = "device_verification"
	// FlowStepRequireMFAChallenge is the enforced MFA registration/challenge step.
	FlowStepRequireMFAChallenge Step = "require_mfa_challenge"
	// FlowStepCallback is the protocol callback/response preparation step.
	FlowStepCallback Step = "callback"
	// FlowStepDone is the terminal state after successful completion.
	FlowStepDone Step = "done"
)

// Valid reports whether the step is a known value.
func (s Step) Valid() bool {
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
