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

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	// FlowIDRequireMFA identifies the durable flow used by required MFA registration.
	FlowIDRequireMFA = "require-mfa-flow"
	// FlowMetadataResumeTarget is an exported package constant.
	FlowMetadataResumeTarget = "resume_target"
	// FlowMetadataResumeTargetDeviceCodeComplete is an exported package constant.
	FlowMetadataResumeTargetDeviceCodeComplete = "nauthilus://idp/device-code/complete"
	// FlowMetadataClientID stores the OIDC client identifier.
	FlowMetadataClientID = "client_id"
	// FlowMetadataRedirectURI stores the OIDC redirect URI.
	FlowMetadataRedirectURI = "redirect_uri"
	// FlowMetadataScope stores the requested OIDC scope string.
	FlowMetadataScope = "scope"
	// FlowMetadataState stores the OIDC state value.
	FlowMetadataState = "state"
	// FlowMetadataNonce stores the OIDC nonce value.
	FlowMetadataNonce = "nonce"
	// FlowMetadataResponseType stores the OIDC response type.
	FlowMetadataResponseType = "response_type"
	// FlowMetadataPrompt stores the OIDC prompt value.
	FlowMetadataPrompt = "prompt"
	// FlowMetadataCodeChallenge stores the PKCE code challenge.
	FlowMetadataCodeChallenge = "code_challenge"
	// FlowMetadataCodeChallengeMethod stores the PKCE code challenge method.
	FlowMetadataCodeChallengeMethod = "code_challenge_method"
	// FlowMetadataSAMLEntityID stores the SAML entity identifier.
	FlowMetadataSAMLEntityID = "saml_entity_id"
	// FlowMetadataOriginalURL stores the original frontend URL.
	FlowMetadataOriginalURL = "original_url"
	// FlowMetadataDeviceCode stores the OAuth 2.0 device code.
	FlowMetadataDeviceCode = "device_code"
	// FlowMetadataAccount stores the authenticated account name across required MFA hops.
	FlowMetadataAccount = "account"
	// FlowMetadataUniqueUserID stores the backend unique user id across required MFA hops.
	FlowMetadataUniqueUserID = "unique_user_id"
	// FlowMetadataDisplayName stores the display name across required MFA hops.
	FlowMetadataDisplayName = "display_name"
)

const requireMFAFlowIDSeparator = ":"

// NewRequireMFAFlowID derives a bounded required-MFA sub-flow identifier from a parent flow.
func NewRequireMFAFlowID(parentFlowID string) string {
	parentFlowID = strings.TrimSpace(parentFlowID)
	if parentFlowID == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(parentFlowID))

	return FlowIDRequireMFA + requireMFAFlowIDSeparator + hex.EncodeToString(sum[:])
}

// IsRequireMFAFlowID reports whether a flow id belongs to an isolated required-MFA sub-flow.
func IsRequireMFAFlowID(flowID string) bool {
	return strings.HasPrefix(flowID, FlowIDRequireMFA+requireMFAFlowIDSeparator)
}

// State stores the domain-level state of an IDP flow.
type State struct {
	FlowID       string            `json:"flow_id"`
	GrantType    string            `json:"grant_type,omitzero"`
	CancelTarget string            `json:"cancel_target,omitzero"`
	ReturnTarget string            `json:"return_target,omitzero"`
	Metadata     map[string]string `json:"metadata,omitzero"`
	Type         Type              `json:"flow_type"`
	Protocol     Protocol          `json:"protocol"`
	CurrentStep  Step              `json:"current_step"`
	AuthOutcome  AuthOutcome       `json:"auth_outcome,omitzero"`
	CreatedAt    time.Time         `json:"created_at,omitzero"`
	UpdatedAt    time.Time         `json:"updated_at,omitzero"`
	PendingMFA   bool              `json:"pending_mfa"`
}

// AuthOutcome captures the first-factor authentication result relevant for flow transitions.
type AuthOutcome string

const (
	// AuthOutcomeUnknown means no first-factor decision is persisted yet.
	AuthOutcomeUnknown AuthOutcome = "unknown"
	// AuthOutcomeOK means first-factor authentication succeeded.
	AuthOutcomeOK AuthOutcome = "ok"
	// AuthOutcomeFailLatched means first-factor authentication failed and must stay denied until flow termination.
	AuthOutcomeFailLatched AuthOutcome = "fail_latched"
)

// Valid reports whether the auth outcome is a known value.
func (a AuthOutcome) Valid() bool {
	switch a {
	case AuthOutcomeUnknown, AuthOutcomeOK, AuthOutcomeFailLatched:
		return true
	default:
		return false
	}
}

// Normalize ensures optional state fields use canonical in-memory values.
func (s *State) Normalize(now time.Time) {
	if s.Metadata == nil {
		s.Metadata = make(map[string]string)
	}

	if s.AuthOutcome == "" {
		s.AuthOutcome = AuthOutcomeUnknown
	}

	if s.CreatedAt.IsZero() {
		s.CreatedAt = now.UTC()
	}

	s.UpdatedAt = now.UTC()
}

// Validate ensures the state can be used by flow domain services.
func (s *State) Validate() error {
	if s == nil {
		return fmt.Errorf("flow state: %w", ErrEmptyFlowID)
	}

	if s.FlowID == "" {
		return fmt.Errorf("flow state: %w", ErrEmptyFlowID)
	}

	if !s.Type.Valid() {
		return fmt.Errorf("flow state: %w (%s)", ErrInvalidFlowType, s.Type)
	}

	if !s.Protocol.Valid() {
		return fmt.Errorf("flow state: %w (%s)", ErrInvalidProtocol, s.Protocol)
	}

	if !s.CurrentStep.Valid() {
		return fmt.Errorf("flow state: %w (%s)", ErrInvalidStep, s.CurrentStep)
	}

	if !s.AuthOutcome.Valid() {
		return fmt.Errorf("flow state: %w (%s)", ErrInvalidAuthOutcome, s.AuthOutcome)
	}

	return nil
}

// UpdateAuthOutcome applies a new first-factor outcome to the state.
// The fail-latched value is terminal for the flow and cannot be overwritten.
func (s *State) UpdateAuthOutcome(next AuthOutcome) error {
	if s == nil {
		return fmt.Errorf("flow state: %w", ErrEmptyFlowID)
	}

	if !next.Valid() {
		return fmt.Errorf("flow state: %w (%s)", ErrInvalidAuthOutcome, next)
	}

	if s.AuthOutcome == "" {
		s.AuthOutcome = AuthOutcomeUnknown
	}

	if s.AuthOutcome == AuthOutcomeFailLatched {
		return nil
	}

	s.AuthOutcome = next

	return nil
}
