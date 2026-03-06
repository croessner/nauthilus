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
	"fmt"
	"time"
)

const (
	FlowMetadataResumeTarget                   = "resume_target"
	FlowMetadataResumeTargetDeviceCodeComplete = "nauthilus://idp/device-code/complete"
	FlowMetadataClientID                       = "client_id"
	FlowMetadataRedirectURI                    = "redirect_uri"
	FlowMetadataScope                          = "scope"
	FlowMetadataState                          = "state"
	FlowMetadataNonce                          = "nonce"
	FlowMetadataResponseType                   = "response_type"
	FlowMetadataPrompt                         = "prompt"
	FlowMetadataCodeChallenge                  = "code_challenge"
	FlowMetadataCodeChallengeMethod            = "code_challenge_method"
	FlowMetadataSAMLEntityID                   = "saml_entity_id"
	FlowMetadataOriginalURL                    = "original_url"
	FlowMetadataDeviceCode                     = "device_code"
)

// State stores the domain-level state of an IdP flow.
type State struct {
	FlowID       string            `json:"flow_id"`
	GrantType    string            `json:"grant_type,omitzero"`
	CancelTarget string            `json:"cancel_target,omitzero"`
	ReturnTarget string            `json:"return_target,omitzero"`
	Metadata     map[string]string `json:"metadata,omitzero"`
	FlowType     FlowType          `json:"flow_type"`
	Protocol     FlowProtocol      `json:"protocol"`
	CurrentStep  FlowStep          `json:"current_step"`
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

	if !s.FlowType.Valid() {
		return fmt.Errorf("flow state: %w (%s)", ErrInvalidFlowType, s.FlowType)
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
