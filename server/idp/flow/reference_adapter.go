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
	"context"
	"crypto/hmac"
	"encoding/binary"
	"net/url"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
)

// FlowReferenceAdapter stores only minimal flow reference data in the session cookie.
type FlowReferenceAdapter struct {
	mgr sessionManager
}

type sessionManager interface {
	Set(key string, value any)
	Delete(key string)
	GetString(key string, defaultValue string) string
	GetBool(key string, defaultValue bool) bool
	GetBytes(key string, defaultValue []byte) []byte
	ComputeHMAC(data []byte) []byte
}

// NewFlowReferenceAdapter creates an adapter that stores only flow reference
// information in the session cookie.
func NewFlowReferenceAdapter(mgr sessionManager) *FlowReferenceAdapter {
	return &FlowReferenceAdapter{mgr: mgr}
}

// Load reconstructs a lightweight flow state from cookie-backed session data.
func (a *FlowReferenceAdapter) Load(_ context.Context, _ string) (*State, error) {
	if a == nil || a.mgr == nil {
		return nil, nil
	}

	flowID := a.mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID == "" {
		return nil, nil
	}

	return &State{
		FlowID:      flowID,
		GrantType:   a.mgr.GetString(definitions.SessionKeyOIDCGrantType, ""),
		FlowType:    a.resolveFlowType(),
		Protocol:    a.resolveProtocol(),
		CurrentStep: a.resolveCurrentStep(),
		AuthOutcome: a.resolveAuthOutcome(),
		PendingMFA:  a.mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false),
		Metadata: map[string]string{
			FlowMetadataResumeTarget:        a.resolveResumeTarget(),
			FlowMetadataClientID:            a.mgr.GetString(definitions.SessionKeyIdPClientID, ""),
			FlowMetadataRedirectURI:         a.mgr.GetString(definitions.SessionKeyIdPRedirectURI, ""),
			FlowMetadataScope:               a.mgr.GetString(definitions.SessionKeyIdPScope, ""),
			FlowMetadataState:               a.mgr.GetString(definitions.SessionKeyIdPState, ""),
			FlowMetadataNonce:               a.mgr.GetString(definitions.SessionKeyIdPNonce, ""),
			FlowMetadataResponseType:        a.mgr.GetString(definitions.SessionKeyIdPResponseType, ""),
			FlowMetadataPrompt:              a.mgr.GetString(definitions.SessionKeyIdPPrompt, ""),
			FlowMetadataCodeChallenge:       a.mgr.GetString(definitions.SessionKeyIdPCodeChallenge, ""),
			FlowMetadataCodeChallengeMethod: a.mgr.GetString(definitions.SessionKeyIdPCodeChallengeMethod, ""),
			FlowMetadataSAMLEntityID:        a.mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, ""),
			FlowMetadataOriginalURL:         a.mgr.GetString(definitions.SessionKeyIdPOriginalURL, ""),
			FlowMetadataDeviceCode:          a.mgr.GetString(definitions.SessionKeyDeviceCode, ""),
		},
	}, nil
}

// Save persists flow reference data derived from the full state into the
// cookie-backed session.
func (a *FlowReferenceAdapter) Save(_ context.Context, state *State) error {
	if a == nil || a.mgr == nil || state == nil {
		return nil
	}

	a.mgr.Set(definitions.SessionKeyIdPFlowType, a.flowTypeToSession(state.Protocol))
	a.mgr.Set(definitions.SessionKeyIdPFlowID, state.FlowID)
	a.mgr.Set(definitions.SessionKeyRequireMFAFlow, state.PendingMFA)
	authOutcome := state.AuthOutcome
	if !authOutcome.Valid() {
		authOutcome = AuthOutcomeUnknown
	}

	a.mgr.Set(definitions.SessionKeyIdPAuthOutcome, string(authOutcome))
	a.mgr.Set(definitions.SessionKeyIdPAuthOutcomeHMAC, buildAuthOutcomeHMACPayload(a.mgr, state.FlowID, authOutcome))

	if state.GrantType != "" {
		a.mgr.Set(definitions.SessionKeyOIDCGrantType, state.GrantType)
	}

	a.setStringIfNonEmpty(definitions.SessionKeyIdPClientID, state.metadataValue(FlowMetadataClientID))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPRedirectURI, state.metadataValue(FlowMetadataRedirectURI))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPScope, state.metadataValue(FlowMetadataScope))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPState, state.metadataValue(FlowMetadataState))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPNonce, state.metadataValue(FlowMetadataNonce))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPResponseType, state.metadataValue(FlowMetadataResponseType))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPPrompt, state.metadataValue(FlowMetadataPrompt))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPCodeChallenge, state.metadataValue(FlowMetadataCodeChallenge))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPCodeChallengeMethod, state.metadataValue(FlowMetadataCodeChallengeMethod))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPSAMLEntityID, state.metadataValue(FlowMetadataSAMLEntityID))
	a.setStringIfNonEmpty(definitions.SessionKeyIdPOriginalURL, state.metadataValue(FlowMetadataOriginalURL))
	a.setStringIfNonEmpty(definitions.SessionKeyDeviceCode, state.metadataValue(FlowMetadataDeviceCode))

	return nil
}

// Delete removes all cookie-backed flow reference keys.
func (a *FlowReferenceAdapter) Delete(_ context.Context, _ string) error {
	if a == nil || a.mgr == nil {
		return nil
	}

	a.mgr.Delete(definitions.SessionKeyIdPFlowType)
	a.mgr.Delete(definitions.SessionKeyIdPFlowID)
	a.mgr.Delete(definitions.SessionKeyIdPAuthOutcome)
	a.mgr.Delete(definitions.SessionKeyIdPAuthOutcomeHMAC)
	a.mgr.Delete(definitions.SessionKeyRequireMFAFlow)

	return nil
}

// TouchTTL is a no-op for cookie-backed flow references.
func (a *FlowReferenceAdapter) TouchTTL(_ context.Context, _ string, _ time.Duration) error {
	return nil
}

func (a *FlowReferenceAdapter) resolveFlowType() FlowType {
	if a.mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		return FlowTypeRequireMFA
	}

	switch a.mgr.GetString(definitions.SessionKeyOIDCGrantType, "") {
	case definitions.OIDCFlowAuthorizationCode:
		return FlowTypeOIDCAuthorization
	case definitions.OIDCFlowDeviceCode:
		return FlowTypeOIDCDeviceCode
	}

	if a.mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "") != "" {
		return FlowTypeSAML
	}

	return FlowTypeUnknown
}

func (a *FlowReferenceAdapter) resolveProtocol() FlowProtocol {
	switch a.mgr.GetString(definitions.SessionKeyIdPFlowType, "") {
	case definitions.ProtoOIDC:
		return FlowProtocolOIDC
	case definitions.ProtoSAML:
		return FlowProtocolSAML
	default:
		if a.mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
			return FlowProtocolInternal
		}
	}

	return FlowProtocolUnknown
}

func (a *FlowReferenceAdapter) flowTypeToSession(protocol FlowProtocol) string {
	switch protocol {
	case FlowProtocolOIDC:
		return definitions.ProtoOIDC
	case FlowProtocolSAML:
		return definitions.ProtoSAML
	default:
		return ""
	}
}

func (a *FlowReferenceAdapter) resolveCurrentStep() FlowStep {
	flowType := a.resolveFlowType()

	switch flowType {
	case FlowTypeRequireMFA:
		return FlowStepRequireMFAChallenge
	case FlowTypeOIDCAuthorization, FlowTypeOIDCDeviceCode, FlowTypeSAML:
		return FlowStepLogin
	default:
		return FlowStepStart
	}
}

func (a *FlowReferenceAdapter) resolveAuthOutcome() AuthOutcome {
	flowID := a.mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID == "" {
		return AuthOutcomeUnknown
	}

	outcome := AuthOutcome(a.mgr.GetString(definitions.SessionKeyIdPAuthOutcome, ""))
	if !outcome.Valid() {
		return AuthOutcomeUnknown
	}

	if !verifyAuthOutcome(a.mgr, flowID, outcome) {
		return AuthOutcomeUnknown
	}

	return outcome
}

func (a *FlowReferenceAdapter) resolveResumeTarget() string {
	switch a.resolveFlowType() {
	case FlowTypeOIDCAuthorization:
		return a.oidcAuthorizeResumeTarget()
	case FlowTypeOIDCDeviceCode:
		return a.oidcDeviceResumeTarget()
	case FlowTypeSAML:
		return a.mgr.GetString(definitions.SessionKeyIdPOriginalURL, "")
	default:
		return ""
	}
}

func (a *FlowReferenceAdapter) oidcAuthorizeResumeTarget() string {
	clientID := a.mgr.GetString(definitions.SessionKeyIdPClientID, "")
	redirectURI := a.mgr.GetString(definitions.SessionKeyIdPRedirectURI, "")
	if clientID == "" || redirectURI == "" {
		return ""
	}

	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("redirect_uri", redirectURI)

	if scope := a.mgr.GetString(definitions.SessionKeyIdPScope, ""); scope != "" {
		values.Set("scope", scope)
	}

	if state := a.mgr.GetString(definitions.SessionKeyIdPState, ""); state != "" {
		values.Set("state", state)
	}

	if nonce := a.mgr.GetString(definitions.SessionKeyIdPNonce, ""); nonce != "" {
		values.Set("nonce", nonce)
	}

	if responseType := a.mgr.GetString(definitions.SessionKeyIdPResponseType, ""); responseType != "" {
		values.Set("response_type", responseType)
	}

	if prompt := a.mgr.GetString(definitions.SessionKeyIdPPrompt, ""); prompt != "" {
		values.Set("prompt", prompt)
	}

	if codeChallenge := a.mgr.GetString(definitions.SessionKeyIdPCodeChallenge, ""); codeChallenge != "" {
		values.Set("code_challenge", codeChallenge)
	}

	if codeChallengeMethod := a.mgr.GetString(definitions.SessionKeyIdPCodeChallengeMethod, ""); codeChallengeMethod != "" {
		values.Set("code_challenge_method", codeChallengeMethod)
	}

	return "/oidc/authorize?" + values.Encode()
}

func (a *FlowReferenceAdapter) oidcDeviceResumeTarget() string {
	if a.mgr.GetString(definitions.SessionKeyDeviceCode, "") == "" {
		return ""
	}

	return FlowMetadataResumeTargetDeviceCodeComplete
}

func buildAuthOutcomeHMACPayload(mgr sessionManager, flowID string, outcome AuthOutcome) []byte {
	ts := time.Now().Unix()
	data := authOutcomeHMACData(flowID, outcome, ts)
	tag := mgr.ComputeHMAC(data)

	payload := make([]byte, 8+len(tag))
	binary.BigEndian.PutUint64(payload[:8], uint64(ts))
	copy(payload[8:], tag)

	return payload
}

func verifyAuthOutcome(mgr sessionManager, flowID string, outcome AuthOutcome) bool {
	if outcome == AuthOutcomeUnknown {
		return true
	}

	payload := mgr.GetBytes(definitions.SessionKeyIdPAuthOutcomeHMAC, nil)
	if len(payload) < 8+32 {
		return false
	}

	ts := int64(binary.BigEndian.Uint64(payload[:8]))
	storedTag := payload[8:]
	expectedTag := mgr.ComputeHMAC(authOutcomeHMACData(flowID, outcome, ts))

	return hmac.Equal(storedTag, expectedTag)
}

func authOutcomeHMACData(flowID string, outcome AuthOutcome, ts int64) []byte {
	outcomeBytes := []byte(outcome)
	buf := make([]byte, 8+len(flowID)+1+len(outcomeBytes))
	binary.BigEndian.PutUint64(buf[:8], uint64(ts))
	copy(buf[8:], flowID)
	buf[8+len(flowID)] = 0
	copy(buf[8+len(flowID)+1:], outcomeBytes)

	return buf
}

func (s *State) metadataValue(key string) string {
	if s == nil || s.Metadata == nil {
		return ""
	}

	return s.Metadata[key]
}

func (a *FlowReferenceAdapter) setStringIfNonEmpty(key string, value string) {
	if value != "" {
		a.mgr.Set(key, value)
	}
}
