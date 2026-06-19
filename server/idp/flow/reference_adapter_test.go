// Copyright (C) 2026 Christian Rößner
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
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
)

type testSessionManager struct {
	data map[string]any
}

func (m *testSessionManager) Set(key string, value any) { m.data[key] = value }
func (m *testSessionManager) Delete(key string)         { delete(m.data, key) }
func (m *testSessionManager) GetString(key string, defaultValue string) string {
	if value, ok := m.data[key]; ok {
		if value, ok := value.(string); ok {
			return value
		}
	}

	return defaultValue
}
func (m *testSessionManager) GetBool(key string, defaultValue bool) bool {
	if value, ok := m.data[key]; ok {
		if value, ok := value.(bool); ok {
			return value
		}
	}

	return defaultValue
}

func (m *testSessionManager) GetBytes(key string, defaultValue []byte) []byte {
	if value, ok := m.data[key]; ok {
		if value, ok := value.([]byte); ok {
			return value
		}
	}

	return defaultValue
}

func (m *testSessionManager) ComputeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte("flow-reference-test-key"))
	_, _ = mac.Write(data)

	return mac.Sum(nil)
}

func TestFlowReferenceAdapterLoadOIDCResumeTarget(t *testing.T) {
	mgr := &testSessionManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:       "flow-1",
		definitions.SessionKeyIDPFlowType:     definitions.ProtoOIDC,
		definitions.SessionKeyIDPAuthOutcome:  "fail_latched",
		definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:     "client-1",
		definitions.SessionKeyIDPRedirectURI:  "https://rp.example/cb",
		definitions.SessionKeyIDPScope:        "openid profile",
		definitions.SessionKeyIDPState:        "abc",
		definitions.SessionKeyIDPNonce:        "nonce-1",
		definitions.SessionKeyIDPResponseType: "code",
	}}
	setAuthOutcomeHMACTestValue(mgr, "flow-1", AuthOutcomeFailLatched)

	state, err := NewReferenceAdapter(mgr).Load(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if state == nil {
		t.Fatal("expected state")
	}

	if state.Metadata[FlowMetadataResumeTarget] == "" {
		t.Fatal("expected resume target metadata")
	}

	if state.AuthOutcome != AuthOutcomeFailLatched {
		t.Fatalf("unexpected auth outcome: %s", state.AuthOutcome)
	}

	expected := "/oidc/authorize?client_id=client-1&nonce=nonce-1&redirect_uri=https%3A%2F%2Frp.example%2Fcb&response_type=code&scope=openid+profile&state=abc"
	if state.Metadata[FlowMetadataResumeTarget] != expected {
		t.Fatalf("unexpected resume target: %s", state.Metadata[FlowMetadataResumeTarget])
	}
}

func setAuthOutcomeHMACTestValue(mgr *testSessionManager, flowID string, outcome AuthOutcome) {
	ts := int64(1735689600)
	data := authOutcomeHMACData(flowID, outcome, ts)
	tag := mgr.ComputeHMAC(data)

	payload := make([]byte, 8+len(tag))
	binary.BigEndian.PutUint64(payload[:8], uint64(ts))
	copy(payload[8:], tag)

	mgr.Set(definitions.SessionKeyIDPAuthOutcomeHMAC, payload)
}

func TestFlowReferenceAdapterLoadSAMLResumeTarget(t *testing.T) {
	mgr := &testSessionManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:       "flow-2",
		definitions.SessionKeyIDPFlowType:     definitions.ProtoSAML,
		definitions.SessionKeyIDPSAMLEntityID: "sp-entity",
		definitions.SessionKeyIDPOriginalURL:  "/saml/sso?SAMLRequest=abc",
	}}

	state, err := NewReferenceAdapter(mgr).Load(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if state.Metadata[FlowMetadataResumeTarget] != "/saml/sso?SAMLRequest=abc" {
		t.Fatalf("unexpected SAML resume target: %s", state.Metadata[FlowMetadataResumeTarget])
	}
}

func TestFlowReferenceAdapterLoadDeviceResumeTarget(t *testing.T) {
	mgr := &testSessionManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:     "flow-3",
		definitions.SessionKeyIDPFlowType:   definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowDeviceCode,
		definitions.SessionKeyDeviceCode:    "device-1",
	}}

	state, err := NewReferenceAdapter(mgr).Load(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if state.Type != FlowTypeOIDCDeviceCode {
		t.Fatalf("unexpected flow type: %s", state.Type)
	}

	if state.Metadata[FlowMetadataResumeTarget] != FlowMetadataResumeTargetDeviceCodeComplete {
		t.Fatalf("unexpected device resume target: %s", state.Metadata[FlowMetadataResumeTarget])
	}
}

func TestFlowReferenceAdapterLoadAuthOutcomeRejectsMissingHMAC(t *testing.T) {
	mgr := &testSessionManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:      "flow-4",
		definitions.SessionKeyIDPFlowType:    definitions.ProtoOIDC,
		definitions.SessionKeyIDPAuthOutcome: "ok",
	}}

	state, err := NewReferenceAdapter(mgr).Load(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if state == nil {
		t.Fatal("expected state")
	}

	if state.AuthOutcome != AuthOutcomeUnknown {
		t.Fatalf("expected auth outcome to downgrade to unknown, got %s", state.AuthOutcome)
	}
}
