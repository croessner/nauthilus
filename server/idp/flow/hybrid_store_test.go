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
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
)

type mapSessionManager struct {
	values map[string]any
}

func newMapSessionManager() *mapSessionManager {
	return &mapSessionManager{values: make(map[string]any)}
}

func (m *mapSessionManager) Set(key string, value any) {
	m.values[key] = value
}

func (m *mapSessionManager) Delete(key string) {
	delete(m.values, key)
}

func (m *mapSessionManager) GetString(key string, defaultValue string) string {
	raw, ok := m.values[key]
	if !ok {
		return defaultValue
	}

	value, ok := raw.(string)
	if !ok {
		return defaultValue
	}

	return value
}

func (m *mapSessionManager) GetBool(key string, defaultValue bool) bool {
	raw, ok := m.values[key]
	if !ok {
		return defaultValue
	}

	value, ok := raw.(bool)
	if !ok {
		return defaultValue
	}

	return value
}

func (m *mapSessionManager) GetBytes(key string, defaultValue []byte) []byte {
	raw, ok := m.values[key]
	if !ok {
		return defaultValue
	}

	value, ok := raw.([]byte)
	if !ok {
		return defaultValue
	}

	return value
}

func (m *mapSessionManager) ComputeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte("flow-hybrid-test-key"))
	_, _ = mac.Write(data)

	return mac.Sum(nil)
}

func TestFlowReferenceAdapterRoundtrip(t *testing.T) {
	session := newMapSessionManager()
	adapter := NewFlowReferenceAdapter(session)

	state := &State{
		FlowID:      "flow-123",
		FlowType:    FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		AuthOutcome: AuthOutcomeFailLatched,
		PendingMFA:  true,
	}

	if err := adapter.Save(t.Context(), state); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	loaded, err := adapter.Load(t.Context(), "")
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if loaded == nil || loaded.FlowID != state.FlowID {
		t.Fatalf("unexpected loaded flow: %+v", loaded)
	}

	if loaded.AuthOutcome != state.AuthOutcome {
		t.Fatalf("unexpected auth outcome: got=%s want=%s", loaded.AuthOutcome, state.AuthOutcome)
	}

	if session.GetString(definitions.SessionKeyIdPFlowID, "") != state.FlowID {
		t.Fatalf("expected flow id key %q to be set", definitions.SessionKeyIdPFlowID)
	}

	if err = adapter.Delete(t.Context(), state.FlowID); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}

	if session.GetString(definitions.SessionKeyIdPFlowID, "") != "" {
		t.Fatalf("expected flow id key %q to be deleted", definitions.SessionKeyIdPFlowID)
	}
}

func TestHybridStoreReturnsNilWhenStateMissing(t *testing.T) {
	reference := &memoryStore{state: &State{FlowID: "flow-id"}}
	state := &memoryStore{}

	hybrid := NewHybridStore(reference, state)

	loaded, err := hybrid.Load(t.Context(), "")
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if loaded != nil {
		t.Fatalf("expected missing state to return nil, got %+v", loaded)
	}

	if reference.state != nil {
		t.Fatalf("expected orphaned reference cleanup, got %+v", reference.state)
	}
}
