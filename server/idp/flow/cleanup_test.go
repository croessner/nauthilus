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
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/stretchr/testify/assert"
)

type mockKeyManager struct {
	data map[string]bool
}

func (m *mockKeyManager) Delete(key string) {
	delete(m.data, key)
}

func TestCleanupMFAState(t *testing.T) {
	t.Run("nil manager does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() { CleanupMFAState(nil) })
	})

	t.Run("deletes all MFA state keys", func(t *testing.T) {
		mgr := &mockKeyManager{data: map[string]bool{
			definitions.SessionKeyUsername:       true,
			definitions.SessionKeyUniqueUserID:   true,
			definitions.SessionKeyAuthResult:     true,
			definitions.SessionKeyAuthResultHMAC: true,
			definitions.SessionKeyMFAMulti:       true,
			definitions.SessionKeyMFAMethod:      true,
			definitions.SessionKeyMFACompleted:   true,
			definitions.SessionKeyRegistration:   true,
			// Non-MFA key that should survive cleanup.
			definitions.SessionKeyAccount: true,
		}}

		CleanupMFAState(mgr)

		assert.False(t, mgr.data[definitions.SessionKeyUsername])
		assert.False(t, mgr.data[definitions.SessionKeyUniqueUserID])
		assert.False(t, mgr.data[definitions.SessionKeyAuthResult])
		assert.False(t, mgr.data[definitions.SessionKeyAuthResultHMAC])
		assert.False(t, mgr.data[definitions.SessionKeyMFAMulti])
		assert.False(t, mgr.data[definitions.SessionKeyMFAMethod])
		assert.False(t, mgr.data[definitions.SessionKeyMFACompleted])
		assert.False(t, mgr.data[definitions.SessionKeyRegistration])
		// Non-MFA key must still be present.
		assert.True(t, mgr.data[definitions.SessionKeyAccount])
	})
}

func TestCleanupIdPState(t *testing.T) {
	t.Run("nil manager does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() { CleanupIdPState(nil) })
	})

	t.Run("deletes all IdP flow state keys", func(t *testing.T) {
		mgr := &mockKeyManager{data: map[string]bool{
			definitions.SessionKeyIdPFlowType:        true,
			definitions.SessionKeyIdPFlowID:          true,
			definitions.SessionKeyIdPAuthOutcome:     true,
			definitions.SessionKeyIdPAuthOutcomeHMAC: true,
			definitions.SessionKeyOIDCGrantType:      true,
			definitions.SessionKeyIdPClientID:        true,
			definitions.SessionKeyIdPRedirectURI:     true,
			definitions.SessionKeyIdPScope:           true,
			definitions.SessionKeyIdPState:           true,
			definitions.SessionKeyIdPNonce:           true,
			definitions.SessionKeyIdPResponseType:    true,
			definitions.SessionKeyIdPPrompt:          true,
			definitions.SessionKeyDeviceCode:         true,
			definitions.SessionKeyIdPSAMLRequest:     true,
			definitions.SessionKeyIdPSAMLRelayState:  true,
			definitions.SessionKeyIdPSAMLEntityID:    true,
			definitions.SessionKeyIdPOriginalURL:     true,
			definitions.SessionKeyRequireMFAFlow:     true,
			definitions.SessionKeyRequireMFAPending:  true,
			// Non-flow key that should survive cleanup.
			definitions.SessionKeyUsername: true,
		}}

		CleanupIdPState(mgr)

		// All IdP flow keys should be removed.
		assert.Len(t, mgr.data, 1)
		assert.True(t, mgr.data[definitions.SessionKeyUsername])
	})
}
