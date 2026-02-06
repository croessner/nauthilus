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

package core

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

// TestLoginWebAuthnBeginUsesSessionUniqueUserID is skipped as it requires a fully initialized
// WebAuthn environment. The session handling for WebAuthn is now tested in webauthn_registration_test.go.
func TestLoginWebAuthnBeginUsesSessionUniqueUserID(t *testing.T) {
	t.Skip("Skipping WebAuthn login test - requires fully initialized WebAuthn environment")
}

func TestUpdateWebAuthnCredentialAfterLoginKeepsDeviceData(t *testing.T) {
	now := time.Date(2026, time.January, 30, 12, 0, 0, 0, time.UTC)

	credentials := []mfa.PersistentCredential{
		{
			Credential: webauthn.Credential{
				ID: []byte("device-a"),
				Authenticator: webauthn.Authenticator{
					SignCount: 3,
				},
			},
			Name:     "TouchID",
			LastUsed: time.Date(2026, time.January, 29, 10, 0, 0, 0, time.UTC),
		},
		{
			Credential: webauthn.Credential{
				ID: []byte("device-b"),
				Authenticator: webauthn.Authenticator{
					SignCount: 0,
				},
			},
			Name:     "YubiKey",
			LastUsed: time.Date(2026, time.January, 28, 11, 0, 0, 0, time.UTC),
		},
	}

	loginCredential := &webauthn.Credential{
		ID: []byte("device-b"),
		Authenticator: webauthn.Authenticator{
			SignCount: 6,
		},
	}

	oldCredential, updatedCredential := updateWebAuthnCredentialAfterLogin(credentials, loginCredential, now)

	if assert.NotNil(t, oldCredential) && assert.NotNil(t, updatedCredential) {
		assert.Equal(t, "YubiKey", oldCredential.Name)
		assert.Equal(t, "YubiKey", updatedCredential.Name)
		assert.Equal(t, uint32(6), updatedCredential.Authenticator.SignCount)
		assert.Equal(t, now, updatedCredential.LastUsed)
		assert.Equal(t, []byte("device-b"), updatedCredential.ID)
	}
}
