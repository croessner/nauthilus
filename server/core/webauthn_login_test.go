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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

// TestLoginWebAuthnBeginUsesSessionUniqueUserID is skipped as it requires a fully initialized
// WebAuthn environment. The session handling for WebAuthn is now tested in webauthn_registration_test.go.
func TestLoginWebAuthnBeginUsesSessionUniqueUserID(t *testing.T) {
	t.Skip("Skipping WebAuthn login test - requires fully initialized WebAuthn environment")
}

// TestIsMFAAuthResultValid tests the authentication result validation after MFA verification.
// This test ensures that "Fall B Punkt 1" from the IdP login flow specification is correctly
// implemented: if the initial credentials were wrong (delayed response), the user must be
// rejected even after successful MFA verification.
func TestIsMFAAuthResultValid(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(mgr *mockCookieManager)
		expected bool
	}{
		{
			name: "AuthResultOK should allow login",
			setup: func(mgr *mockCookieManager) {
				mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))
			},
			expected: true,
		},
		{
			name: "AuthResultFail should reject login (Fall B Punkt 1 - wrong initial credentials)",
			setup: func(mgr *mockCookieManager) {
				mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultFail))
			},
			expected: false,
		},
		{
			name: "No AuthResult set should allow login (non-delayed response case)",
			setup: func(mgr *mockCookieManager) {
				// No AuthResult set
			},
			expected: true,
		},
		{
			name: "AuthResultTempFail should allow login (temporary failures are not credential errors)",
			setup: func(mgr *mockCookieManager) {
				mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultTempFail))
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &mockCookieManager{data: make(map[string]any)}
			tt.setup(mgr)

			result := isMFAAuthResultValid(mgr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsMFAAuthResultValidNilManager tests that a nil manager allows login.
// This case occurs when the cookie manager is not available.
func TestIsMFAAuthResultValidNilManager(t *testing.T) {
	// Passing nil directly as the interface value
	result := isMFAAuthResultValid(nil)
	assert.True(t, result, "Nil manager should allow login")
}

// TestDelayedResponseWithWrongCredentialsRejectAfterMFA documents the expected behavior
// for "Fall B Punkt 1": When delayed_response is enabled and the user provides wrong
// initial credentials but has MFA configured, the flow should:
// 1. Continue to MFA verification (hiding whether credentials were correct)
// 2. After successful MFA, reject the login because initial credentials were wrong
// This prevents attackers from using MFA bypass techniques to circumvent password verification.
func TestDelayedResponseWithWrongCredentialsRejectAfterMFA(t *testing.T) {
	// This is a documentation test that verifies the expected behavior
	// The actual implementation is in LoginWebAuthnFinish and PostLoginTOTP

	mgr := &mockCookieManager{data: make(map[string]any)}

	// Simulate delayed response with wrong credentials
	mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultFail))
	mgr.Set(definitions.SessionKeyUsername, "testuser")

	// After MFA verification, the auth result should still be checked
	isValid := isMFAAuthResultValid(mgr)

	// User should be rejected because initial credentials were wrong
	assert.False(t, isValid, "User with wrong initial credentials must be rejected after MFA")
}

// TestDelayedResponseWithCorrectCredentialsAllowAfterMFA documents the expected behavior
// when the user provides correct initial credentials with delayed_response enabled.
func TestDelayedResponseWithCorrectCredentialsAllowAfterMFA(t *testing.T) {
	mgr := &mockCookieManager{data: make(map[string]any)}

	// Simulate delayed response with correct credentials
	mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))
	mgr.Set(definitions.SessionKeyUsername, "testuser")

	// After MFA verification, the auth result should allow login
	isValid := isMFAAuthResultValid(mgr)

	// User should be allowed because initial credentials were correct
	assert.True(t, isValid, "User with correct initial credentials must be allowed after MFA")
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
