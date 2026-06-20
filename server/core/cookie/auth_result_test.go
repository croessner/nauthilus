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

package cookie

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestSetAndVerifyAuthResult(t *testing.T) {
	t.Run("round-trip OK result", func(t *testing.T) {
		assertAuthResultRoundTrip(t, definitions.AuthResultOK)
	})

	t.Run("round-trip Fail result", func(t *testing.T) {
		assertAuthResultRoundTrip(t, definitions.AuthResultFail)
	})

	t.Run("wrong username rejects", func(t *testing.T) {
		assertWrongAuthResultUsernameRejects(t)
	})

	t.Run("nil manager returns fail", func(t *testing.T) {
		result, ok := VerifyAuthResult(nil, "alice")
		assert.False(t, ok)
		assert.Equal(t, definitions.AuthResultFail, result)
	})

	t.Run("nil manager set is no-op", func(t *testing.T) {
		assert.NotPanics(t, func() {
			SetAuthResult(nil, "alice", definitions.AuthResultOK)
		})
	})

	t.Run("missing auth_result key rejects", func(t *testing.T) {
		assertAuthResultRejects(t, newAuthResultTestManager(), "Missing auth_result key must be rejected")
	})

	t.Run("tampered auth_result value rejects", func(t *testing.T) {
		assertTamperedAuthResultRejects(t)
	})

	t.Run("missing HMAC key rejects", func(t *testing.T) {
		assertMissingAuthResultHMACRejects(t)
	})

	t.Run("truncated HMAC payload rejects", func(t *testing.T) {
		assertTruncatedAuthResultHMACRejects(t)
	})

	t.Run("different secret produces different HMAC", func(t *testing.T) {
		assertDifferentAuthResultSecretRejects(t)
	})
}

// newAuthResultTestManager builds the default secure manager for auth-result tests.
func newAuthResultTestManager() *SecureManager {
	return NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)
}

// assertAuthResultRoundTrip verifies that one auth-result value survives a round trip.
func assertAuthResultRoundTrip(t *testing.T, expected definitions.AuthResult) {
	t.Helper()

	mgr := newAuthResultTestManager()
	SetAuthResult(mgr, "alice", expected)

	result, ok := VerifyAuthResult(mgr, "alice")
	assert.True(t, ok)
	assert.Equal(t, expected, result)
}

// assertWrongAuthResultUsernameRejects verifies username binding in the auth-result HMAC.
func assertWrongAuthResultUsernameRejects(t *testing.T) {
	t.Helper()

	mgr := newAuthResultTestManager()
	SetAuthResult(mgr, "alice", definitions.AuthResultOK)

	assertAuthResultRejectsForUser(t, mgr, "bob", "Wrong username must be rejected")
}

// assertTamperedAuthResultRejects verifies that changing the stored result invalidates the HMAC.
func assertTamperedAuthResultRejects(t *testing.T) {
	t.Helper()

	mgr := newAuthResultTestManager()
	SetAuthResult(mgr, "alice", definitions.AuthResultFail)
	mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))

	assertAuthResultRejects(t, mgr, "Tampered auth_result must be rejected")
}

// assertMissingAuthResultHMACRejects verifies fail-closed behavior without an HMAC payload.
func assertMissingAuthResultHMACRejects(t *testing.T) {
	t.Helper()

	mgr := newAuthResultTestManager()
	mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))

	assertAuthResultRejects(t, mgr, "Missing HMAC must be rejected")
}

// assertTruncatedAuthResultHMACRejects verifies fail-closed behavior for malformed HMAC payloads.
func assertTruncatedAuthResultHMACRejects(t *testing.T) {
	t.Helper()

	mgr := newAuthResultTestManager()
	mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))
	mgr.Set(definitions.SessionKeyAuthResultHMAC, []byte("too-short"))

	assertAuthResultRejects(t, mgr, "Truncated HMAC payload must be rejected")
}

// assertDifferentAuthResultSecretRejects verifies that HMACs are scoped to the manager secret.
func assertDifferentAuthResultSecretRejects(t *testing.T) {
	t.Helper()

	mgr1 := NewSecureManager([]byte("secret-one-32bytes-1234567890!!"), "test", nil, nil)
	mgr2 := NewSecureManager([]byte("secret-two-32bytes-1234567890!!"), "test", nil, nil)

	SetAuthResult(mgr1, "alice", definitions.AuthResultOK)

	authResult, _ := mgr1.Get(definitions.SessionKeyAuthResult)
	hmacPayload, _ := mgr1.Get(definitions.SessionKeyAuthResultHMAC)

	mgr2.Set(definitions.SessionKeyAuthResult, authResult)
	mgr2.Set(definitions.SessionKeyAuthResultHMAC, hmacPayload)

	assertAuthResultRejects(t, mgr2, "HMAC from different secret must be rejected")
}

// assertAuthResultRejects verifies the common fail-closed auth-result outcome.
func assertAuthResultRejects(t *testing.T, mgr *SecureManager, message string) {
	t.Helper()

	assertAuthResultRejectsForUser(t, mgr, "alice", message)
}

// assertAuthResultRejectsForUser verifies the common fail-closed outcome for one username.
func assertAuthResultRejectsForUser(t *testing.T, mgr *SecureManager, username string, message string) {
	t.Helper()

	result, ok := VerifyAuthResult(mgr, username)
	assert.False(t, ok, message)
	assert.Equal(t, definitions.AuthResultFail, result)
}
