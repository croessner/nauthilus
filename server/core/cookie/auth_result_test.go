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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestSetAndVerifyAuthResult(t *testing.T) {
	t.Run("round-trip OK result", func(t *testing.T) {
		mgr := NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)
		SetAuthResult(mgr, "alice", definitions.AuthResultOK)

		result, ok := VerifyAuthResult(mgr, "alice")
		assert.True(t, ok)
		assert.Equal(t, definitions.AuthResultOK, result)
	})

	t.Run("round-trip Fail result", func(t *testing.T) {
		mgr := NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)
		SetAuthResult(mgr, "alice", definitions.AuthResultFail)

		result, ok := VerifyAuthResult(mgr, "alice")
		assert.True(t, ok)
		assert.Equal(t, definitions.AuthResultFail, result)
	})

	t.Run("wrong username rejects", func(t *testing.T) {
		mgr := NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)
		SetAuthResult(mgr, "alice", definitions.AuthResultOK)

		result, ok := VerifyAuthResult(mgr, "bob")
		assert.False(t, ok)
		assert.Equal(t, definitions.AuthResultFail, result)
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
		mgr := NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)

		result, ok := VerifyAuthResult(mgr, "alice")
		assert.False(t, ok)
		assert.Equal(t, definitions.AuthResultFail, result)
	})

	t.Run("tampered auth_result value rejects", func(t *testing.T) {
		mgr := NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)
		SetAuthResult(mgr, "alice", definitions.AuthResultFail)

		// Tamper: flip result to OK without updating HMAC
		mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))

		result, ok := VerifyAuthResult(mgr, "alice")
		assert.False(t, ok, "Tampered auth_result must be rejected")
		assert.Equal(t, definitions.AuthResultFail, result)
	})

	t.Run("missing HMAC key rejects", func(t *testing.T) {
		mgr := NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)
		// Set auth_result without HMAC (simulating legacy or tampered cookie)
		mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))

		result, ok := VerifyAuthResult(mgr, "alice")
		assert.False(t, ok, "Missing HMAC must be rejected")
		assert.Equal(t, definitions.AuthResultFail, result)
	})

	t.Run("truncated HMAC payload rejects", func(t *testing.T) {
		mgr := NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "test", nil, nil)
		mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))
		mgr.Set(definitions.SessionKeyAuthResultHMAC, []byte("too-short"))

		result, ok := VerifyAuthResult(mgr, "alice")
		assert.False(t, ok, "Truncated HMAC payload must be rejected")
		assert.Equal(t, definitions.AuthResultFail, result)
	})

	t.Run("different secret produces different HMAC", func(t *testing.T) {
		mgr1 := NewSecureManager([]byte("secret-one-32bytes-1234567890!!"), "test", nil, nil)
		mgr2 := NewSecureManager([]byte("secret-two-32bytes-1234567890!!"), "test", nil, nil)

		SetAuthResult(mgr1, "alice", definitions.AuthResultOK)

		// Copy raw data from mgr1 to mgr2
		authResult, _ := mgr1.Get(definitions.SessionKeyAuthResult)
		hmacPayload, _ := mgr1.Get(definitions.SessionKeyAuthResultHMAC)
		mgr2.Set(definitions.SessionKeyAuthResult, authResult)
		mgr2.Set(definitions.SessionKeyAuthResultHMAC, hmacPayload)

		// Verification with different secret should fail
		result, ok := VerifyAuthResult(mgr2, "alice")
		assert.False(t, ok, "HMAC from different secret must be rejected")
		assert.Equal(t, definitions.AuthResultFail, result)
	})
}
