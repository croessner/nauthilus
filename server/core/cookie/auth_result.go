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
	"crypto/hmac"
	"encoding/binary"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
)

// authResultHMACData builds the message to be HMAC'd: username || auth_result || timestamp.
func authResultHMACData(username string, authResult uint8, ts int64) []byte {
	// 8 bytes timestamp + 1 byte auth_result + username bytes
	buf := make([]byte, 8+1+len(username))
	binary.BigEndian.PutUint64(buf[:8], uint64(ts))
	buf[8] = authResult
	copy(buf[9:], username)

	return buf
}

// SetAuthResult stores the authentication result together with an HMAC integrity tag
// that binds the result to the username and a timestamp. This prevents tampering with
// the auth_result value even if the outer cookie encryption were somehow bypassed.
func SetAuthResult(mgr Manager, username string, result definitions.AuthResult) {
	if mgr == nil {
		return
	}

	ts := time.Now().Unix()
	authResult := uint8(result)

	mgr.Set(definitions.SessionKeyAuthResult, authResult)

	data := authResultHMACData(username, authResult, ts)
	tag := mgr.ComputeHMAC(data)

	// Store HMAC tag as []byte along with the timestamp so verification can reconstruct the message.
	hmacPayload := make([]byte, 8+len(tag))
	binary.BigEndian.PutUint64(hmacPayload[:8], uint64(ts))
	copy(hmacPayload[8:], tag)

	mgr.Set(definitions.SessionKeyAuthResultHMAC, hmacPayload)
}

// VerifyAuthResult reads the auth_result from the cookie and verifies its HMAC integrity tag.
// Returns the AuthResult and true only if:
//   - mgr is non-nil
//   - auth_result key exists
//   - auth_result_hmac key exists and is valid
//   - the HMAC matches the stored username + result + timestamp
//
// On any failure (missing data, wrong HMAC, nil mgr), returns AuthResultFail and false.
// This implements default-deny: the caller must not grant access unless this returns true.
func VerifyAuthResult(mgr Manager, username string) (definitions.AuthResult, bool) {
	if mgr == nil {
		return definitions.AuthResultFail, false
	}

	if !mgr.HasKey(definitions.SessionKeyAuthResult) {
		return definitions.AuthResultFail, false
	}

	authResult := mgr.GetUint8(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultFail))

	hmacPayload := mgr.GetBytes(definitions.SessionKeyAuthResultHMAC, nil)
	if len(hmacPayload) < 8+32 { // 8 bytes timestamp + 32 bytes HMAC-SHA256
		return definitions.AuthResultFail, false
	}

	ts := int64(binary.BigEndian.Uint64(hmacPayload[:8]))
	storedTag := hmacPayload[8:]

	data := authResultHMACData(username, authResult, ts)
	expectedTag := mgr.ComputeHMAC(data)

	if !hmac.Equal(storedTag, expectedTag) {
		return definitions.AuthResultFail, false
	}

	return definitions.AuthResult(authResult), true
}
