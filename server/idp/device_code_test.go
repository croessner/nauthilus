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

package idp

import (
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestDefaultUserCodeGenerator_GenerateUserCode(t *testing.T) {
	gen := &DefaultUserCodeGenerator{}

	t.Run("generates code with correct length", func(t *testing.T) {
		assertGeneratedUserCodeShape(t, gen, 8, 9, 4)
	})

	t.Run("generates code with correct charset", func(t *testing.T) {
		assertGeneratedUserCodeCharset(t, gen)
	})

	t.Run("excludes confusing characters", func(t *testing.T) {
		assertGeneratedUserCodeExcludesConfusingCharacters(t, gen)
	})

	t.Run("generates unique codes", func(t *testing.T) {
		assertGeneratedUserCodesUnique(t, gen)
	})

	t.Run("handles different lengths", func(t *testing.T) {
		assertGeneratedUserCodeShape(t, gen, 6, 7, 3)
	})
}

// assertGeneratedUserCodeShape verifies length and hyphen placement.
func assertGeneratedUserCodeShape(t *testing.T, gen *DefaultUserCodeGenerator, inputLength int, expectedLength int, hyphenIndex int) {
	t.Helper()

	code, err := gen.GenerateUserCode(inputLength)

	assert.NoError(t, err)
	assert.Len(t, code, expectedLength)
	assert.Equal(t, "-", string(code[hyphenIndex]))
}

// assertGeneratedUserCodeCharset verifies that generated codes use the expected alphabet.
func assertGeneratedUserCodeCharset(t *testing.T, gen *DefaultUserCodeGenerator) {
	t.Helper()

	const validChars = "ABCDEFGHJKMNPQRSTVWXYZ-"

	code, err := gen.GenerateUserCode(8)

	assert.NoError(t, err)

	for _, c := range code {
		assert.Contains(t, validChars, string(c), "unexpected character: %c", c)
	}
}

// assertGeneratedUserCodeExcludesConfusingCharacters checks repeated samples for excluded characters.
func assertGeneratedUserCodeExcludesConfusingCharacters(t *testing.T, gen *DefaultUserCodeGenerator) {
	t.Helper()

	const confusing = "OIL01"

	for range 100 {
		code, err := gen.GenerateUserCode(8)

		assert.NoError(t, err)

		cleaned := strings.ReplaceAll(code, "-", "")
		for _, c := range cleaned {
			assert.NotContains(t, confusing, string(c), "confusing character found: %c", c)
		}
	}
}

// assertGeneratedUserCodesUnique checks that a small sample does not collide.
func assertGeneratedUserCodesUnique(t *testing.T, gen *DefaultUserCodeGenerator) {
	t.Helper()

	seen := make(map[string]bool)

	for range 50 {
		code, err := gen.GenerateUserCode(8)

		assert.NoError(t, err)
		assert.False(t, seen[code], "duplicate code generated: %s", code)

		seen[code] = true
	}
}

func TestRedisDeviceCodeStoreUsesConfiguredRedisDeadlines(t *testing.T) {
	store := NewRedisDeviceCodeStore(nil, "test:")
	store.cfg = newRedisReadDeadlineTestConfig(35 * time.Millisecond)

	assertConfiguredRedisReadDeadline(t, store, 35*time.Millisecond)
}

func TestRedisDeviceCodeStore_StoreAndGet(t *testing.T) {
	store, mock, prefix := newRedisDeviceCodeStoreTest()

	t.Run("StoreDeviceCode stores both device code and user code mapping", func(t *testing.T) {
		assertStoreDeviceCodeStoresMappings(t, store, mock, prefix)
	})

	t.Run("GetDeviceCode retrieves stored request", func(t *testing.T) {
		assertGetDeviceCodeRetrievesRequest(t, store, mock, prefix)
	})

	t.Run("GetDeviceCode returns error for expired/missing code", func(t *testing.T) {
		mock.ExpectGet(prefix + "oidc:device_code:nonexistent").RedisNil()

		_, err := store.GetDeviceCode(t.Context(), "nonexistent")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found or expired")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// newRedisDeviceCodeStoreTest builds a mocked Redis-backed device-code store.
func newRedisDeviceCodeStoreTest() (*RedisDeviceCodeStore, redismock.ClientMock, string) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"

	return NewRedisDeviceCodeStore(client, prefix), mock, prefix
}

// assertStoreDeviceCodeStoresMappings verifies device-code and user-code Redis writes.
func assertStoreDeviceCodeStoresMappings(t *testing.T, store *RedisDeviceCodeStore, mock redismock.ClientMock, prefix string) {
	t.Helper()

	deviceCode := "device-abc123"
	ttl := 10 * time.Minute
	request := testDeviceCodeRequest([]string{"openid", "email"}, "ABCD-EFGH", ttl)
	data, _ := json.Marshal(request)

	mock.ExpectSet(prefix+"oidc:device_code:"+deviceCode, string(data), ttl).SetVal("OK")
	mock.ExpectSet(prefix+"oidc:user_code:ABCD-EFGH", deviceCode, ttl).SetVal("OK")

	err := store.StoreDeviceCode(t.Context(), deviceCode, request, ttl)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// assertGetDeviceCodeRetrievesRequest verifies a Redis read decodes into the stored request.
func assertGetDeviceCodeRetrievesRequest(t *testing.T, store *RedisDeviceCodeStore, mock redismock.ClientMock, prefix string) {
	t.Helper()

	deviceCode := "device-get123"
	request := testDeviceCodeRequest([]string{"openid"}, "XYZW-MNPQ", 5*time.Minute)
	data, _ := json.Marshal(request)

	mock.ExpectGet(prefix + "oidc:device_code:" + deviceCode).SetVal(string(data))

	retrieved, err := store.GetDeviceCode(t.Context(), deviceCode)

	assert.NoError(t, err)
	assert.Equal(t, request.ClientID, retrieved.ClientID)
	assert.Equal(t, request.UserCode, retrieved.UserCode)
	assert.Equal(t, DeviceCodeStatusPending, retrieved.Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// testDeviceCodeRequest builds a pending device-code request for Redis store tests.
func testDeviceCodeRequest(scopes []string, userCode string, ttl time.Duration) *DeviceCodeRequest {
	return &DeviceCodeRequest{
		ClientID:  "test-client",
		Scopes:    scopes,
		UserCode:  userCode,
		Status:    DeviceCodeStatusPending,
		ExpiresAt: time.Now().Add(ttl),
		Interval:  5,
	}
}

func TestRedisDeviceCodeStore_GetByUserCode(t *testing.T) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"
	store := NewRedisDeviceCodeStore(client, prefix)

	for _, tc := range deviceCodeByUserCodeCases() {
		t.Run(tc.name, func(t *testing.T) {
			assertDeviceCodeByUserCode(t, store, mock, prefix, tc)
		})
	}

	t.Run("GetDeviceCodeByUserCode returns error for invalid code", func(t *testing.T) {
		mock.ExpectGet(prefix + "oidc:user_code:INVA-LIDC").RedisNil()

		_, _, err := store.GetDeviceCodeByUserCode(t.Context(), "INVA-LIDC")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found or expired")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

type deviceCodeByUserCodeCase struct {
	name       string
	input      string
	lookupCode string
	deviceCode string
	request    *DeviceCodeRequest
}

func deviceCodeByUserCodeCases() []deviceCodeByUserCodeCase {
	return []deviceCodeByUserCodeCase{
		{
			name:       "GetDeviceCodeByUserCode normalizes and retrieves",
			input:      "abcdefgh",
			lookupCode: "ABCD-EFGH",
			deviceCode: "device-user123",
			request: &DeviceCodeRequest{
				ClientID: "test-client",
				UserCode: "ABCD-EFGH",
				Status:   DeviceCodeStatusPending,
			},
		},
		{
			name:       "GetDeviceCodeByUserCode handles hyphenated input",
			input:      "XYZW-MNPQ",
			lookupCode: "XYZW-MNPQ",
			deviceCode: "device-hyp123",
			request: &DeviceCodeRequest{
				ClientID: "test-client",
				UserCode: "XYZW-MNPQ",
				Status:   DeviceCodeStatusPending,
			},
		},
	}
}

// assertDeviceCodeByUserCode verifies normalized user-code lookups return the stored request.
func assertDeviceCodeByUserCode(
	t *testing.T,
	store *RedisDeviceCodeStore,
	mock redismock.ClientMock,
	prefix string,
	tc deviceCodeByUserCodeCase,
) {
	t.Helper()

	data, _ := json.Marshal(tc.request)

	mock.ExpectGet(prefix + "oidc:user_code:" + tc.lookupCode).SetVal(tc.deviceCode)
	mock.ExpectGet(prefix + "oidc:device_code:" + tc.deviceCode).SetVal(string(data))

	deviceCode, req, err := store.GetDeviceCodeByUserCode(t.Context(), tc.input)

	assert.NoError(t, err)
	assert.Equal(t, tc.deviceCode, deviceCode)
	assert.Equal(t, tc.request.ClientID, req.ClientID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRedisDeviceCodeStore_Update(t *testing.T) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"
	store := NewRedisDeviceCodeStore(client, prefix)
	ctx := t.Context()

	t.Run("UpdateDeviceCode preserves TTL", func(t *testing.T) {
		deviceCode := "device-upd123"
		request := &DeviceCodeRequest{
			ClientID: "test-client",
			UserCode: "ABCD-EFGH",
			Status:   DeviceCodeStatusAuthorized,
			UserID:   "user123",
		}

		key := prefix + "oidc:device_code:" + deviceCode
		remainingTTL := 5 * time.Minute

		data, _ := json.Marshal(request)
		encryptedData := string(data)

		mock.ExpectTTL(key).SetVal(remainingTTL)
		mock.ExpectSet(key, encryptedData, remainingTTL).SetVal("OK")

		err := store.UpdateDeviceCode(ctx, deviceCode, request)

		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("UpdateDeviceCode returns error for expired code", func(t *testing.T) {
		deviceCode := "device-expired"
		request := &DeviceCodeRequest{
			Status: DeviceCodeStatusAuthorized,
		}

		key := prefix + "oidc:device_code:" + deviceCode
		mock.ExpectTTL(key).SetVal(-1 * time.Second)

		err := store.UpdateDeviceCode(ctx, deviceCode, request)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found or expired")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRedisDeviceCodeStore_Delete(t *testing.T) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"
	store := NewRedisDeviceCodeStore(client, prefix)
	ctx := t.Context()

	t.Run("DeleteDeviceCode removes device code and user code mapping", func(t *testing.T) {
		deviceCode := "device-del123"
		request := &DeviceCodeRequest{
			ClientID: "test-client",
			UserCode: "ABCD-EFGH",
			Status:   DeviceCodeStatusAuthorized,
		}

		data, _ := json.Marshal(request)

		// GetDeviceCode is called first to find user code
		mock.ExpectGet(prefix + "oidc:device_code:" + deviceCode).SetVal(string(data))
		mock.ExpectDel(prefix + "oidc:user_code:ABCD-EFGH").SetVal(1)
		mock.ExpectDel(prefix + "oidc:device_code:" + deviceCode).SetVal(1)

		err := store.DeleteDeviceCode(ctx, deviceCode)

		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeviceCodeStatus(t *testing.T) {
	t.Run("status constants have correct values", func(t *testing.T) {
		assert.Equal(t, DeviceCodeStatus("pending"), DeviceCodeStatusPending)
		assert.Equal(t, DeviceCodeStatus("authorized"), DeviceCodeStatusAuthorized)
		assert.Equal(t, DeviceCodeStatus("denied"), DeviceCodeStatusDenied)
	})
}
