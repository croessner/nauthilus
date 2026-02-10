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

	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestDefaultUserCodeGenerator_GenerateUserCode(t *testing.T) {
	gen := &DefaultUserCodeGenerator{}

	t.Run("generates code with correct length", func(t *testing.T) {
		code, err := gen.GenerateUserCode(8)

		assert.NoError(t, err)

		// Code should be 9 chars: 4 + hyphen + 4
		assert.Len(t, code, 9)
		assert.Equal(t, "-", string(code[4]))
	})

	t.Run("generates code with correct charset", func(t *testing.T) {
		const validChars = "ABCDEFGHJKMNPQRSTVWXYZ-"

		code, err := gen.GenerateUserCode(8)

		assert.NoError(t, err)

		for _, c := range code {
			assert.Contains(t, validChars, string(c), "unexpected character: %c", c)
		}
	})

	t.Run("excludes confusing characters", func(t *testing.T) {
		const confusing = "OIL01"

		// Generate many codes and check none contain confusing characters
		for range 100 {
			code, err := gen.GenerateUserCode(8)

			assert.NoError(t, err)

			cleaned := strings.ReplaceAll(code, "-", "")

			for _, c := range cleaned {
				assert.NotContains(t, confusing, string(c), "confusing character found: %c", c)
			}
		}
	})

	t.Run("generates unique codes", func(t *testing.T) {
		seen := make(map[string]bool)

		for range 50 {
			code, err := gen.GenerateUserCode(8)

			assert.NoError(t, err)

			assert.False(t, seen[code], "duplicate code generated: %s", code)

			seen[code] = true
		}
	})

	t.Run("handles different lengths", func(t *testing.T) {
		code, err := gen.GenerateUserCode(6)

		assert.NoError(t, err)

		// Should be 7 chars: 3 + hyphen + 3
		assert.Len(t, code, 7)
		assert.Equal(t, "-", string(code[3]))
	})
}

func TestRedisDeviceCodeStore_StoreAndGet(t *testing.T) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"
	store := NewRedisDeviceCodeStore(client, prefix)
	ctx := t.Context()

	t.Run("StoreDeviceCode stores both device code and user code mapping", func(t *testing.T) {
		deviceCode := "device-abc123"
		request := &DeviceCodeRequest{
			ClientID:  "test-client",
			Scopes:    []string{"openid", "email"},
			UserCode:  "ABCD-EFGH",
			Status:    DeviceCodeStatusPending,
			ExpiresAt: time.Now().Add(10 * time.Minute),
			Interval:  5,
		}

		ttl := 10 * time.Minute
		data, _ := json.Marshal(request)
		encryptedData := string(data) // Passthrough encryption with empty key

		mock.ExpectSet(prefix+"oidc:device_code:"+deviceCode, encryptedData, ttl).SetVal("OK")
		mock.ExpectSet(prefix+"oidc:user_code:ABCD-EFGH", deviceCode, ttl).SetVal("OK")

		err := store.StoreDeviceCode(ctx, deviceCode, request, ttl)

		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetDeviceCode retrieves stored request", func(t *testing.T) {
		deviceCode := "device-get123"
		request := &DeviceCodeRequest{
			ClientID:  "test-client",
			Scopes:    []string{"openid"},
			UserCode:  "XYZW-MNPQ",
			Status:    DeviceCodeStatusPending,
			ExpiresAt: time.Now().Add(5 * time.Minute),
			Interval:  5,
		}

		data, _ := json.Marshal(request)

		mock.ExpectGet(prefix + "oidc:device_code:" + deviceCode).SetVal(string(data))

		retrieved, err := store.GetDeviceCode(ctx, deviceCode)

		assert.NoError(t, err)
		assert.Equal(t, request.ClientID, retrieved.ClientID)
		assert.Equal(t, request.UserCode, retrieved.UserCode)
		assert.Equal(t, DeviceCodeStatusPending, retrieved.Status)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetDeviceCode returns error for expired/missing code", func(t *testing.T) {
		mock.ExpectGet(prefix + "oidc:device_code:nonexistent").RedisNil()

		_, err := store.GetDeviceCode(ctx, "nonexistent")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found or expired")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRedisDeviceCodeStore_GetByUserCode(t *testing.T) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"
	store := NewRedisDeviceCodeStore(client, prefix)
	ctx := t.Context()

	t.Run("GetDeviceCodeByUserCode normalizes and retrieves", func(t *testing.T) {
		deviceCode := "device-user123"
		request := &DeviceCodeRequest{
			ClientID: "test-client",
			UserCode: "ABCD-EFGH",
			Status:   DeviceCodeStatusPending,
		}

		data, _ := json.Marshal(request)

		// User enters "abcdefgh" -> normalized to "ABCD-EFGH"
		mock.ExpectGet(prefix + "oidc:user_code:ABCD-EFGH").SetVal(deviceCode)
		mock.ExpectGet(prefix + "oidc:device_code:" + deviceCode).SetVal(string(data))

		dc, req, err := store.GetDeviceCodeByUserCode(ctx, "abcdefgh")

		assert.NoError(t, err)
		assert.Equal(t, deviceCode, dc)
		assert.Equal(t, request.ClientID, req.ClientID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetDeviceCodeByUserCode handles hyphenated input", func(t *testing.T) {
		deviceCode := "device-hyp123"
		request := &DeviceCodeRequest{
			ClientID: "test-client",
			UserCode: "XYZW-MNPQ",
			Status:   DeviceCodeStatusPending,
		}

		data, _ := json.Marshal(request)

		// User enters "XYZW-MNPQ" -> normalized to "XYZW-MNPQ"
		mock.ExpectGet(prefix + "oidc:user_code:XYZW-MNPQ").SetVal(deviceCode)
		mock.ExpectGet(prefix + "oidc:device_code:" + deviceCode).SetVal(string(data))

		dc, req, err := store.GetDeviceCodeByUserCode(ctx, "XYZW-MNPQ")

		assert.NoError(t, err)
		assert.Equal(t, deviceCode, dc)
		assert.Equal(t, request.ClientID, req.ClientID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetDeviceCodeByUserCode returns error for invalid code", func(t *testing.T) {
		mock.ExpectGet(prefix + "oidc:user_code:INVA-LIDC").RedisNil()

		_, _, err := store.GetDeviceCodeByUserCode(ctx, "INVA-LIDC")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found or expired")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
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
