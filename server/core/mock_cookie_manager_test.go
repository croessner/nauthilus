// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/gin-gonic/gin"
)

type mockCookieManager struct {
	data    map[string]any
	saveErr error
	saves   int
}

func (m *mockCookieManager) Set(key string, value any) { m.data[key] = value }

func (m *mockCookieManager) Get(key string) (any, bool) {
	value, ok := m.data[key]

	return value, ok
}

func (m *mockCookieManager) Delete(key string) { delete(m.data, key) }

func (m *mockCookieManager) Clear() { m.data = make(map[string]any) }

func (m *mockCookieManager) Save(_ *gin.Context) error {
	m.saves++

	return m.saveErr
}

func (m *mockCookieManager) Load(_ *gin.Context) error { return nil }

func (m *mockCookieManager) GetString(key string, defaultValue string) string {
	if value, ok := m.data[key].(string); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) GetInt(key string, defaultValue int) int {
	if value, ok := m.data[key].(int); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) GetInt64(key string, defaultValue int64) int64 {
	if value, ok := m.data[key].(int64); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) GetUint8(key string, defaultValue uint8) uint8 {
	if value, ok := m.data[key].(uint8); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) GetBool(key string, defaultValue bool) bool {
	if value, ok := m.data[key].(bool); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) GetStringSlice(key string, defaultValue []string) []string {
	if value, ok := m.data[key].([]string); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) GetDuration(key string, defaultValue time.Duration) time.Duration {
	if value, ok := m.data[key].(time.Duration); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) GetBytes(key string, defaultValue []byte) []byte {
	if value, ok := m.data[key].([]byte); ok {
		return value
	}

	return defaultValue
}

func (m *mockCookieManager) Debug(_ *gin.Context, _ *slog.Logger, _ string) {}

func (m *mockCookieManager) HasKey(key string) bool {
	_, ok := m.data[key]

	return ok
}

func (m *mockCookieManager) SetMaxAge(_ int) {}

func (m *mockCookieManager) ComputeHMAC(data []byte) []byte {
	hash := hmac.New(sha256.New, []byte("test-hmac-key-for-mock"))
	_, _ = hash.Write(data)

	return hash.Sum(nil)
}

var _ cookie.Manager = (*mockCookieManager)(nil)
