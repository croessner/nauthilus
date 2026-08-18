// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// mockCookieManager remains test-only so canonical negative tests can prove
// that stale legacy browser state is ignored.
type mockCookieManager struct {
	data      map[string]any
	saves     int
	saveErr   error
	mutations []string
}

func (m *mockCookieManager) Set(key string, value any) {
	m.mutations = append(m.mutations, "set:"+key)
	m.data[key] = value
}

func (m *mockCookieManager) Get(key string) (any, bool) {
	value, ok := m.data[key]

	return value, ok
}

func (m *mockCookieManager) Delete(key string) {
	m.mutations = append(m.mutations, "delete:"+key)
	delete(m.data, key)
}

func (m *mockCookieManager) Clear() {
	m.mutations = append(m.mutations, "clear")
	m.data = make(map[string]any)
}

func (m *mockCookieManager) Save(_ *gin.Context) error {
	m.mutations = append(m.mutations, "save")
	m.saves++

	return m.saveErr
}

func (m *mockCookieManager) Load(_ *gin.Context) error { return nil }

func (m *mockCookieManager) GetString(key string, fallback string) string {
	if value, ok := m.data[key].(string); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) GetInt(key string, fallback int) int {
	if value, ok := m.data[key].(int); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) GetInt64(key string, fallback int64) int64 {
	if value, ok := m.data[key].(int64); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) GetUint8(key string, fallback uint8) uint8 {
	if value, ok := m.data[key].(uint8); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) GetBool(key string, fallback bool) bool {
	if value, ok := m.data[key].(bool); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) GetStringSlice(key string, fallback []string) []string {
	if value, ok := m.data[key].([]string); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) GetDuration(key string, fallback time.Duration) time.Duration {
	if value, ok := m.data[key].(time.Duration); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) Debug(_ *gin.Context, _ *slog.Logger, _ string) {}

func (m *mockCookieManager) HasKey(key string) bool {
	_, ok := m.data[key]

	return ok
}

func (m *mockCookieManager) GetBytes(key string, fallback []byte) []byte {
	if value, ok := m.data[key].([]byte); ok {
		return value
	}

	return fallback
}

func (m *mockCookieManager) SetMaxAge(maxAge int) {
	m.mutations = append(m.mutations, fmt.Sprintf("max-age:%d", maxAge))
}

func (m *mockCookieManager) ComputeHMAC(data []byte) []byte {
	hash := hmac.New(sha256.New, []byte("test-hmac-key-for-mock"))
	_, _ = hash.Write(data)

	return hash.Sum(nil)
}
