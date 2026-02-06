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
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// mockCookieManager implements cookie.Manager for testing.
type mockCookieManager struct {
	data map[string]any
}

func (m *mockCookieManager) Set(key string, value any) {
	m.data[key] = value
}

func (m *mockCookieManager) Get(key string) (any, bool) {
	val, ok := m.data[key]
	return val, ok
}

func (m *mockCookieManager) Delete(key string) {
	delete(m.data, key)
}

func (m *mockCookieManager) Clear() {
	m.data = make(map[string]any)
}

func (m *mockCookieManager) Save(_ *gin.Context) error {
	return nil
}

func (m *mockCookieManager) Load(_ *gin.Context) error {
	return nil
}

func (m *mockCookieManager) GetString(key string, defaultValue string) string {
	if val, ok := m.data[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetInt(key string, defaultValue int) int {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(int); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetInt64(key string, defaultValue int64) int64 {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(int64); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetUint8(key string, defaultValue uint8) uint8 {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(uint8); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetBool(key string, defaultValue bool) bool {
	if val, ok := m.data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetStringSlice(key string, defaultValue []string) []string {
	if val, ok := m.data[key]; ok {
		if s, ok := val.([]string); ok {
			return s
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetDuration(key string, defaultValue time.Duration) time.Duration {
	if val, ok := m.data[key]; ok {
		if d, ok := val.(time.Duration); ok {
			return d
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetBytes(key string, defaultValue []byte) []byte {
	if val, ok := m.data[key]; ok {
		if b, ok := val.([]byte); ok {
			return b
		}
	}
	return defaultValue
}

func (m *mockCookieManager) Debug(_ *gin.Context, _ *slog.Logger, _ string) {}

func (m *mockCookieManager) HasKey(key string) bool {
	_, ok := m.data[key]
	return ok
}

func (m *mockCookieManager) SetMaxAge(_ int) {}

// Verify mockCookieManager implements cookie.Manager
var _ cookie.Manager = (*mockCookieManager)(nil)

func TestIsWebAuthnRegistrationAuthenticated(t *testing.T) {
	tests := []struct {
		name  string
		setup func(mgr *mockCookieManager)
		want  bool
	}{
		{
			name: "auth result ok",
			setup: func(mgr *mockCookieManager) {
				mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))
			},
			want: true,
		},
		{
			name: "auth result fail overrides account",
			setup: func(mgr *mockCookieManager) {
				mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultFail))
				mgr.Set(definitions.SessionKeyAccount, "testuser")
			},
			want: false,
		},
		{
			name: "account without auth result",
			setup: func(mgr *mockCookieManager) {
				mgr.Set(definitions.SessionKeyAccount, "testuser")
			},
			want: true,
		},
		{
			name:  "missing auth result and account",
			setup: func(mgr *mockCookieManager) {},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &mockCookieManager{data: make(map[string]any)}
			tt.setup(mgr)
			got := isWebAuthnRegistrationAuthenticated(mgr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveWebAuthnDisplayNameFallbacksToUserName(t *testing.T) {
	mgr := &mockCookieManager{data: make(map[string]any)}

	displayName, updated := resolveWebAuthnDisplayName(mgr, "testuser")

	assert.Equal(t, "testuser", displayName)
	assert.True(t, updated)

	storedName := mgr.GetString(definitions.SessionKeyDisplayName, "")
	assert.Equal(t, "testuser", storedName)
}
