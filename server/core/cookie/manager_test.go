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
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// testEnv implements config.Environment for testing.
type testEnv struct {
	devMode bool
}

func (e *testEnv) GetDevMode() bool {
	return e.devMode
}

const testSecret = "test-secret-key-for-cookie-encryption"

func newTestManager(cookieName string, devMode bool) *SecureManager {
	return NewSecureManager(testSecret, cookieName, nil, &testEnv{devMode: devMode})
}

func TestNewSecureManager(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	assert.NotNil(t, mgr)
	assert.NotNil(t, mgr.codec)
	assert.Equal(t, "test_cookie", mgr.cookieName)
	assert.NotNil(t, mgr.data)
	assert.Equal(t, "/", mgr.path)
	assert.Equal(t, 0, mgr.maxAge)
}

func TestSecureManager_SetGet(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	mgr.Set("username", "testuser")
	mgr.Set("authenticated", true)
	mgr.Set("count", 42)

	val, ok := mgr.Get("username")
	assert.True(t, ok)
	assert.Equal(t, "testuser", val)

	val, ok = mgr.Get("authenticated")
	assert.True(t, ok)
	assert.Equal(t, true, val)

	val, ok = mgr.Get("count")
	assert.True(t, ok)
	assert.Equal(t, 42, val)

	val, ok = mgr.Get("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestSecureManager_Delete(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	mgr.Set("key1", "value1")
	mgr.Set("key2", "value2")

	val, ok := mgr.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	mgr.Delete("key1")

	val, ok = mgr.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)

	// key2 should still exist.
	val, ok = mgr.Get("key2")
	assert.True(t, ok)
	assert.Equal(t, "value2", val)
}

func TestSecureManager_Clear(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	mgr.Set("key1", "value1")
	mgr.Set("key2", "value2")

	mgr.Clear()

	val, ok := mgr.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)

	val, ok = mgr.Get("key2")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestSecureManager_TypedGetters(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	// Setup test data.
	mgr.Set("str", "hello")
	mgr.Set("int", 42)
	mgr.Set("int64", int64(123456789))
	mgr.Set("uint8", uint8(255))
	mgr.Set("bool", true)
	mgr.Set("strSlice", []string{"a", "b", "c"})
	mgr.Set("duration", 5*time.Second)

	// Test GetString.
	assert.Equal(t, "hello", mgr.GetString("str", "default"))
	assert.Equal(t, "default", mgr.GetString("missing", "default"))
	assert.Equal(t, "default", mgr.GetString("int", "default")) // Wrong type.

	// Test GetInt.
	assert.Equal(t, 42, mgr.GetInt("int", 0))
	assert.Equal(t, 0, mgr.GetInt("missing", 0))
	assert.Equal(t, -1, mgr.GetInt("str", -1)) // Wrong type.

	// Test GetInt64.
	assert.Equal(t, int64(123456789), mgr.GetInt64("int64", 0))
	assert.Equal(t, int64(0), mgr.GetInt64("missing", 0))

	// Test GetUint8.
	assert.Equal(t, uint8(255), mgr.GetUint8("uint8", 0))
	assert.Equal(t, uint8(0), mgr.GetUint8("missing", 0))

	// Test GetBool.
	assert.Equal(t, true, mgr.GetBool("bool", false))
	assert.Equal(t, false, mgr.GetBool("missing", false))
	assert.Equal(t, true, mgr.GetBool("str", true)) // Wrong type, returns default.

	// Test GetStringSlice.
	assert.Equal(t, []string{"a", "b", "c"}, mgr.GetStringSlice("strSlice", nil))
	assert.Nil(t, mgr.GetStringSlice("missing", nil))

	// Test GetDuration.
	assert.Equal(t, 5*time.Second, mgr.GetDuration("duration", 0))
	assert.Equal(t, time.Duration(0), mgr.GetDuration("missing", 0))
}

func TestSecureManager_SaveLoad(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Set up the default environment for util.ShouldSetSecureCookie.
	util.SetDefaultEnvironment(&testEnv{devMode: true})

	// Create and populate manager.
	mgr1 := NewSecureManager(testSecret, "secure_data", nil, &testEnv{devMode: true})
	mgr1.Set("account", "user@example.com")
	mgr1.Set("auth_result", uint8(1))
	mgr1.Set("authenticated", true)

	// Save the cookie.
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	err := mgr1.Save(ctx)
	if err != nil {
		t.Fatalf("unexpected error saving cookie: %v", err)
	}

	// Extract cookies from response.
	cookies := w.Result().Cookies()

	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	assert.Equal(t, "secure_data", cookies[0].Name)

	// Load into a new manager.
	mgr2 := NewSecureManager(testSecret, "secure_data", nil, &testEnv{devMode: true})

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	for _, c := range cookies {
		req.AddCookie(c)
	}

	ctx2, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx2.Request = req

	err = mgr2.Load(ctx2)
	if err != nil {
		t.Fatalf("unexpected error loading cookie: %v", err)
	}

	// Verify loaded data.
	assert.Equal(t, "user@example.com", mgr2.GetString("account", ""))
	assert.Equal(t, uint8(1), mgr2.GetUint8("auth_result", 0))
	assert.Equal(t, true, mgr2.GetBool("authenticated", false))
}

func TestSecureManager_LoadNoCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mgr := newTestManager("secure_data", false)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	err := mgr.Load(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Data should be empty but not nil.
	assert.NotNil(t, mgr.data)
	assert.Len(t, mgr.data, 0)
}

func TestSecureManager_LoadInvalidCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mgr := newTestManager("secure_data", false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "secure_data",
		Value: "invalid-garbage-data",
	})

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req

	err := mgr.Load(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Data should be reset to empty.
	assert.NotNil(t, mgr.data)
	assert.Len(t, mgr.data, 0)
}

func TestSecureManager_HasKey(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	mgr.Set("exists", "value")

	assert.True(t, mgr.HasKey("exists"))
	assert.False(t, mgr.HasKey("missing"))
}

func TestSecureManager_Keys(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	mgr.Set("key1", "value1")
	mgr.Set("key2", "value2")
	mgr.Set("key3", "value3")

	keys := mgr.Keys()
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, "key1")
	assert.Contains(t, keys, "key2")
	assert.Contains(t, keys, "key3")
}

func TestSecureManager_SetMaxAge(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	assert.Equal(t, 0, mgr.maxAge)

	mgr.SetMaxAge(3600)

	assert.Equal(t, 3600, mgr.maxAge)
}

func TestSecureManager_SetPath(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	assert.Equal(t, "/", mgr.path)

	mgr.SetPath("/api")

	assert.Equal(t, "/api", mgr.path)
}

func TestSecureManager_MaskSensitiveValues(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	mgr.Set("account", "user@example.com")
	mgr.Set("totp_secret", "JBSWY3DPEHPK3PXP")
	mgr.Set("totp_url", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP")
	mgr.Set("auth_result", uint8(1))
	mgr.Set("password", "secret123")

	// Without dev mode, sensitive values should be masked.
	masked := mgr.maskSensitiveValues(false)

	assert.Equal(t, "user@example.com", masked["account"])
	assert.Equal(t, "<hidden>", masked["totp_secret"])
	assert.Equal(t, "<hidden>", masked["totp_url"])
	assert.Equal(t, "<hidden>", masked["auth_result"])
	assert.Equal(t, "<hidden>", masked["password"])

	// With dev mode, all values should be visible.
	visible := mgr.maskSensitiveValues(true)

	assert.Equal(t, "user@example.com", visible["account"])
	assert.Equal(t, "JBSWY3DPEHPK3PXP", visible["totp_secret"])
	assert.Equal(t, "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP", visible["totp_url"])
	assert.Equal(t, uint8(1), visible["auth_result"])
	assert.Equal(t, "secret123", visible["password"])
}

func TestSecureManager_IsSensitiveKey(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	// Direct matches.
	assert.True(t, mgr.isSensitiveKey("totp_secret"))
	assert.True(t, mgr.isSensitiveKey("TOTP_SECRET"))
	assert.True(t, mgr.isSensitiveKey("auth_result"))
	assert.True(t, mgr.isSensitiveKey("password"))

	// Partial matches.
	assert.True(t, mgr.isSensitiveKey("my_password_field"))
	assert.True(t, mgr.isSensitiveKey("secret_key"))

	// Non-sensitive keys.
	assert.False(t, mgr.isSensitiveKey("account"))
	assert.False(t, mgr.isSensitiveKey("username"))
	assert.False(t, mgr.isSensitiveKey("display_name"))
}

func TestSecureManager_Debug(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mgr := newTestManager("test_cookie", false)

	mgr.Set("account", "user@example.com")
	mgr.Set("totp_secret", "sensitive")

	// Create a logger that writes to discard (just verify no panic).
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create a test gin context.
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	// Should not panic.
	mgr.Debug(ctx, logger, "test debug message")

	// With nil logger should not panic.
	mgr.Debug(ctx, nil, "test debug message")
}

func TestSecureManager_GetUint8_IntConversions(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	// Test int to uint8 conversion.
	mgr.Set("int_val", 100)

	assert.Equal(t, uint8(100), mgr.GetUint8("int_val", 0))

	// Test int64 to uint8 conversion.
	mgr.Set("int64_val", int64(200))

	assert.Equal(t, uint8(200), mgr.GetUint8("int64_val", 0))

	// Test out of range int (negative).
	mgr.Set("negative", -1)

	assert.Equal(t, uint8(0), mgr.GetUint8("negative", 0))

	// Test out of range int (too large).
	mgr.Set("too_large", 300)

	assert.Equal(t, uint8(0), mgr.GetUint8("too_large", 0))
}

func TestSecureManager_GetInt_TypeConversions(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	// int64 to int.
	mgr.Set("int64_val", int64(42))

	assert.Equal(t, 42, mgr.GetInt("int64_val", 0))

	// int32 to int.
	mgr.Set("int32_val", int32(42))

	assert.Equal(t, 42, mgr.GetInt("int32_val", 0))
}

func TestSecureManager_GetInt_OverflowProtection(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	// Test int64 value within int range.
	mgr.Set("safe_val", int64(1000000))

	assert.Equal(t, 1000000, mgr.GetInt("safe_val", -1))

	// Test int64 value at max int (should work).
	mgr.Set("max_int", int64(math.MaxInt))

	assert.Equal(t, math.MaxInt, mgr.GetInt("max_int", -1))

	// Test int64 value at min int (should work).
	mgr.Set("min_int", int64(math.MinInt))

	assert.Equal(t, math.MinInt, mgr.GetInt("min_int", 0))

	// Test int64 value exceeding max int (should return default).
	// On 64-bit systems math.MaxInt == math.MaxInt64, so we use a different approach.
	// We test with a value that would definitely overflow on 32-bit systems.
	if math.MaxInt < math.MaxInt64 {
		// On 32-bit systems.
		mgr.Set("overflow_pos", int64(math.MaxInt64))

		assert.Equal(t, -1, mgr.GetInt("overflow_pos", -1), "should return default for overflow")

		mgr.Set("overflow_neg", int64(math.MinInt64))

		assert.Equal(t, -1, mgr.GetInt("overflow_neg", -1), "should return default for underflow")
	}

	// Test negative int64 conversion.
	mgr.Set("negative", int64(-500))

	assert.Equal(t, -500, mgr.GetInt("negative", 0))
}

func TestSecureManager_GetInt64_TypeConversions(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	// int to int64.
	mgr.Set("int_val", 42)

	assert.Equal(t, int64(42), mgr.GetInt64("int_val", 0))

	// int32 to int64.
	mgr.Set("int32_val", int32(42))

	assert.Equal(t, int64(42), mgr.GetInt64("int32_val", 0))
}

func TestSecureManager_GetDuration_TypeConversions(t *testing.T) {
	mgr := newTestManager("test_cookie", false)

	// int64 to Duration.
	mgr.Set("int64_val", int64(5000000000)) // 5 seconds in nanoseconds

	assert.Equal(t, 5*time.Second, mgr.GetDuration("int64_val", 0))

	// int to Duration.
	mgr.Set("int_val", 1000000000) // 1 second in nanoseconds

	assert.Equal(t, time.Second, mgr.GetDuration("int_val", 0))
}

// TestManagerInterface verifies that SecureManager implements Manager interface.
func TestManagerInterface(t *testing.T) {
	var _ Manager = (*SecureManager)(nil)

	mgr := newTestManager("test_cookie", false)
	var iface Manager = mgr

	iface.Set("key", "value")
	val, ok := iface.Get("key")

	assert.True(t, ok)
	assert.Equal(t, "value", val)
}
