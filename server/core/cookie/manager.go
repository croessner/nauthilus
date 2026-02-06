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

// Package cookie provides secure encrypted cookie management for storing
// sensitive session data in a single encrypted browser cookie.
package cookie

import (
	"encoding/gob"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

func init() {
	// Register types that will be stored in the cookie map.
	gob.Register(map[string]any{})
	gob.Register([]string{})
	gob.Register([]byte{})
	gob.Register(time.Time{})
	gob.Register(time.Duration(0))
}

// Manager defines the interface for secure cookie storage operations.
// All session data is stored in a single encrypted cookie.
type Manager interface {
	// Set stores a key-value pair in the cookie data.
	Set(key string, value any)

	// Get retrieves a value by key from the cookie data.
	// Returns nil and false if the key does not exist.
	Get(key string) (any, bool)

	// Delete removes a key from the cookie data.
	Delete(key string)

	// Clear removes all data from the cookie.
	Clear()

	// Save persists the encrypted cookie to the response.
	Save(ctx *gin.Context) error

	// Load reads and decrypts the cookie from the request.
	// If the cookie does not exist or cannot be decoded, it initializes empty data.
	Load(ctx *gin.Context) error

	// GetString retrieves a string value by key, returning the default if not found or wrong type.
	GetString(key string, defaultValue string) string

	// GetInt retrieves an int value by key, returning the default if not found or wrong type.
	GetInt(key string, defaultValue int) int

	// GetInt64 retrieves an int64 value by key, returning the default if not found or wrong type.
	GetInt64(key string, defaultValue int64) int64

	// GetUint8 retrieves a uint8 value by key, returning the default if not found or wrong type.
	GetUint8(key string, defaultValue uint8) uint8

	// GetBool retrieves a bool value by key, returning the default if not found or wrong type.
	GetBool(key string, defaultValue bool) bool

	// GetStringSlice retrieves a []string value by key, returning the default if not found or wrong type.
	GetStringSlice(key string, defaultValue []string) []string

	// GetDuration retrieves a time.Duration value by key, returning the default if not found or wrong type.
	GetDuration(key string, defaultValue time.Duration) time.Duration

	// GetBytes retrieves a []byte value by key, returning the default if not found or wrong type.
	GetBytes(key string, defaultValue []byte) []byte

	// Debug logs the current cookie data with sensitive values masked.
	Debug(ctx *gin.Context, logger *slog.Logger, msg string)

	// HasKey checks if a key exists in the cookie data.
	HasKey(key string) bool

	// SetMaxAge sets the maximum age of the cookie in seconds.
	SetMaxAge(maxAge int)
}

// SecureManager implements Manager using ChaCha20-Poly1305 for encryption.
type SecureManager struct {
	codec      *SecureCodec
	cfg        config.File
	cookieName string
	data       map[string]any
	path       string
	maxAge     int
	env        config.Environment
}

// sensitiveKeys lists keys whose values should be masked in debug output unless developer mode is enabled.
var sensitiveKeys = map[string]bool{
	"totp_secret": true,
	"totp_url":    true,
	"auth_result": true,
	"password":    true,
	"secret":      true,
}

// NewSecureManager creates a new encrypted cookie manager.
// The secret is used to derive encryption and authentication keys via SHA256.
// The cfg parameter provides access to debug module configuration.
func NewSecureManager(secret string, cookieName string, cfg config.File, env config.Environment) *SecureManager {
	codec := NewSecureCodec(secret)

	return &SecureManager{
		codec:      codec,
		cfg:        cfg,
		cookieName: cookieName,
		data:       make(map[string]any),
		path:       "/",
		maxAge:     0, // Session cookie by default
		env:        env,
	}
}

// Set stores a key-value pair in the cookie data.
func (m *SecureManager) Set(key string, value any) {
	m.data[key] = value
}

// Get retrieves a value by key from the cookie data.
func (m *SecureManager) Get(key string) (any, bool) {
	val, ok := m.data[key]

	return val, ok
}

// Delete removes a key from the cookie data.
func (m *SecureManager) Delete(key string) {
	delete(m.data, key)
}

// Clear removes all data from the cookie.
func (m *SecureManager) Clear() {
	m.data = make(map[string]any)
}

// Save persists the encrypted cookie to the response.
func (m *SecureManager) Save(ctx *gin.Context) error {
	encoded, err := m.codec.Encode(m.cookieName, m.data)
	if err != nil {
		return fmt.Errorf("failed to encode cookie: %w", err)
	}

	secure := util.ShouldSetSecureCookie()

	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     m.cookieName,
		Value:    encoded,
		Path:     m.path,
		MaxAge:   m.maxAge,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

// Load reads and decrypts the cookie from the request.
func (m *SecureManager) Load(ctx *gin.Context) error {
	cookie, err := ctx.Request.Cookie(m.cookieName)
	if err != nil {
		// No cookie exists, start with empty data.
		m.data = make(map[string]any)

		return nil
	}

	var data map[string]any

	if err := m.codec.Decode(m.cookieName, cookie.Value, &data); err != nil {
		// Cookie is invalid, tampered, or expired - start fresh.
		m.data = make(map[string]any)

		return nil
	}

	m.data = data

	return nil
}

// GetString retrieves a string value by key, returning the default if not found or wrong type.
func (m *SecureManager) GetString(key string, defaultValue string) string {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	if s, ok := val.(string); ok {
		return s
	}

	return defaultValue
}

// GetInt retrieves an int value by key, returning the default if not found or wrong type.
// Returns defaultValue if the stored int64 value would overflow the int type.
func (m *SecureManager) GetInt(key string, defaultValue int) int {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	switch v := val.(type) {
	case int:
		return v
	case int64:
		if v >= math.MinInt && v <= math.MaxInt {
			return int(v)
		}

		return defaultValue
	case int32:
		return int(v)
	default:
		return defaultValue
	}
}

// GetInt64 retrieves an int64 value by key, returning the default if not found or wrong type.
func (m *SecureManager) GetInt64(key string, defaultValue int64) int64 {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	switch v := val.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case int32:
		return int64(v)
	default:
		return defaultValue
	}
}

// GetUint8 retrieves a uint8 value by key, returning the default if not found or wrong type.
func (m *SecureManager) GetUint8(key string, defaultValue uint8) uint8 {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	switch v := val.(type) {
	case uint8:
		return v
	case int:
		if v >= 0 && v <= 255 {
			return uint8(v)
		}

		return defaultValue
	case int64:
		if v >= 0 && v <= 255 {
			return uint8(v)
		}

		return defaultValue
	default:
		return defaultValue
	}
}

// GetBool retrieves a bool value by key, returning the default if not found or wrong type.
func (m *SecureManager) GetBool(key string, defaultValue bool) bool {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	if b, ok := val.(bool); ok {
		return b
	}

	return defaultValue
}

// GetStringSlice retrieves a []string value by key, returning the default if not found or wrong type.
func (m *SecureManager) GetStringSlice(key string, defaultValue []string) []string {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	if s, ok := val.([]string); ok {
		return s
	}

	return defaultValue
}

// GetDuration retrieves a time.Duration value by key, returning the default if not found or wrong type.
func (m *SecureManager) GetDuration(key string, defaultValue time.Duration) time.Duration {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	switch v := val.(type) {
	case time.Duration:
		return v
	case int64:
		return time.Duration(v)
	case int:
		return time.Duration(v)
	default:
		return defaultValue
	}
}

// GetBytes retrieves a []byte value by key, returning the default if not found or wrong type.
func (m *SecureManager) GetBytes(key string, defaultValue []byte) []byte {
	val, ok := m.data[key]
	if !ok {
		return defaultValue
	}

	if b, ok := val.([]byte); ok {
		return b
	}

	return defaultValue
}

// Debug logs the current cookie data with sensitive values masked.
func (m *SecureManager) Debug(ctx *gin.Context, logger *slog.Logger, msg string) {
	if logger == nil || m.cfg == nil {
		return
	}

	devMode := m.env != nil && m.env.GetDevMode()
	masked := m.maskSensitiveValues(devMode)

	util.DebugModule(
		ctx.Request.Context(),
		m.cfg,
		logger,
		definitions.DbgCookie,
		"msg", msg,
		"cookie_data", fmt.Sprintf("%v", masked),
	)
}

// maskSensitiveValues returns a copy of the data map with sensitive values masked.
func (m *SecureManager) maskSensitiveValues(devMode bool) map[string]any {
	result := make(map[string]any, len(m.data))

	for k, v := range m.data {
		if !devMode && m.isSensitiveKey(k) {
			result[k] = "<hidden>"
		} else {
			result[k] = v
		}
	}

	return result
}

// isSensitiveKey checks if a key should be masked in debug output.
func (m *SecureManager) isSensitiveKey(key string) bool {
	lowerKey := strings.ToLower(key)

	if sensitiveKeys[lowerKey] {
		return true
	}

	// Check for partial matches.
	for sensitive := range sensitiveKeys {
		if strings.Contains(lowerKey, sensitive) {
			return true
		}
	}

	return false
}

// SetMaxAge sets the maximum age of the cookie in seconds.
// Use 0 for session cookies, negative values to delete.
// This also updates the codec's maxAge to ensure the internal timestamp
// validation is consistent with the browser cookie lifetime.
func (m *SecureManager) SetMaxAge(maxAge int) {
	m.maxAge = maxAge
	m.codec.SetMaxAge(maxAge)
}

// SetPath sets the cookie path.
func (m *SecureManager) SetPath(path string) {
	m.path = path
}

// HasKey checks if a key exists in the cookie data.
func (m *SecureManager) HasKey(key string) bool {
	_, ok := m.data[key]

	return ok
}

// Keys returns all keys currently stored in the cookie.
func (m *SecureManager) Keys() []string {
	keys := make([]string, 0, len(m.data))

	for k := range m.data {
		keys = append(keys, k)
	}

	return keys
}

// Compile-time interface verification.
var _ Manager = (*SecureManager)(nil)

// Middleware creates a gin middleware that loads the secure data cookie at the start
// of the request and saves it after the handler chain completes.
// The CookieManager is stored in the gin.Context under CtxSecureDataKey.
func Middleware(secret string, cfg config.File, env config.Environment) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		mgr := NewSecureManager(secret, definitions.SecureDataCookieName, cfg, env)

		// Load existing cookie data.
		_ = mgr.Load(ctx)

		// Store manager in context for handler access.
		ctx.Set(definitions.CtxSecureDataKey, mgr)

		// Process request.
		ctx.Next()

		// Save cookie after all handlers complete.
		_ = mgr.Save(ctx)
	}
}

// GetManager retrieves the CookieManager from the gin.Context.
// Returns nil if the middleware was not applied.
func GetManager(ctx *gin.Context) Manager {
	if v, exists := ctx.Get(definitions.CtxSecureDataKey); exists {
		if mgr, ok := v.(Manager); ok {
			return mgr
		}
	}

	return nil
}

// MustGetManager retrieves the CookieManager from the gin.Context.
// Panics if the middleware was not applied.
func MustGetManager(ctx *gin.Context) Manager {
	mgr := GetManager(ctx)
	if mgr == nil {
		panic("cookie.MustGetManager: CookieManager not found in context; ensure cookie.Middleware is applied")
	}

	return mgr
}
