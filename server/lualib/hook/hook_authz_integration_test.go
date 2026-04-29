// Copyright (C) 2024 Christian Rößner
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

package hook

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type mockTokenValidator struct {
	claims jwt.MapClaims
	err    error
}

func (m *mockTokenValidator) ValidateToken(_ context.Context, _ string) (jwt.MapClaims, error) {
	return m.claims, m.err
}

func setupHookTestConfig(t *testing.T) config.File {
	t.Helper()

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix:      "t:",
				NegCacheTTL: time.Hour,
			},
		},
	}
	config.SetTestFile(cfg)

	return config.GetFile()
}

func withIsolatedHookRoles(t *testing.T) {
	t.Helper()

	mu.Lock()
	orig := make(map[string][]string, len(hookScopes))
	for k, v := range hookScopes {
		clone := append([]string(nil), v...)
		orig[k] = clone
	}
	origAliases := make(map[string]string, len(hookAliasLocations))
	for k, v := range hookAliasLocations {
		origAliases[k] = v
	}
	origLocation := customLocation
	hookScopes = make(map[string][]string)
	hookAliasLocations = make(map[string]string)
	customLocation = NewCustomLocation()
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		hookScopes = orig
		hookAliasLocations = origAliases
		customLocation = origLocation
		mu.Unlock()
	})
}

func setHookScopes(location, method string, scopes []string) {
	mu.Lock()
	hookScopes[getHookKey(location, method)] = append([]string(nil), scopes...)
	mu.Unlock()
}

func newHookTestContext(method, path string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(method, path, nil)
	ctx.Set(definitions.CtxGUIDKey, "guid-test")

	return ctx, rec
}

func writeHookScript(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hook.lua")
	content := []byte(`function nauthilus_run_hook(request)
	return {}
end
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write hook script: %v", err)
	}

	return path
}

func TestHasRequiredScopes_PublicHookAllows(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/foo")

	ok := HasRequiredScopes(ctx, cfg, logger, nil, "/custom/foo", http.MethodGet)
	if !ok {
		t.Fatal("expected public hook to be allowed")
	}

	if ctx.IsAborted() {
		t.Fatal("did not expect aborted context for public hook")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestHasRequiredScopes_ValidatorMissingDeniesUnauthorized(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/secure")
	setHookScopes("/custom/secure", http.MethodGet, []string{"scope:a"})

	ok := HasRequiredScopes(ctx, cfg, logger, nil, "/custom/secure", http.MethodGet)
	if ok {
		t.Fatal("expected missing validator to deny access")
	}

	if !ctx.IsAborted() {
		t.Fatal("expected aborted context")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHasRequiredScopes_ScopeMatchAllows(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/secure")
	setHookScopes("/custom/secure", http.MethodGet, []string{"scope:a"})
	ctx.Request.Header.Set("Authorization", "Bearer token")

	validator := &mockTokenValidator{
		claims: jwt.MapClaims{"scope": "scope:a scope:b"},
	}

	ok := HasRequiredScopes(ctx, cfg, logger, validator, "/custom/secure", http.MethodGet)
	if !ok {
		t.Fatal("expected scope match to allow access")
	}

	if ctx.IsAborted() {
		t.Fatal("did not expect aborted context for authorized request")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestHasRequiredScopes_ScopeMissDeniesForbidden(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/secure")
	setHookScopes("/custom/secure", http.MethodGet, []string{"scope:a"})
	ctx.Request.Header.Set("Authorization", "Bearer token")

	validator := &mockTokenValidator{
		claims: jwt.MapClaims{"scope": "scope:x"},
	}

	ok := HasRequiredScopes(ctx, cfg, logger, validator, "/custom/secure", http.MethodGet)
	if ok {
		t.Fatal("expected scope miss to deny access")
	}

	if !ctx.IsAborted() {
		t.Fatal("expected aborted context")
	}

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHasRequiredScopes_MissingBearerDeniesUnauthorized(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/secure")
	setHookScopes("/custom/secure", http.MethodGet, []string{"scope:a"})

	validator := &mockTokenValidator{
		claims: jwt.MapClaims{"scope": "scope:a"},
	}

	ok := HasRequiredScopes(ctx, cfg, logger, validator, "/custom/secure", http.MethodGet)
	if ok {
		t.Fatal("expected missing bearer token to deny access")
	}

	if !ctx.IsAborted() {
		t.Fatal("expected aborted context")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHasRequiredScopes_InvalidTokenDeniesUnauthorized(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/secure")
	setHookScopes("/custom/secure", http.MethodGet, []string{"scope:a"})
	ctx.Request.Header.Set("Authorization", "Bearer bad")

	validator := &mockTokenValidator{
		err: fmt.Errorf("invalid token"),
	}

	ok := HasRequiredScopes(ctx, cfg, logger, validator, "/custom/secure", http.MethodGet)
	if ok {
		t.Fatal("expected invalid token to deny access")
	}

	if !ctx.IsAborted() {
		t.Fatal("expected aborted context")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPreCompileLuaHooks_RegistersAbsoluteAlias(t *testing.T) {
	withIsolatedHookRoles(t)

	scriptPath := writeHookScript(t)
	cfg := &config.FileSettings{
		Lua: &config.LuaSection{
			Hooks: []config.LuaHooks{
				{
					Location:      "canonical-hook",
					AliasLocation: "/external/hook",
					Method:        http.MethodPost,
					ScriptPath:    scriptPath,
					Scopes:        []string{"scope:hook"},
				},
			},
		},
	}

	if err := PreCompileLuaHooks(cfg); err != nil {
		t.Fatalf("PreCompileLuaHooks() error = %v", err)
	}

	canonicalHook, found := ResolveAliasLocation("/external/hook", http.MethodPost)
	if !found {
		t.Fatal("expected alias to resolve")
	}

	if canonicalHook != "canonical-hook" {
		t.Fatalf("ResolveAliasLocation() = %q, want canonical-hook", canonicalHook)
	}

	if _, found := ResolveAliasLocation("/external/hook", http.MethodGet); found {
		t.Fatal("did not expect alias to resolve for a different method")
	}
}

func TestPreCompileLuaHooks_ClearsRemovedAliases(t *testing.T) {
	withIsolatedHookRoles(t)

	scriptPath := writeHookScript(t)
	cfg := &config.FileSettings{
		Lua: &config.LuaSection{
			Hooks: []config.LuaHooks{
				{
					Location:      "canonical-hook",
					AliasLocation: "/external/hook",
					Method:        http.MethodPost,
					ScriptPath:    scriptPath,
				},
			},
		},
	}

	if err := PreCompileLuaHooks(cfg); err != nil {
		t.Fatalf("PreCompileLuaHooks() error = %v", err)
	}

	if _, found := ResolveAliasLocation("/external/hook", http.MethodPost); !found {
		t.Fatal("expected alias to resolve before refresh")
	}

	cfg.Lua.Hooks = nil
	if err := PreCompileLuaHooks(cfg); err != nil {
		t.Fatalf("PreCompileLuaHooks() refresh error = %v", err)
	}

	if _, found := ResolveAliasLocation("/external/hook", http.MethodPost); found {
		t.Fatal("did not expect removed alias to resolve after refresh")
	}
}

func TestHasRequiredScopes_AliasUsesCanonicalHookScopes(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/external/hook")
	ctx.Set(definitions.CtxCustomHookKey, "canonical-hook")
	setHookScopes("canonical-hook", http.MethodGet, []string{"scope:a"})
	ctx.Request.Header.Set("Authorization", "Bearer token")

	validator := &mockTokenValidator{
		claims: jwt.MapClaims{"scope": "scope:a"},
	}

	ok := HasRequiredScopes(ctx, cfg, logger, validator, ResolveRequestHook(ctx), http.MethodGet)
	if !ok {
		t.Fatal("expected canonical hook scopes to allow alias request")
	}

	if ctx.IsAborted() {
		t.Fatal("did not expect aborted context for authorized alias request")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}
