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
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/secret"
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

// hookAccessClaims returns valid backchannel access-token claims for hook tests.
func hookAccessClaims(scope string) jwt.MapClaims {
	return jwt.MapClaims{
		"aud":                      definitions.AudienceBackchannelAPI,
		"scope":                    scope,
		"sub":                      "hook-client",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
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

func setupHookBasicAuthConfig(t *testing.T, enabled bool) config.File {
	t.Helper()

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix:      "t:",
				NegCacheTTL: time.Hour,
			},
			BasicAuth: config.BasicAuth{
				Enabled:  enabled,
				Username: "hook-client",
				Password: secret.New("hook-secret"),
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
	maps.Copy(origAliases, hookAliasLocations)

	origPublic := make(map[string]bool, len(hookPublicAllowed))
	maps.Copy(origPublic, hookPublicAllowed)

	origLocation := customLocation
	hookScopes = make(map[string][]string)
	hookPublicAllowed = make(map[string]bool)
	hookAliasLocations = make(map[string]string)
	customLocation = NewCustomLocation()
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		hookScopes = orig
		hookPublicAllowed = origPublic
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

func setHookPublic(location, method string, public bool) {
	mu.Lock()

	hookPublicAllowed[getHookKey(location, method)] = public
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

func TestHasRequiredScopes_MissingScopesWithoutPublicMarkerDenies(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/foo")

	ok := HasRequiredScopes(ctx, cfg, logger, nil, "/custom/foo", http.MethodGet)
	if ok {
		t.Fatal("expected unmarked hook without scopes to deny access")
	}

	if !ctx.IsAborted() {
		t.Fatal("expected aborted context")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHasRequiredScopes_ExplicitPublicHookAllows(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookTestConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/foo")
	setHookPublic("/custom/foo", http.MethodGet, true)

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

func TestHasRequiredScopes_UnscopedNonPublicHookAllowsValidBackchannelBasicAuth(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookBasicAuthConfig(t, true)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/foo")
	ctx.Request.SetBasicAuth("hook-client", "hook-secret")

	ok := HasRequiredScopes(ctx, cfg, logger, nil, "/custom/foo", http.MethodGet)
	if !ok {
		t.Fatal("expected valid backchannel Basic Auth to allow unscoped non-public hook")
	}

	if ctx.IsAborted() {
		t.Fatal("did not expect aborted context for valid Basic Auth")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if !ctx.GetBool(definitions.CtxBasicAuthValidatedKey) {
		t.Fatal("expected Basic Auth validated context marker")
	}

	if method := ctx.GetString(definitions.CtxAuthMethodKey); method != "basic_auth" {
		t.Fatalf("expected auth method basic_auth, got %q", method)
	}
}

func TestHasRequiredScopes_UnscopedNonPublicHookRejectsInvalidBackchannelBasicAuth(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookBasicAuthConfig(t, true)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/foo")
	ctx.Request.SetBasicAuth("hook-client", "wrong-secret")

	ok := HasRequiredScopes(ctx, cfg, logger, nil, "/custom/foo", http.MethodGet)
	assertHookBasicAuthDenied(t, ctx, rec, ok, "expected invalid backchannel Basic Auth to deny unscoped non-public hook")
}

func TestHasRequiredScopes_UnscopedNonPublicHookRejectsBasicWhenDisabled(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookBasicAuthConfig(t, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/foo")
	ctx.Request.SetBasicAuth("hook-client", "hook-secret")

	ok := HasRequiredScopes(ctx, cfg, logger, nil, "/custom/foo", http.MethodGet)
	assertHookBasicAuthDenied(t, ctx, rec, ok, "expected disabled backchannel Basic Auth to deny unscoped non-public hook")
}

// assertHookBasicAuthDenied verifies the common denial contract for Basic Auth hook attempts.
func assertHookBasicAuthDenied(t *testing.T, ctx *gin.Context, rec *httptest.ResponseRecorder, ok bool, allowMessage string) {
	t.Helper()

	if ok {
		t.Fatal(allowMessage)
	}

	if !ctx.IsAborted() {
		t.Fatal("expected aborted context")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}

	if ctx.GetBool(definitions.CtxBasicAuthValidatedKey) {
		t.Fatal("did not expect Basic Auth validated context marker")
	}
}

func TestHasRequiredScopes_ScopedHookDoesNotBypassScopesWithBasicAuth(t *testing.T) {
	withIsolatedHookRoles(t)
	cfg := setupHookBasicAuthConfig(t, true)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/secure")
	setHookScopes("/custom/secure", http.MethodGet, []string{"scope:a"})
	ctx.Request.SetBasicAuth("hook-client", "hook-secret")

	ok := HasRequiredScopes(ctx, cfg, logger, nil, "/custom/secure", http.MethodGet)
	if ok {
		t.Fatal("expected Basic Auth not to bypass scoped hook requirements")
	}

	if !ctx.IsAborted() {
		t.Fatal("expected aborted context")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}

	if ctx.GetBool(definitions.CtxBasicAuthValidatedKey) {
		t.Fatal("did not expect Basic Auth validated marker for scoped hook")
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
		claims: hookAccessClaims("scope:a scope:b"),
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
		claims: hookAccessClaims("scope:x"),
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
		claims: hookAccessClaims("scope:a"),
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

func TestPreCompileLuaHooks_RegistersExplicitPublicHook(t *testing.T) {
	withIsolatedHookRoles(t)

	scriptPath := writeHookScript(t)
	cfg := &config.FileSettings{
		Lua: &config.LuaSection{
			Hooks: []config.LuaHooks{
				{
					Location:   "public-hook",
					Method:     http.MethodGet,
					ScriptPath: scriptPath,
					Public:     true,
				},
			},
		},
	}

	if err := PreCompileLuaHooks(cfg); err != nil {
		t.Fatalf("PreCompileLuaHooks() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, rec := newHookTestContext(http.MethodGet, "/custom/public-hook")

	ok := HasRequiredScopes(ctx, setupHookTestConfig(t), logger, nil, "public-hook", http.MethodGet)
	if !ok {
		t.Fatal("expected explicit public hook to allow access")
	}

	if ctx.IsAborted() {
		t.Fatal("did not expect aborted context for explicit public hook")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
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
		claims: hookAccessClaims("scope:a"),
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
