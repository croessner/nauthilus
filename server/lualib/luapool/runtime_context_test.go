// Copyright (C) 2026 Christian Rößner
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

package luapool

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

type runtimeContextTestKey string

// cachedModuleBindingCase describes one cached request-bound module reset scenario.
type cachedModuleBindingCase struct {
	name            string
	bindingKey      string
	bind            func(*testing.T, *lua.LState)
	loadModule      string
	failClosedCheck string
}

const runtimeContextTestRequestIDKey runtimeContextTestKey = "request_id"

func newRuntimeContextTestState(t *testing.T) *lua.LState {
	t.Helper()

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	L := NewLuaState(nil, cfg)

	t.Cleanup(L.Close)

	return L
}

func bindRuntimeTestContext(t *testing.T, L *lua.LState, luaCtx *lualib.Context) {
	t.Helper()

	bindRuntimeTestModule(t, L, lualib.LoaderModContext(luaCtx), definitions.LuaModContext, "context")
}

func bindRuntimeTestHTTPRequest(t *testing.T, L *lua.LState, req *http.Request) {
	t.Helper()

	bindRuntimeTestModule(t, L, lualib.LoaderModHTTP(lualib.NewHTTPMetaFromRequest(req)), definitions.LuaModHTTPRequest, "http request")
}

func bindRuntimeTestHTTPResponse(t *testing.T, L *lua.LState, ginCtx *gin.Context) {
	t.Helper()

	bindRuntimeTestModule(t, L, lualib.LoaderModHTTPResponse(ginCtx), definitions.LuaModHTTPResponse, "http response")
}

// bindRuntimeTestModule loads a request-bound module and exposes it through the request environment.
func bindRuntimeTestModule(t *testing.T, L *lua.LState, loader lua.LGFunction, moduleName string, label string) {
	t.Helper()

	if loader == nil {
		t.Fatalf("expected %s loader", label)
	}

	_ = loader(L)

	mod, ok := L.Get(-1).(*lua.LTable)
	if !ok {
		t.Fatalf("expected %s module table, got %T", label, L.Get(-1))
	}

	L.Pop(1)
	BindModuleIntoReq(L, moduleName, mod)
}

func bindRuntimeTestRuntimeModule(ctx context.Context, t *testing.T, L *lua.LState) {
	t.Helper()

	mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get_value": func(L *lua.LState) int {
			currentCtx := lualib.RequireRuntimeContext(L, "runtime_helper")
			value, _ := currentCtx.Value(runtimeContextTestRequestIDKey).(string)

			L.Push(lua.LString(value))

			return 1
		},
	})

	lualib.BindRequestRuntimeContext(ctx, L, mod)
	BindModuleIntoReq(L, "runtime_helper", mod)
}

func TestContextModuleFailsClosedWithoutRequestBinding(t *testing.T) {
	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)

	if err := L.DoString(`
		local ctx = require("nauthilus_context")
		ctx.context_set("request_id", "first")
	`); err == nil {
		t.Fatal("expected nauthilus_context to fail without request binding")
	}
}

func TestRuntimeModuleFailsClosedWithoutRequestBinding(t *testing.T) {
	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)
	bindRuntimeTestRuntimeModule(context.WithValue(context.Background(), runtimeContextTestRequestIDKey, "first"), t, L)

	ResetLuaState(L)
	PrepareRequestEnv(L)

	if err := L.DoString(`
		local helper = require("runtime_helper")
		helper.get_value()
	`); err == nil {
		t.Fatal("expected runtime_helper to fail without request binding")
	}
}

func TestResetLuaStateScrubsOldRequestEnvironmentBindings(t *testing.T) {
	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)

	bindRuntimeTestContext(t, L, lualib.NewContext())

	if err := L.DoString(`
		package.preload["request_env_holder"] = function()
			return {
				req = __NAUTH_REQ_ENV,
			}
		end

		local holder = require("request_env_holder")
		if rawget(holder.req, "__NAUTH_REQ_CONTEXT") == nil then
			error("missing request context binding before reset")
		end
		if rawget(holder.req, "__NAUTH_REQ_MODULE_TABLES") == nil then
			error("missing request module tracker before reset")
		end
	`); err != nil {
		t.Fatalf("failed to capture request environment before reset: %v", err)
	}

	ResetLuaState(L)

	if err := L.DoString(`
		local holder = require("request_env_holder")
		if rawget(holder.req, "__NAUTH_REQ_CONTEXT") ~= nil then
			error("stale request context binding was not scrubbed")
		end
		if rawget(holder.req, "__NAUTH_REQ_MODULE_TABLES") ~= nil then
			error("stale request module tracker was not scrubbed")
		end
	`); err != nil {
		t.Fatalf("expected old request environment bindings to be scrubbed: %v", err)
	}
}

func TestResetLuaStateScrubsCachedModuleBindings(t *testing.T) {
	for _, tt := range cachedModuleBindingCases() {
		t.Run(tt.name, func(t *testing.T) {
			assertCachedModuleBindingReset(t, tt)
		})
	}
}

// cachedModuleBindingCases returns cached module reset scenarios.
func cachedModuleBindingCases() []cachedModuleBindingCase {
	return []cachedModuleBindingCase{
		cachedContextModuleBindingCase(),
		cachedRuntimeModuleBindingCase(),
	}
}

// cachedContextModuleBindingCase returns the context module reset scenario.
func cachedContextModuleBindingCase() cachedModuleBindingCase {
	return cachedModuleBindingCase{
		name:       "context_module",
		bindingKey: "__NAUTH_REQ_CONTEXT",
		bind: func(t *testing.T, L *lua.LState) {
			t.Helper()
			bindRuntimeTestContext(t, L, lualib.NewContext())
		},
		loadModule: `
			package.preload["module_holder"] = function()
				return {
					module = require("nauthilus_context"),
				}
			end
		`,
		failClosedCheck: `
			local ok = pcall(function()
				holder.module.context_get("request_id")
			end)
			if ok then
				error("expected cached context module to fail closed without request binding")
			end
		`,
	}
}

// cachedRuntimeModuleBindingCase returns the runtime module reset scenario.
func cachedRuntimeModuleBindingCase() cachedModuleBindingCase {
	return cachedModuleBindingCase{
		name:       "runtime_module",
		bindingKey: "__NAUTH_REQ_RUNTIME_CONTEXT",
		bind: func(t *testing.T, L *lua.LState) {
			t.Helper()
			bindRuntimeTestRuntimeModule(context.WithValue(t.Context(), runtimeContextTestRequestIDKey, "first"), t, L)
		},
		loadModule: `
			package.preload["module_holder"] = function()
				return {
					module = require("runtime_helper"),
				}
			end
		`,
		failClosedCheck: `
			local ok = pcall(function()
				holder.module.get_value()
			end)
			if ok then
				error("expected cached runtime module to fail closed without request binding")
			end
		`,
	}
}

// assertCachedModuleBindingReset verifies one cached module reset scenario.
func assertCachedModuleBindingReset(t *testing.T, tt cachedModuleBindingCase) {
	t.Helper()

	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)
	tt.bind(t, L)

	if err := L.DoString(cachedModuleBindingBeforeResetScript(tt.loadModule, tt.bindingKey)); err != nil {
		t.Fatalf("failed to cache request-bound module before reset: %v", err)
	}

	ResetLuaState(L)

	if err := L.DoString(cachedModuleBindingAfterResetScript(tt.bindingKey, tt.failClosedCheck)); err != nil {
		t.Fatalf("expected cached module binding to be scrubbed on reset: %v", err)
	}
}

// cachedModuleBindingBeforeResetScript returns the pre-reset Lua assertion script.
func cachedModuleBindingBeforeResetScript(loadModule string, bindingKey string) string {
	return fmt.Sprintf(`
		%s

		local holder = require("module_holder")
		if rawget(holder.module, %q) == nil then
			error("missing request binding before reset")
		end
	`, loadModule, bindingKey)
}

// cachedModuleBindingAfterResetScript returns the post-reset Lua assertion script.
func cachedModuleBindingAfterResetScript(bindingKey string, failClosedCheck string) string {
	return fmt.Sprintf(`
		local holder = require("module_holder")
		if rawget(holder.module, %q) ~= nil then
			error("stale request binding was not scrubbed")
		end

		%s
	`, bindingKey, failClosedCheck)
}

func TestCachedContextModuleUsesCurrentRequestContextAfterReset(t *testing.T) {
	runCachedContextAfterResetTest(t, "request_id", "first", "second", `
		package.preload["ctx_holder"] = function()
			return {
				ctx = require("nauthilus_context"),
			}
		end

		local holder = require("ctx_holder")
		holder.ctx.context_set("request_id", "first")
	`, `
		local holder = require("ctx_holder")
		holder.ctx.context_set("request_id", "second")
	`)
}

func TestCachedLuaModuleUsesCurrentRequestContextAfterReset(t *testing.T) {
	runCachedContextAfterResetTest(t, "customer_id", "alpha", "beta", `
		package.preload["common"] = function()
			local common = {}
			local ctx = require("nauthilus_context")

			function common.store(key, value)
				ctx.context_set(key, value)
			end

			function common.load(key)
				return ctx.context_get(key)
			end

			return common
		end

		local common = require("common")
		common.store("customer_id", "alpha")
	`, `
		local common = require("common")
		common.store("customer_id", "beta")

		local value = common.load("customer_id")
		if value ~= "beta" then
			error("unexpected context value: " .. tostring(value))
		end
	`)
}

// runCachedContextAfterResetTest verifies that cached modules use the active request context after reset.
func runCachedContextAfterResetTest(t *testing.T, key string, firstValue string, secondValue string, firstScript string, secondScript string) {
	t.Helper()

	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)

	firstContext := lualib.NewContext()
	bindRuntimeTestContext(t, L, firstContext)

	if err := L.DoString(firstScript); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	if got := firstContext.Get(key); got != firstValue {
		t.Fatalf("expected first context to contain %s, got %#v", firstValue, got)
	}

	ResetLuaState(L)
	PrepareRequestEnv(L)

	secondContext := lualib.NewContext()
	bindRuntimeTestContext(t, L, secondContext)

	if err := L.DoString(secondScript); err != nil {
		t.Fatalf("second request failed: %v", err)
	}

	if got := firstContext.Get(key); got != firstValue {
		t.Fatalf("expected first context to remain %s, got %#v", firstValue, got)
	}

	if got := secondContext.Get(key); got != secondValue {
		t.Fatalf("expected second context to contain %s, got %#v", secondValue, got)
	}
}

func TestCachedHTTPRequestModuleUsesCurrentRequestDataAfterReset(t *testing.T) {
	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)

	firstRequest := httptest.NewRequest(http.MethodGet, "/first?customer=alpha", nil)
	firstRequest.Header.Set("X-Request-Id", "first")
	bindRuntimeTestHTTPRequest(t, L, firstRequest)

	if err := L.DoString(`
		package.preload["http_holder"] = function()
			return {
				http = require("nauthilus_http_request"),
			}
		end

		local holder = require("http_holder")
		local header = holder.http.get_http_request_header("x-request-id")
		if header[1] ~= "first" then
			error("unexpected first header: " .. tostring(header[1]))
		end
		if holder.http.get_http_query_param("customer") ~= "alpha" then
			error("unexpected first query param")
		end
	`); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	ResetLuaState(L)
	PrepareRequestEnv(L)

	secondRequest := httptest.NewRequest(http.MethodGet, "/second?customer=beta", nil)
	secondRequest.Header.Set("X-Request-Id", "second")
	bindRuntimeTestHTTPRequest(t, L, secondRequest)

	if err := L.DoString(`
		local holder = require("http_holder")
		local header = holder.http.get_http_request_header("x-request-id")
		if header[1] ~= "second" then
			error("unexpected second header: " .. tostring(header[1]))
		end
		if holder.http.get_http_query_param("customer") ~= "beta" then
			error("unexpected second query param")
		end
	`); err != nil {
		t.Fatalf("second request failed: %v", err)
	}
}

func TestCachedHTTPResponseModuleUsesCurrentRequestContextAfterReset(t *testing.T) {
	gin.SetMode(gin.TestMode)

	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)

	firstRecorder := httptest.NewRecorder()
	firstGinCtx, _ := gin.CreateTestContext(firstRecorder)
	firstGinCtx.Request = httptest.NewRequest(http.MethodGet, "/first", nil)
	bindRuntimeTestHTTPResponse(t, L, firstGinCtx)

	if err := L.DoString(`
		package.preload["response_holder"] = function()
			return {
				response = require("nauthilus_http_response"),
			}
		end

		local holder = require("response_holder")
		holder.response.set_http_response_header("X-Request-Id", "first")
		if holder.response.STATUS_OK ~= 200 then
			error("missing response constants")
		end
	`); err != nil {
		t.Fatalf("first response failed: %v", err)
	}

	if got := firstRecorder.Header().Get("X-Request-Id"); got != "first" {
		t.Fatalf("expected first recorder header to be first, got %q", got)
	}

	ResetLuaState(L)
	PrepareRequestEnv(L)

	secondRecorder := httptest.NewRecorder()
	secondGinCtx, _ := gin.CreateTestContext(secondRecorder)
	secondGinCtx.Request = httptest.NewRequest(http.MethodGet, "/second", nil)
	bindRuntimeTestHTTPResponse(t, L, secondGinCtx)

	if err := L.DoString(`
		local holder = require("response_holder")
		holder.response.set_http_response_header("X-Request-Id", "second")
	`); err != nil {
		t.Fatalf("second response failed: %v", err)
	}

	if got := firstRecorder.Header().Get("X-Request-Id"); got != "first" {
		t.Fatalf("expected first recorder header to remain first, got %q", got)
	}

	if got := secondRecorder.Header().Get("X-Request-Id"); got != "second" {
		t.Fatalf("expected second recorder header to be second, got %q", got)
	}
}

func TestCachedRuntimeContextModuleUsesCurrentRequestContextAfterReset(t *testing.T) {
	L := newRuntimeContextTestState(t)
	PrepareRequestEnv(L)

	firstRuntimeContext := context.WithValue(context.Background(), runtimeContextTestRequestIDKey, "first")
	bindRuntimeTestRuntimeModule(firstRuntimeContext, t, L)

	if err := L.DoString(`
		package.preload["runtime_holder"] = function()
			return {
				runtime = require("runtime_helper"),
			}
		end

		local holder = require("runtime_holder")
		if holder.runtime.get_value() ~= "first" then
			error("unexpected first runtime value")
		end
	`); err != nil {
		t.Fatalf("first runtime request failed: %v", err)
	}

	ResetLuaState(L)
	PrepareRequestEnv(L)

	secondRuntimeContext := context.WithValue(context.Background(), runtimeContextTestRequestIDKey, "second")
	bindRuntimeTestRuntimeModule(secondRuntimeContext, t, L)

	if err := L.DoString(`
		local holder = require("runtime_holder")
		if holder.runtime.get_value() ~= "second" then
			error("unexpected second runtime value")
		end
	`); err != nil {
		t.Fatalf("second runtime request failed: %v", err)
	}
}
