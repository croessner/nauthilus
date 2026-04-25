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

package feature

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/gin-gonic/gin"
)

func writeFeatureScript(t *testing.T, dir, name, content string) string {
	t.Helper()

	scriptPath := filepath.Join(dir, name)
	if err := os.WriteFile(scriptPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing script %s: %v", scriptPath, err)
	}

	return scriptPath
}

func mustNewLuaFeature(t *testing.T, name, scriptPath string) *LuaFeature {
	t.Helper()

	lf, err := NewLuaFeature(name, scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua feature %q: %v", name, err)
	}

	lf.WhenAuthenticated = true
	lf.WhenUnauthenticated = true
	lf.WhenNoAuth = true

	return lf
}

func withTestLuaFeatures(t *testing.T, features ...*LuaFeature) {
	t.Helper()

	original := LuaFeatures
	LuaFeatures = &PreCompiledLuaFeatures{LuaScripts: features}

	t.Cleanup(func() {
		LuaFeatures = original
	})
}

func newFeatureTestContext() *gin.Context {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	return ctx
}

func newFeatureTestConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{},
	}
}

func newFeatureTestRequest() *Request {
	return &Request{
		Session:       "guid-test",
		Context:       lualib.NewContext(),
		CommonRequest: &lualib.CommonRequest{},
	}
}

func TestCallFeatureLuaDependencyContextPropagation(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeFeatureScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_feature(request)
    nauthilus_context.context_set("feature_dependency_value", "ready")
    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
`)
	secondScriptPath := writeFeatureScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_feature(request)
    if nauthilus_context.context_get("feature_dependency_value") ~= "ready" then
        return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_FAIL
    end

    nauthilus_context.context_set("feature_dependent_value", "seen")
    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
`)
	first := mustNewLuaFeature(t, "first", firstScriptPath)
	second := mustNewLuaFeature(t, "second", secondScriptPath)
	second.DependsOn = []string{"first"}

	withTestLuaFeatures(t, first, second)

	request := newFeatureTestRequest()
	triggered, abortFeatures, err := request.CallFeatureLua(newFeatureTestContext(), newFeatureTestConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("CallFeatureLua returned error: %v", err)
	}

	if triggered {
		t.Fatal("expected triggered=false")
	}

	if abortFeatures {
		t.Fatal("expected abortFeatures=false")
	}

	if got := request.Get("feature_dependent_value"); got != "seen" {
		t.Fatalf("expected dependent context value %q, got %v", "seen", got)
	}
}

func TestCallFeatureLuaRejectsDependencyCycle(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeFeatureScript(t, scriptDir, "first.lua", `
function nauthilus_call_feature(request)
    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
`)
	secondScriptPath := writeFeatureScript(t, scriptDir, "second.lua", `
function nauthilus_call_feature(request)
    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
`)
	first := mustNewLuaFeature(t, "first", firstScriptPath)
	second := mustNewLuaFeature(t, "second", secondScriptPath)
	first.DependsOn = []string{"second"}
	second.DependsOn = []string{"first"}

	withTestLuaFeatures(t, first, second)

	request := newFeatureTestRequest()
	_, _, err := request.CallFeatureLua(newFeatureTestContext(), newFeatureTestConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err == nil {
		t.Fatal("expected dependency cycle error")
	}
}
