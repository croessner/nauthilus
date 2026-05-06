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

package environment

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/pipeline"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
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

func mustNewLuaEnvironmentSource(t *testing.T, name, scriptPath string) *LuaEnvironmentSource {
	t.Helper()

	lf, err := NewLuaEnvironmentSource(name, scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua environment source %q: %v", name, err)
	}

	lf.Modes = pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth

	return lf
}

func withTestLuaEnvironmentSources(t *testing.T, sources ...*LuaEnvironmentSource) {
	t.Helper()

	original := LuaEnvironmentSources
	LuaEnvironmentSources = &PreCompiledLuaEnvironmentSources{LuaScripts: sources}

	t.Cleanup(func() {
		LuaEnvironmentSources = original
	})
}

func TestPreCompiledLuaEnvironmentSourcesCachesPlansForModes(t *testing.T) {
	sources := &PreCompiledLuaEnvironmentSources{
		LuaScripts: []*LuaEnvironmentSource{
			{Name: "context", Modes: pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated},
			{Name: "monitor", Dependencies: []string{"context"}, Modes: pipeline.ModeAuthenticated},
		},
	}

	if err := sources.RebuildPlans(); err != nil {
		t.Fatalf("RebuildPlans returned error: %v", err)
	}

	plan, cached, err := sources.planForMode(pipeline.ModeAuthenticated)
	if err != nil {
		t.Fatalf("planForMode returned error: %v", err)
	}

	if !cached {
		t.Fatal("expected cached plan")
	}

	if len(plan.Levels) != 2 {
		t.Fatalf("expected 2 dependency levels, got %d", len(plan.Levels))
	}

	if got := pipeline.PlannedNodeCount(plan); got != 2 {
		t.Fatalf("expected 2 planned scripts, got %d", got)
	}
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

func TestCallEnvironmentLuaDependencyContextPropagation(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeFeatureScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    nauthilus_context.context_set("feature_dependency_value", "ready")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	secondScriptPath := writeFeatureScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    if nauthilus_context.context_get("feature_dependency_value") ~= "ready" then
        return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_FAIL
    end

    nauthilus_context.context_set("feature_dependent_value", "seen")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	first := mustNewLuaEnvironmentSource(t, "first", firstScriptPath)
	second := mustNewLuaEnvironmentSource(t, "second", secondScriptPath)
	second.Dependencies = []string{"first"}

	withTestLuaEnvironmentSources(t, first, second)

	request := newFeatureTestRequest()
	triggered, abortFeatures, err := request.CallEnvironmentLua(newFeatureTestContext(), newFeatureTestConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("CallEnvironmentLua returned error: %v", err)
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

func TestCallEnvironmentLuaIndependentScriptsMergeSharedContextTable(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeFeatureScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.first_feature = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	secondScriptPath := writeFeatureScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.second_feature = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	first := mustNewLuaEnvironmentSource(t, "first", firstScriptPath)
	second := mustNewLuaEnvironmentSource(t, "second", secondScriptPath)

	withTestLuaEnvironmentSources(t, first, second)

	request := newFeatureTestRequest()
	triggered, abortFeatures, err := request.CallEnvironmentLua(newFeatureTestContext(), newFeatureTestConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("CallEnvironmentLua returned error: %v", err)
	}

	if triggered {
		t.Fatal("expected triggered=false")
	}

	if abortFeatures {
		t.Fatal("expected abortFeatures=false")
	}

	rt, ok := request.Get("rt").(map[any]any)
	if !ok {
		t.Fatalf("expected rt context map, got %T", request.Get("rt"))
	}

	if got := rt["first_feature"]; got != true {
		t.Fatalf("expected first_feature=true, got %v", got)
	}

	if got := rt["second_feature"]; got != true {
		t.Fatalf("expected second_feature=true, got %v", got)
	}
}

func TestCallEnvironmentLuaRejectsDependencyCycle(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeFeatureScript(t, scriptDir, "first.lua", `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	secondScriptPath := writeFeatureScript(t, scriptDir, "second.lua", `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	first := mustNewLuaEnvironmentSource(t, "first", firstScriptPath)
	second := mustNewLuaEnvironmentSource(t, "second", secondScriptPath)
	first.Dependencies = []string{"second"}
	second.Dependencies = []string{"first"}

	withTestLuaEnvironmentSources(t, first, second)

	request := newFeatureTestRequest()
	_, _, err := request.CallEnvironmentLua(newFeatureTestContext(), newFeatureTestConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err == nil {
		t.Fatal("expected dependency cycle error")
	}
}

func TestCallEnvironmentLuaUsesPolicyScheduleForNoAuthControl(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := writeFeatureScript(t, scriptDir, "policy_only.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    nauthilus_context.context_set("policy_only_feature", "ran")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	luaFeature, err := NewLuaEnvironmentSource("policy_only", scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua environment source: %v", err)
	}

	withTestLuaEnvironmentSources(t, luaFeature)

	recorder := &policyFeatureScheduleRecorder{
		plan: policycollection.ScriptSchedulePlan{
			Configured: true,
			Schedules: []policycollection.ScriptSchedule{
				{Name: "policy_only"},
			},
		},
	}
	request := newFeatureTestRequest()
	request.NoAuth = true
	request.ScriptRecorder = recorder

	triggered, abortFeatures, err := request.CallEnvironmentLua(newFeatureTestContext(), newFeatureTestConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("CallEnvironmentLua returned error: %v", err)
	}

	if triggered {
		t.Fatal("expected triggered=false")
	}

	if abortFeatures {
		t.Fatal("expected abortFeatures=false")
	}

	if got := request.Get("policy_only_feature"); got != "ran" {
		t.Fatalf("policy scheduled environment source result = %v, want ran", got)
	}

	if len(recorder.results) != 1 || recorder.results[0].Name != "policy_only" {
		t.Fatalf("recorded script results = %#v, want policy_only", recorder.results)
	}
}

type policyFeatureScheduleRecorder struct {
	plan    policycollection.ScriptSchedulePlan
	results []policycollection.ScriptResult
}

func (r *policyFeatureScheduleRecorder) RecordScriptResult(_ context.Context, result policycollection.ScriptResult) {
	r.results = append(r.results, result)
}

func (r *policyFeatureScheduleRecorder) ScriptScheduled(kind policycollection.ScriptKind, name string, _ policycollection.AuthState) bool {
	if kind != policycollection.ScriptKindEnvironment {
		return false
	}

	for _, schedule := range r.plan.Schedules {
		if schedule.Name == name {
			return true
		}
	}

	return false
}

func (r *policyFeatureScheduleRecorder) ScriptPlan(kind policycollection.ScriptKind, _ policycollection.AuthState) policycollection.ScriptSchedulePlan {
	if kind != policycollection.ScriptKindEnvironment {
		return policycollection.ScriptSchedulePlan{}
	}

	return r.plan
}
