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

func mustNewLuaFeature(t *testing.T, name, scriptPath string) *LuaFeature {
	t.Helper()

	lf, err := NewLuaFeature(name, scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua feature %q: %v", name, err)
	}

	lf.Modes = pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth

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

func TestPreCompiledLuaFeaturesCachesPlansForModes(t *testing.T) {
	features := &PreCompiledLuaFeatures{
		LuaScripts: []*LuaFeature{
			{Name: "context", Modes: pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated},
			{Name: "monitor", Dependencies: []string{"context"}, Modes: pipeline.ModeAuthenticated},
		},
	}

	if err := features.RebuildPlans(); err != nil {
		t.Fatalf("RebuildPlans returned error: %v", err)
	}

	plan, cached, err := features.planForMode(pipeline.ModeAuthenticated)
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
	second.Dependencies = []string{"first"}

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

func TestCallFeatureLuaIndependentScriptsMergeSharedContextTable(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeFeatureScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_feature(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.first_feature = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
`)
	secondScriptPath := writeFeatureScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_feature(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.second_feature = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
`)
	first := mustNewLuaFeature(t, "first", firstScriptPath)
	second := mustNewLuaFeature(t, "second", secondScriptPath)

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
	first.Dependencies = []string{"second"}
	second.Dependencies = []string{"first"}

	withTestLuaFeatures(t, first, second)

	request := newFeatureTestRequest()
	_, _, err := request.CallFeatureLua(newFeatureTestContext(), newFeatureTestConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err == nil {
		t.Fatal("expected dependency cycle error")
	}
}

func TestCallFeatureLuaUsesPolicyScheduleForNoAuthControl(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := writeFeatureScript(t, scriptDir, "policy_only.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_feature(request)
    nauthilus_context.context_set("policy_only_feature", "ran")
    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
`)

	luaFeature, err := NewLuaFeature("policy_only", scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua feature: %v", err)
	}

	withTestLuaFeatures(t, luaFeature)

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

	if got := request.Get("policy_only_feature"); got != "ran" {
		t.Fatalf("policy scheduled feature result = %v, want ran", got)
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
	if kind != policycollection.ScriptKindControl {
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
	if kind != policycollection.ScriptKindControl {
		return policycollection.ScriptSchedulePlan{}
	}

	return r.plan
}
