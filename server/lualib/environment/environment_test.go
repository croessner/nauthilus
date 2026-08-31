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
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/pipeline"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	policycollection "github.com/croessner/nauthilus/v4/server/policy/collection"
	"github.com/croessner/nauthilus/v4/server/testing/tracetest"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
)

func writeEnvironmentScript(t *testing.T, dir, name, content string) string {
	t.Helper()

	scriptPath := filepath.Join(dir, name)
	if err := os.WriteFile(scriptPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing script %s: %v", scriptPath, err)
	}

	return scriptPath
}

func mustNewLuaEnvironmentSource(t *testing.T, name, scriptPath string) *LuaEnvironmentSource {
	t.Helper()

	lf, err := newTestLuaEnvironmentSource(name, scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua environment source %q: %v", name, err)
	}

	lf.Modes = pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth

	return lf
}

// newTestLuaEnvironmentSource compiles one test-owned fixture from explicitly read bytes.
func newTestLuaEnvironmentSource(name string, scriptPath string) (*LuaEnvironmentSource, error) {
	source, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, err
	}

	prototype, err := lualib.CompileLuaSource(scriptPath, source)
	if err != nil {
		return nil, err
	}

	return &LuaEnvironmentSource{
		Name: name, CompiledScript: prototype,
		Modes: pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated,
	}, nil
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

func newEnvironmentTestContext() *gin.Context {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	return ctx
}

func newEnvironmentTestConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{},
	}
}

func newEnvironmentTestRequest() *Request {
	return &Request{
		Session:       "guid-test",
		Context:       lualib.NewContext(),
		CommonRequest: &lualib.CommonRequest{},
	}
}

// environmentTestPoolKey registers cleanup for one test-owned exact VM pool.
func environmentTestPoolKey(t *testing.T, manager *vmpool.Manager, suffix string) vmpool.PoolKey {
	t.Helper()

	key := vmpool.PoolKey("test:environment:" + t.Name() + ":" + suffix)
	t.Cleanup(func() {
		if err := manager.Delete(key); err != nil {
			t.Errorf("delete environment VM pool %q: %v", key, err)
		}
	})

	return key
}

// callTestLuaEnvironmentSources executes one test-owned source collection without ambient selection.
func callTestLuaEnvironmentSources(
	t *testing.T,
	request *Request,
	sources ...*LuaEnvironmentSource,
) (triggered bool, skipRemainingEnvironment bool, err error) {
	t.Helper()

	manager := vmpool.NewManager()

	return request.callEnvironmentLua(
		newEnvironmentTestContext(),
		newEnvironmentTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		&PreCompiledLuaEnvironmentSources{LuaScripts: sources},
		manager,
		environmentTestPoolKey(t, manager, "collection"),
	)
}

func TestCallEnvironmentLuaDependencyContextPropagation(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeEnvironmentScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    nauthilus_context.context_set("environment_dependency_value", "ready")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	secondScriptPath := writeEnvironmentScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    if nauthilus_context.context_get("environment_dependency_value") ~= "ready" then
        return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_FAIL
    end

    nauthilus_context.context_set("environment_dependent_value", "seen")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	first := mustNewLuaEnvironmentSource(t, "first", firstScriptPath)
	second := mustNewLuaEnvironmentSource(t, "second", secondScriptPath)
	second.Dependencies = []string{"first"}

	request := newEnvironmentTestRequest()

	triggered, skipRemainingEnvironment, err := callTestLuaEnvironmentSources(t, request, first, second)
	if err != nil {
		t.Fatalf("explicit environment source collection returned error: %v", err)
	}

	if triggered {
		t.Fatal("expected triggered=false")
	}

	if skipRemainingEnvironment {
		t.Fatal("expected skipRemainingEnvironment=false")
	}

	if got := request.Get("environment_dependent_value"); got != "seen" {
		t.Fatalf("expected dependent context value %q, got %v", "seen", got)
	}
}

func TestCallEnvironmentLuaIndependentScriptsMergeSharedContextTable(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeEnvironmentScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.first_environment = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	secondScriptPath := writeEnvironmentScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.second_environment = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	first := mustNewLuaEnvironmentSource(t, "first", firstScriptPath)
	second := mustNewLuaEnvironmentSource(t, "second", secondScriptPath)

	request := newEnvironmentTestRequest()

	triggered, skipRemainingEnvironment, err := callTestLuaEnvironmentSources(t, request, first, second)
	if err != nil {
		t.Fatalf("explicit environment source collection returned error: %v", err)
	}

	if triggered {
		t.Fatal("expected triggered=false")
	}

	if skipRemainingEnvironment {
		t.Fatal("expected skipRemainingEnvironment=false")
	}

	rt, ok := request.Get("rt").(map[any]any)
	if !ok {
		t.Fatalf("expected rt context map, got %T", request.Get("rt"))
	}

	if got := rt["first_environment"]; got != true {
		t.Fatalf("expected first_environment=true, got %v", got)
	}

	if got := rt["second_environment"]; got != true {
		t.Fatalf("expected second_environment=true, got %v", got)
	}
}

func TestCallEnvironmentLuaRejectsDependencyCycle(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeEnvironmentScript(t, scriptDir, "first.lua", `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	secondScriptPath := writeEnvironmentScript(t, scriptDir, "second.lua", `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	first := mustNewLuaEnvironmentSource(t, "first", firstScriptPath)
	second := mustNewLuaEnvironmentSource(t, "second", secondScriptPath)
	first.Dependencies = []string{"second"}
	second.Dependencies = []string{"first"}

	request := newEnvironmentTestRequest()

	_, _, err := callTestLuaEnvironmentSources(t, request, first, second)
	if err == nil {
		t.Fatal("expected dependency cycle error")
	}
}

func TestCallEnvironmentLuaRecordsNoAuthSourceResult(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := writeEnvironmentScript(t, scriptDir, "policy_only.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_environment(request)
    nauthilus_context.context_set("policy_only_environment", "ran")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	luaEnvironment, err := newTestLuaEnvironmentSource("policy_only", scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua environment source: %v", err)
	}

	luaEnvironment.Modes = pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth

	recorder := &policyEnvironmentResultRecorder{}
	request := newEnvironmentTestRequest()
	request.NoAuth = true
	request.ScriptRecorder = recorder
	manager := vmpool.NewManager()

	triggered, skipRemainingEnvironment, err := request.CallEnvironmentLuaSource(
		newEnvironmentTestContext(),
		newEnvironmentTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		luaEnvironment,
		manager,
		environmentTestPoolKey(t, manager, "policy-only"),
	)
	if err != nil {
		t.Fatalf("CallEnvironmentLuaSource returned error: %v", err)
	}

	if triggered {
		t.Fatal("expected triggered=false")
	}

	if skipRemainingEnvironment {
		t.Fatal("expected skipRemainingEnvironment=false")
	}

	if got := request.Get("policy_only_environment"); got != "ran" {
		t.Fatalf("environment source result = %v, want ran", got)
	}

	if len(recorder.results) != 1 || recorder.results[0].Name != "policy_only" {
		t.Fatalf("recorded script results = %#v, want policy_only", recorder.results)
	}
}

func TestCallEnvironmentLuaSourceExecutesCapturedSource(t *testing.T) {
	scriptDir := t.TempDir()
	capturedPath := writeEnvironmentScript(t, scriptDir, "captured.lua", `
function nauthilus_call_environment(_request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	recorder := &policyEnvironmentResultRecorder{}
	request := newEnvironmentTestRequest()
	request.ScriptRecorder = recorder
	manager := vmpool.NewManager()

	triggered, aborted, err := request.CallEnvironmentLuaSource(
		newEnvironmentTestContext(),
		newEnvironmentTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		mustNewLuaEnvironmentSource(t, "captured", capturedPath),
		manager,
		environmentTestPoolKey(t, manager, "captured"),
	)
	if err != nil {
		t.Fatalf("CallEnvironmentLuaSource returned error: %v", err)
	}

	if triggered || aborted {
		t.Fatalf("captured source result triggered=%t aborted=%t, want false/false", triggered, aborted)
	}

	if len(recorder.results) != 1 || recorder.results[0].Name != "captured" {
		t.Fatalf("recorded script results = %#v, want only captured", recorder.results)
	}
}

func TestCallEnvironmentLuaSourceUsesInjectedTolerateWithoutGlobal(t *testing.T) {
	cfg := newEnvironmentTestConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	injected := tolerate.NewTolerateWithDeps(cfg, logger, nil, 0)
	injected.SetCustomToleration("192.0.2.51", 25, time.Minute)

	previous := tolerate.GetTolerate()

	tolerate.SetTolerate(nil)
	t.Cleanup(func() { tolerate.SetTolerate(previous) })

	scriptPath := writeEnvironmentScript(t, t.TempDir(), "captured.lua", `
local brute_force = require("nauthilus_brute_force")

function nauthilus_call_environment(_request)
    local entries, err = brute_force.get_custom_tolerations()
    assert(err == nil)
    assert(#entries == 1)
    assert(entries[1].ip_address == "192.0.2.51")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	request := newEnvironmentTestRequest()
	request.Tolerate = injected
	manager := vmpool.NewManager()

	_, _, err := request.CallEnvironmentLuaSource(
		newEnvironmentTestContext(),
		cfg,
		logger,
		nil,
		mustNewLuaEnvironmentSource(t, "captured", scriptPath),
		manager,
		environmentTestPoolKey(t, manager, "captured-tolerate"),
	)
	if err != nil {
		t.Fatalf("CallEnvironmentLuaSource with injected tolerate returned error: %v", err)
	}
}

func TestCallEnvironmentLuaSourceRejectsEmptyPoolKey(t *testing.T) {
	scriptPath := writeEnvironmentScript(t, t.TempDir(), "captured.lua", `
function nauthilus_call_environment(_request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	_, _, err := newEnvironmentTestRequest().CallEnvironmentLuaSource(
		newEnvironmentTestContext(),
		newEnvironmentTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		mustNewLuaEnvironmentSource(t, "captured", scriptPath),
		vmpool.NewManager(),
		"",
	)
	if !errors.Is(err, errEnvironmentSourcePoolKeyMissing) {
		t.Fatalf("CallEnvironmentLuaSource empty-key error = %v, want %v", err, errEnvironmentSourcePoolKeyMissing)
	}
}

func TestCallEnvironmentLuaSourceUsesExactPoolKey(t *testing.T) {
	scriptPath := writeEnvironmentScript(t, t.TempDir(), "captured.lua", `
function nauthilus_call_environment(_request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	source := mustNewLuaEnvironmentSource(t, "captured", scriptPath)
	cfg := newEnvironmentTestConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := vmpool.NewManager()
	blockedKey := environmentTestPoolKey(t, manager, "blocked")
	blockedPool := manager.GetOrCreate(blockedKey, vmpool.PoolOptions{MaxVMs: 1, Config: cfg})

	lease, err := blockedPool.AcquireLease(t.Context())
	if err != nil {
		t.Fatalf("acquire blocking environment VM lease: %v", err)
	}

	t.Cleanup(lease.Release)

	blockedContext := newEnvironmentTestContext()
	deadlineContext, cancel := context.WithTimeout(blockedContext.Request.Context(), 50*time.Millisecond)
	t.Cleanup(cancel)

	blockedContext.Request = blockedContext.Request.WithContext(deadlineContext)

	_, _, err = newEnvironmentTestRequest().CallEnvironmentLuaSource(
		blockedContext,
		cfg,
		logger,
		nil,
		source,
		manager,
		blockedKey,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same-key environment call error = %v, want context deadline exceeded", err)
	}

	freeKey := environmentTestPoolKey(t, manager, "free")

	_, _, err = newEnvironmentTestRequest().CallEnvironmentLuaSource(
		newEnvironmentTestContext(),
		cfg,
		logger,
		nil,
		source,
		manager,
		freeKey,
	)
	if err != nil {
		t.Fatalf("distinct-key environment call returned error: %v", err)
	}

	if got := manager.GetOrCreate(blockedKey, vmpool.PoolOptions{MaxVMs: 1, Config: cfg}); got != blockedPool {
		t.Fatal("exact environment VM pool key did not reuse its existing pool")
	}

	if got := manager.GetOrCreate(freeKey, vmpool.PoolOptions{MaxVMs: 1, Config: cfg}); got == blockedPool {
		t.Fatal("distinct environment VM pool keys selected the same pool")
	}
}

type policyEnvironmentResultRecorder struct {
	results []policycollection.ScriptResult
}

func (r *policyEnvironmentResultRecorder) RecordScriptResult(_ context.Context, result policycollection.ScriptResult) {
	r.results = append(r.results, result)
}

func TestCallEnvironmentLuaEmitsExecutionPhaseSpans(t *testing.T) {
	collector := tracetest.Setup(t)
	scriptDir := t.TempDir()
	scriptPath := writeEnvironmentScript(t, scriptDir, "instrumented.lua", `
local top_level_marker = "loaded"

function nauthilus_call_environment(request)
    if top_level_marker ~= "loaded" then
        return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_YES, nauthilus_builtin.ENVIRONMENT_RESULT_FAIL
    end

    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	request := newEnvironmentTestRequest()
	ctx := newEnvironmentTestContext()
	cfg := newEnvironmentTestConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := vmpool.NewManager()

	_, _, err := request.CallEnvironmentLuaSource(
		ctx,
		cfg,
		logger,
		nil,
		mustNewLuaEnvironmentSource(t, "instrumented_environment", scriptPath),
		manager,
		environmentTestPoolKey(t, manager, "instrumented"),
	)
	if err != nil {
		t.Fatalf("CallEnvironmentLuaSource returned error: %v", err)
	}

	spans := collector.Spans()
	attrs := []attribute.KeyValue{
		attribute.String("lua.kind", "environment"),
		attribute.String("lua.script.name", "instrumented_environment"),
	}

	for _, spanName := range []string{
		"lua.script.module_authority",
		"lua.script.load_chunk",
		"lua.script.lookup_entrypoint",
		"lua.script.call",
		"lua.script.decode_result",
	} {
		if _, ok := tracetest.FindByNameAndAttributes(spans, spanName, attrs...); !ok {
			t.Fatalf("missing %s span for instrumented environment source; spans=%d", spanName, len(spans))
		}
	}

	if _, ok := tracetest.FindByNameAndAttributes(
		spans,
		"lua.script.call",
		attribute.String("lua.kind", "environment"),
		attribute.String("lua.script.name", "instrumented_environment"),
		attribute.String("lua.entrypoint", definitions.LuaFnCallEnvironment),
	); !ok {
		t.Fatal("missing lua.script.call span with environment entrypoint attribute")
	}
}
