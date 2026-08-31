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

//nolint:goconst
package subject

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
	"github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
)

func TestGetBackendServers(t *testing.T) { //nolint:funlen
	tests := []struct {
		name         string
		serversInput []*config.BackendServer
		wantLen      int
	}{
		{
			name:         "NoServers",
			serversInput: []*config.BackendServer{},
			wantLen:      0,
		},
		{
			name: "SingleServer",
			serversInput: []*config.BackendServer{
				{
					Protocol:  "http",
					Host:      "192.168.1.1",
					Port:      8000,
					HAProxyV2: false,
					TLS:       false,
				},
			},
			wantLen: 1,
		},
		{
			name: "MultipleServersIncludingNil",
			serversInput: []*config.BackendServer{
				{
					Protocol:  "http",
					Host:      "192.168.1.1",
					Port:      8000,
					HAProxyV2: false,
					TLS:       false,
				},
				nil,
				{
					Protocol:  "https",
					Host:      "192.168.1.2",
					Port:      443,
					HAProxyV2: true,
					TLS:       true,
				},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lState := lua.NewState()
			defer lState.Close()

			request := &Request{
				BackendServers: tt.serversInput,
			}
			manager := NewBackendManager(context.TODO(), nil, nil, request, nil, nil)
			manager.getBackendServers(lState)

			serverTable := lState.Get(-1).(*lua.LTable)

			if serverTable.Len() != tt.wantLen {
				t.Errorf("Expected length %d but got %d", tt.wantLen, serverTable.Len())
			}
		})
	}
}

func TestSelectBackendServer(t *testing.T) { //nolint:funlen
	tests := []struct {
		name    string
		server  string
		port    int
		expServ string
		expPort int
		wantErr bool
	}{
		{
			name:    "httpServerAndPort",
			server:  "192.168.1.1",
			port:    8000,
			expServ: "192.168.1.1",
			expPort: 8000,
			wantErr: false,
		},
		{
			name:    "httpsServerAndPort",
			server:  "192.168.1.2",
			port:    443,
			expServ: "192.168.1.2",
			expPort: 443,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			var (
				server *string
				port   *int
			)

			request := &Request{
				UsedBackendAddr: server,
				UsedBackendPort: port,
			}
			manager := NewBackendManager(context.TODO(), nil, nil, request, nil, nil)

			L.Push(lua.LString(tt.server))
			L.Push(lua.LNumber(tt.port))

			err := L.CallByParam(lua.P{
				Fn:      L.NewFunction(manager.selectBackendServer),
				NRet:    0,
				Protect: true,
			}, L.Get(-2), L.Get(-1))
			if err != nil {
				if !tt.wantErr {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if request.UsedBackendAddr == nil || request.UsedBackendPort == nil || *request.UsedBackendAddr != tt.expServ || *request.UsedBackendPort != tt.expPort {
					t.Errorf("Expected server %s and port %d but got server %v and port %v", tt.expServ, tt.expPort, request.UsedBackendAddr, request.UsedBackendPort)
				}
			}
		})
	}
}

func TestSelectBackendServerUpdatesExistingPointers(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	initialServer := "10.0.0.1"
	initialPort := 143
	request := &Request{
		UsedBackendAddr: &initialServer,
		UsedBackendPort: &initialPort,
	}
	originalAddrPtr := request.UsedBackendAddr
	originalPortPtr := request.UsedBackendPort

	manager := NewBackendManager(context.TODO(), nil, nil, request, nil, nil)

	err := L.CallByParam(lua.P{
		Fn:      L.NewFunction(manager.selectBackendServer),
		NRet:    0,
		Protect: true,
	}, lua.LString("127.0.0.1"), lua.LNumber(993))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if request.UsedBackendAddr != originalAddrPtr {
		t.Fatalf("expected UsedBackendAddr pointer to remain unchanged")
	}

	if request.UsedBackendPort != originalPortPtr {
		t.Fatalf("expected UsedBackendPort pointer to remain unchanged")
	}

	if *request.UsedBackendAddr != "127.0.0.1" {
		t.Fatalf("expected updated server %q, got %q", "127.0.0.1", *request.UsedBackendAddr)
	}

	if *request.UsedBackendPort != 993 {
		t.Fatalf("expected updated port %d, got %d", 993, *request.UsedBackendPort)
	}
}

func writeSubjectScript(t *testing.T, dir, name, content string) string {
	t.Helper()

	scriptPath := filepath.Join(dir, name)
	if err := os.WriteFile(scriptPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing script %s: %v", scriptPath, err)
	}

	return scriptPath
}

func mustNewLuaSubjectSource(t *testing.T, name, scriptPath string) *LuaSubjectSource {
	t.Helper()

	lf, err := newTestLuaSubjectSource(name, scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua subject source %q: %v", name, err)
	}

	lf.Modes = pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth

	return lf
}

// newTestLuaSubjectSource compiles one test-owned fixture from explicitly read bytes.
func newTestLuaSubjectSource(name string, scriptPath string) (*LuaSubjectSource, error) {
	source, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, err
	}

	prototype, err := lualib.CompileLuaSource(scriptPath, source)
	if err != nil {
		return nil, err
	}

	return &LuaSubjectSource{
		Name: name, CompiledScript: prototype,
		Modes: pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated,
	}, nil
}

func TestPreCompiledLuaSubjectSourcesCachesPlansForModes(t *testing.T) {
	sources := &PreCompiledLuaSubjectSources{
		LuaScripts: []*LuaSubjectSource{
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

func newSubjectTestContext() *gin.Context {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	return ctx
}

func newSubjectTestConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{},
	}
}

func newSubjectTestRequest(addr *string, port *int) *Request {
	return &Request{
		Session:         "guid-test",
		UsedBackendAddr: addr,
		UsedBackendPort: port,
		Context:         lualib.NewContext(),
		CommonRequest:   &lualib.CommonRequest{},
	}
}

// subjectTestPoolKey registers cleanup with the explicit manager that owns the test pool.
func subjectTestPoolKey(t *testing.T, pools *vmpool.Manager, suffix string) vmpool.PoolKey {
	t.Helper()

	key := vmpool.PoolKey("test:subject:" + t.Name() + ":" + suffix)
	t.Cleanup(func() {
		if err := pools.Delete(key); err != nil {
			t.Errorf("delete subject VM pool %q: %v", key, err)
		}
	})

	return key
}

func backendResultSubjectScript(attributeName string, attributeValue string) string {
	return `
local nauthilus_backend = require("nauthilus_backend")
local nauthilus_backend_result = require("nauthilus_backend_result")

function nauthilus_call_subject(request)
    local backend_result = nauthilus_backend_result.new()
    backend_result:attributes({ ["` + attributeName + `"] = "` + attributeValue + `" })
    nauthilus_backend.apply_backend_result(backend_result)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`
}

// callTestLuaSubjectSources executes only the source collection owned by this test request.
func callTestLuaSubjectSources(
	t *testing.T,
	request *Request,
	sources ...*LuaSubjectSource,
) (bool, *lualib.LuaBackendResult, []string) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sourceSet := &PreCompiledLuaSubjectSources{LuaScripts: sources}
	pools := vmpool.NewManager()

	action, backendResult, removeAttributes, err := request.callSubjectLua(
		newSubjectTestContext(),
		newSubjectTestConfig(),
		logger,
		nil,
		sourceSet,
		pools,
		subjectTestPoolKey(t, pools, "sources"),
	)
	if err != nil {
		t.Fatalf("callSubjectLua returned error: %v", err)
	}

	return action, backendResult, removeAttributes
}

// runSubjectDependencyPair executes two Lua subject scripts where the second depends on the first.
func runSubjectDependencyPair(t *testing.T, firstScript string, secondScript string) *Request {
	t.Helper()

	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", firstScript)
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", secondScript)
	first := mustNewLuaSubjectSource(t, "first", firstScriptPath)
	second := mustNewLuaSubjectSource(t, "second", secondScriptPath)
	second.Dependencies = []string{"first"}

	request := newSubjectTestRequest(nil, nil)
	action, _, _ := callTestLuaSubjectSources(t, request, first, second)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	return request
}

func assertSelectedBackend(t *testing.T, request *Request, expectedAddr string, expectedPort int) {
	t.Helper()

	if request.UsedBackendAddr == nil || request.UsedBackendPort == nil {
		t.Fatalf("expected selected backend address/port to be set")
	}

	if *request.UsedBackendAddr != expectedAddr {
		t.Fatalf("expected selected backend address %q, got %q", expectedAddr, *request.UsedBackendAddr)
	}

	if *request.UsedBackendPort != expectedPort {
		t.Fatalf("expected selected backend port %d, got %d", expectedPort, *request.UsedBackendPort)
	}
}

func TestCallSubjectLuaAppliesSingleBackendResultProjection(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := writeSubjectScript(t, scriptDir, "single.lua", backendResultSubjectScript("route_hint", "single"))

	initialAddr := "initial.backend.local"
	initialPort := 25
	request := newSubjectTestRequest(&initialAddr, &initialPort)
	action, backendResult, _ := callTestLuaSubjectSources(
		t,
		request,
		mustNewLuaSubjectSource(t, "single-result", scriptPath),
	)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	if got := backendResult.Attributes["route_hint"]; got != "single" {
		t.Fatalf("backend result route hint = %v, want %q", got, "single")
	}

	assertSelectedBackend(t, request, initialAddr, initialPort)
}

func TestCallSubjectLuaSourceUsesOnlyCapturedSource(t *testing.T) {
	scriptDir := t.TempDir()
	capturedPath := writeSubjectScript(t, scriptDir, "captured.lua", `
function nauthilus_call_subject(_request)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	recorder := &policySubjectResultRecorder{}
	request := newSubjectTestRequest(nil, nil)
	request.ScriptRecorder = recorder
	pools := vmpool.NewManager()

	action, _, _, err := request.CallSubjectLuaSource(
		newSubjectTestContext(),
		newSubjectTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		mustNewLuaSubjectSource(t, "captured", capturedPath),
		pools,
		subjectTestPoolKey(t, pools, "captured"),
	)
	if err != nil {
		t.Fatalf("CallSubjectLuaSource returned error: %v", err)
	}

	if action {
		t.Fatal("captured subject source rejected the request")
	}

	if len(recorder.results) != 1 || recorder.results[0].Name != "captured" {
		t.Fatalf("recorded script results = %#v, want only captured", recorder.results)
	}
}

func TestCallSubjectLuaSourceUsesInjectedTolerateWithoutGlobal(t *testing.T) {
	cfg := newSubjectTestConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	injected := tolerate.NewTolerateWithDeps(cfg, logger, nil, 0)
	injected.SetCustomToleration("192.0.2.52", 30, time.Minute)

	previous := tolerate.GetTolerate()

	tolerate.SetTolerate(nil)
	t.Cleanup(func() { tolerate.SetTolerate(previous) })

	scriptPath := writeSubjectScript(t, t.TempDir(), "captured.lua", `
local brute_force = require("nauthilus_brute_force")

function nauthilus_call_subject(_request)
    local entries, err = brute_force.get_custom_tolerations()
    assert(err == nil)
    assert(#entries == 1)
    assert(entries[1].ip_address == "192.0.2.52")
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	request := newSubjectTestRequest(nil, nil)
	request.Tolerate = injected
	pools := vmpool.NewManager()

	_, _, _, err := request.CallSubjectLuaSource(
		newSubjectTestContext(),
		cfg,
		logger,
		nil,
		mustNewLuaSubjectSource(t, "captured", scriptPath),
		pools,
		subjectTestPoolKey(t, pools, "captured-tolerate"),
	)
	if err != nil {
		t.Fatalf("CallSubjectLuaSource with injected tolerate returned error: %v", err)
	}
}

func TestCallSubjectLuaSourceRejectsEmptyPoolKey(t *testing.T) {
	scriptPath := writeSubjectScript(t, t.TempDir(), "captured.lua", `
function nauthilus_call_subject(_request)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	pools := vmpool.NewManager()

	_, _, _, err := newSubjectTestRequest(nil, nil).CallSubjectLuaSource(
		newSubjectTestContext(),
		newSubjectTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		mustNewLuaSubjectSource(t, "captured", scriptPath),
		pools,
		"",
	)
	if !errors.Is(err, errSubjectSourcePoolKeyMissing) {
		t.Fatalf("CallSubjectLuaSource empty-key error = %v, want %v", err, errSubjectSourcePoolKeyMissing)
	}
}

func TestCallSubjectLuaSourceUsesExactPoolKey(t *testing.T) {
	scriptPath := writeSubjectScript(t, t.TempDir(), "captured.lua", `
function nauthilus_call_subject(_request)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	source := mustNewLuaSubjectSource(t, "captured", scriptPath)
	cfg := newSubjectTestConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pools := vmpool.NewManager()
	blockedKey := subjectTestPoolKey(t, pools, "blocked")
	blockedPool := pools.GetOrCreate(blockedKey, vmpool.PoolOptions{MaxVMs: 1, Config: cfg})

	lease, err := blockedPool.AcquireLease(t.Context())
	if err != nil {
		t.Fatalf("acquire blocking subject VM lease: %v", err)
	}

	t.Cleanup(lease.Release)

	blockedContext := newSubjectTestContext()
	deadlineContext, cancel := context.WithTimeout(blockedContext.Request.Context(), 50*time.Millisecond)
	t.Cleanup(cancel)

	blockedContext.Request = blockedContext.Request.WithContext(deadlineContext)

	_, _, _, err = newSubjectTestRequest(nil, nil).CallSubjectLuaSource(
		blockedContext,
		cfg,
		logger,
		nil,
		source,
		pools,
		blockedKey,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same-key subject call error = %v, want context deadline exceeded", err)
	}

	freeKey := subjectTestPoolKey(t, pools, "free")

	_, _, _, err = newSubjectTestRequest(nil, nil).CallSubjectLuaSource(
		newSubjectTestContext(),
		cfg,
		logger,
		nil,
		source,
		pools,
		freeKey,
	)
	if err != nil {
		t.Fatalf("distinct-key subject call returned error: %v", err)
	}

	if got := pools.GetOrCreate(blockedKey, vmpool.PoolOptions{MaxVMs: 1, Config: cfg}); got != blockedPool {
		t.Fatal("exact subject VM pool key did not reuse its existing pool")
	}

	if got := pools.GetOrCreate(freeKey, vmpool.PoolOptions{MaxVMs: 1, Config: cfg}); got == blockedPool {
		t.Fatal("distinct subject VM pool keys selected the same pool")
	}
}

func TestCallSubjectLuaMergesTwoBackendResultProjections(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", backendResultSubjectScript("first_fact", "first"))
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", backendResultSubjectScript("second_fact", "second"))

	initialAddr := "initial.backend.local"
	initialPort := 25
	request := newSubjectTestRequest(&initialAddr, &initialPort)
	action, backendResult, _ := callTestLuaSubjectSources(
		t,
		request,
		mustNewLuaSubjectSource(t, "first-result", firstScriptPath),
		mustNewLuaSubjectSource(t, "second-result", secondScriptPath),
	)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	if got := backendResult.Attributes["first_fact"]; got != "first" {
		t.Fatalf("first backend result fact = %v, want %q", got, "first")
	}

	if got := backendResult.Attributes["second_fact"]; got != "second" {
		t.Fatalf("second backend result fact = %v, want %q", got, "second")
	}

	assertSelectedBackend(t, request, initialAddr, initialPort)
}

func TestCallSubjectLuaDependencyContextPropagation(t *testing.T) {
	request := runSubjectDependencyPair(t, `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    nauthilus_context.context_set("dependency_value", "ready")
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`, `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    if nauthilus_context.context_get("dependency_value") ~= "ready" then
        return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_FAIL
    end

    nauthilus_context.context_set("dependent_value", "seen")
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	if got := request.Get("dependent_value"); got != "seen" {
		t.Fatalf("expected dependent context value %q, got %v", "seen", got)
	}
}

func TestCallSubjectLuaUsesStaticDependenciesAndRecordsResults(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    nauthilus_context.context_set("policy_dependency_value", "ready")
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    if nauthilus_context.context_get("policy_dependency_value") ~= "ready" then
        return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_FAIL
    end

    nauthilus_context.context_set("policy_dependent_value", "seen")
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	first := mustNewLuaSubjectSource(t, "first", firstScriptPath)
	second := mustNewLuaSubjectSource(t, "second", secondScriptPath)
	second.Dependencies = []string{"first"}

	request := newSubjectTestRequest(nil, nil)
	recorder := &policySubjectResultRecorder{}
	request.ScriptRecorder = recorder
	action, _, _ := callTestLuaSubjectSources(t, request, first, second)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	if got := request.Get("policy_dependent_value"); got != "seen" {
		t.Fatalf("expected dependent context value %q, got %v", "seen", got)
	}

	if len(recorder.results) != 2 {
		t.Fatalf("recorded script results = %#v, want two", recorder.results)
	}
}

type policySubjectResultRecorder struct {
	results []policycollection.ScriptResult
}

func (r *policySubjectResultRecorder) RecordScriptResult(_ context.Context, result policycollection.ScriptResult) {
	r.results = append(r.results, result)
}

func TestCallSubjectLuaIndependentScriptsMergeSharedContextTable(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.first_subject = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    local rt = nauthilus_context.context_get("rt") or {}
    rt.second_subject = true
    nauthilus_context.context_set("rt", rt)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	first := mustNewLuaSubjectSource(t, "first", firstScriptPath)
	second := mustNewLuaSubjectSource(t, "second", secondScriptPath)

	request := newSubjectTestRequest(nil, nil)
	action, _, _ := callTestLuaSubjectSources(t, request, first, second)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	rt, ok := request.Get("rt").(map[any]any)
	if !ok {
		t.Fatalf("expected rt context map, got %T", request.Get("rt"))
	}

	if got := rt["first_subject"]; got != true {
		t.Fatalf("expected first_subject=true, got %v", got)
	}

	if got := rt["second_subject"]; got != true {
		t.Fatalf("expected second_subject=true, got %v", got)
	}
}

func TestCallSubjectLuaRejectsDependencyCycle(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", backendResultSubjectScript("first_fact", "first"))
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", backendResultSubjectScript("second_fact", "second"))
	first := mustNewLuaSubjectSource(t, "first", firstScriptPath)
	second := mustNewLuaSubjectSource(t, "second", secondScriptPath)
	first.Dependencies = []string{"second"}
	second.Dependencies = []string{"first"}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	request := newSubjectTestRequest(nil, nil)
	sources := &PreCompiledLuaSubjectSources{LuaScripts: []*LuaSubjectSource{first, second}}
	pools := vmpool.NewManager()

	_, _, _, err := request.callSubjectLua(
		newSubjectTestContext(),
		newSubjectTestConfig(),
		logger,
		nil,
		sources,
		pools,
		subjectTestPoolKey(t, pools, "cycle"),
	)
	if err == nil {
		t.Fatal("expected dependency cycle error")
	}
}

func TestCallSubjectLuaDependencyBackendSnapshotPropagation(t *testing.T) {
	request := runSubjectDependencyPair(t, `
local nauthilus_backend = require("nauthilus_backend")
local nauthilus_backend_result = require("nauthilus_backend_result")

function nauthilus_call_subject(request)
    local backend_result = nauthilus_backend_result.new()
    backend_result:attributes({ dependency_attribute = "ready" })
    nauthilus_backend.apply_backend_result(backend_result)
    nauthilus_backend.remove_from_backend_result({ "stale_attribute" })

    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`, `
local nauthilus_context = require("nauthilus_context")
local nauthilus_backend = require("nauthilus_backend")

function nauthilus_call_subject(request)
    local backend_result = nauthilus_backend.get_current_backend_result()
    local attributes = backend_result:attributes()
    local removed = nauthilus_backend.get_removed_backend_attributes()

    if attributes.dependency_attribute == "ready" and removed[1] == "stale_attribute" then
        nauthilus_context.context_set("backend_snapshot_seen", "yes")
        return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
    end

    return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_FAIL
end
`)

	if got := request.Get("backend_snapshot_seen"); got != "yes" {
		t.Fatalf("expected backend snapshot marker %q, got %v", "yes", got)
	}
}

func TestCallSubjectLuaEmitsExecutionPhaseSpans(t *testing.T) {
	collector := tracetest.Setup(t)
	scriptDir := t.TempDir()
	scriptPath := writeSubjectScript(t, scriptDir, "instrumented.lua", `
local top_level_marker = "loaded"

function nauthilus_call_subject(request)
    if top_level_marker ~= "loaded" then
        return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_FAIL
    end

    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	request := newSubjectTestRequest(nil, nil)
	_, _, _ = callTestLuaSubjectSources(t, request, mustNewLuaSubjectSource(t, "instrumented_subject", scriptPath))

	spans := collector.Spans()
	attrs := []attribute.KeyValue{
		attribute.String("lua.kind", "subject"),
		attribute.String("lua.script.name", "instrumented_subject"),
	}

	for _, spanName := range []string{
		"lua.script.module_authority",
		"lua.script.load_chunk",
		"lua.script.lookup_entrypoint",
		"lua.script.call",
		"lua.script.decode_result",
	} {
		if _, ok := tracetest.FindByNameAndAttributes(spans, spanName, attrs...); !ok {
			t.Fatalf("missing %s span for instrumented subject source; spans=%d", spanName, len(spans))
		}
	}

	if _, ok := tracetest.FindByNameAndAttributes(
		spans,
		"lua.script.call",
		attribute.String("lua.kind", "subject"),
		attribute.String("lua.script.name", "instrumented_subject"),
		attribute.String("lua.entrypoint", definitions.LuaFnCallSubject),
	); !ok {
		t.Fatal("missing lua.script.call span with subject entrypoint attribute")
	}
}

func TestLoaderModBackendProjectionOmitsTargetSelectionAuthority(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	request := &Request{}

	var result *lualib.LuaBackendResult

	removed := make([]string, 0)
	loader := LoaderModBackendProjectionWithCurrent(
		t.Context(), nil, nil, request, &result, &removed, nil, nil,
	)
	loader(state)

	module, ok := state.Get(-1).(*lua.LTable)
	if !ok {
		t.Fatalf("expected backend projection table, got %v", state.Get(-1).Type())
	}

	for _, name := range []string{
		definitions.LuaFnGetBackendServers,
		definitions.LuaFnSelectBackendServer,
		definitions.LuaFnGetSelectedBackendServer,
		definitions.LuaFnCheckBackendConnection,
	} {
		if value := module.RawGetString(name); value != lua.LNil {
			t.Fatalf("forbidden backend authority %q remains visible as %v", name, value.Type())
		}
	}

	for _, name := range []string{
		definitions.LuaFnGetCurrentBackendResult,
		definitions.LuaFnApplyBackendResult,
		definitions.LuaFnRemoveFromBackendResult,
		definitions.LuaFnGetRemovedBackendAttributes,
	} {
		if value := module.RawGetString(name); value.Type() != lua.LTFunction {
			t.Fatalf("request-local backend projection %q is unavailable", name)
		}
	}
}
