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
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/pipeline"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"
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

	lf, err := NewLuaSubjectSource(name, scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua subject source %q: %v", name, err)
	}

	lf.Modes = pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth

	return lf
}

func withTestLuaSubjectSources(t *testing.T, sources ...*LuaSubjectSource) {
	t.Helper()

	original := LuaSubjectSources
	LuaSubjectSources = &PreCompiledLuaSubjectSources{LuaScripts: sources}

	t.Cleanup(func() {
		LuaSubjectSources = original
	})
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

func selectBackendSubjectScript(address string, port int) string {
	return `
local nauthilus_backend = require("nauthilus_backend")

function nauthilus_call_subject(request)
    nauthilus_backend.select_backend_server("` + address + `", ` + lua.LNumber(port).String() + `)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`
}

func runCallSubjectLua(t *testing.T, request *Request) bool {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	action, _, _, err := request.CallSubjectLua(newSubjectTestContext(), newSubjectTestConfig(), logger, nil)
	if err != nil {
		t.Fatalf("CallSubjectLua returned error: %v", err)
	}

	return action
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

func TestCallSubjectLuaSelectBackendServerDelegatesSingleScript(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := writeSubjectScript(t, scriptDir, "single.lua", selectBackendSubjectScript("single.backend.local", 1143))

	withTestLuaSubjectSources(t, mustNewLuaSubjectSource(t, "single-select", scriptPath))

	initialAddr := "initial.backend.local"
	initialPort := 25
	request := newSubjectTestRequest(&initialAddr, &initialPort)
	action := runCallSubjectLua(t, request)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	assertSelectedBackend(t, request, "single.backend.local", 1143)
}

func TestCallSubjectLuaSelectBackendServerDelegatesTwoScriptsDeterministic(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", selectBackendSubjectScript("first.backend.local", 2001))
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", selectBackendSubjectScript("second.backend.local", 2002))

	withTestLuaSubjectSources(t,
		mustNewLuaSubjectSource(t, "first-select", firstScriptPath),
		mustNewLuaSubjectSource(t, "second-select", secondScriptPath),
	)

	initialAddr := "initial.backend.local"
	initialPort := 25
	request := newSubjectTestRequest(&initialAddr, &initialPort)
	action := runCallSubjectLua(t, request)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	assertSelectedBackend(t, request, "second.backend.local", 2002)
}

func TestCallSubjectLuaDependencyContextPropagation(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    nauthilus_context.context_set("dependency_value", "ready")
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")

function nauthilus_call_subject(request)
    if nauthilus_context.context_get("dependency_value") ~= "ready" then
        return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_FAIL
    end

    nauthilus_context.context_set("dependent_value", "seen")
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	first := mustNewLuaSubjectSource(t, "first", firstScriptPath)
	second := mustNewLuaSubjectSource(t, "second", secondScriptPath)
	second.Dependencies = []string{"first"}

	withTestLuaSubjectSources(t, first, second)

	request := newSubjectTestRequest(nil, nil)
	action := runCallSubjectLua(t, request)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	if got := request.Get("dependent_value"); got != "seen" {
		t.Fatalf("expected dependent context value %q, got %v", "seen", got)
	}
}

func TestCallSubjectLuaUsesPolicyScheduleDependencies(t *testing.T) {
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

	withTestLuaSubjectSources(t, first, second)

	request := newSubjectTestRequest(nil, nil)
	request.ScriptRecorder = &policySubjectScheduleRecorder{
		plan: policycollection.ScriptSchedulePlan{
			Configured: true,
			Schedules: []policycollection.ScriptSchedule{
				{Name: "first"},
				{Name: "second", After: []string{"first"}},
			},
		},
	}
	action := runCallSubjectLua(t, request)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	if got := request.Get("policy_dependent_value"); got != "seen" {
		t.Fatalf("expected policy dependent context value %q, got %v", "seen", got)
	}
}

type policySubjectScheduleRecorder struct {
	plan    policycollection.ScriptSchedulePlan
	results []policycollection.ScriptResult
}

func (r *policySubjectScheduleRecorder) RecordScriptResult(_ context.Context, result policycollection.ScriptResult) {
	r.results = append(r.results, result)
}

func (r *policySubjectScheduleRecorder) ScriptScheduled(kind policycollection.ScriptKind, name string, _ policycollection.AuthState) bool {
	if kind != policycollection.ScriptKindSubject {
		return false
	}

	for _, schedule := range r.plan.Schedules {
		if schedule.Name == name {
			return true
		}
	}

	return false
}

func (r *policySubjectScheduleRecorder) ScriptPlan(kind policycollection.ScriptKind, _ policycollection.AuthState) policycollection.ScriptSchedulePlan {
	if kind != policycollection.ScriptKindSubject {
		return policycollection.ScriptSchedulePlan{}
	}

	return r.plan
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

	withTestLuaSubjectSources(t, first, second)

	request := newSubjectTestRequest(nil, nil)
	action := runCallSubjectLua(t, request)

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
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", selectBackendSubjectScript("first.backend.local", 2001))
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", selectBackendSubjectScript("second.backend.local", 2002))
	first := mustNewLuaSubjectSource(t, "first", firstScriptPath)
	second := mustNewLuaSubjectSource(t, "second", secondScriptPath)
	first.Dependencies = []string{"second"}
	second.Dependencies = []string{"first"}

	withTestLuaSubjectSources(t, first, second)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	request := newSubjectTestRequest(nil, nil)

	_, _, _, err := request.CallSubjectLua(newSubjectTestContext(), newSubjectTestConfig(), logger, nil)
	if err == nil {
		t.Fatal("expected dependency cycle error")
	}
}

func TestCallSubjectLuaDependencyBackendSnapshotPropagation(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeSubjectScript(t, scriptDir, "first.lua", `
local nauthilus_backend = require("nauthilus_backend")
local nauthilus_backend_result = require("nauthilus_backend_result")

function nauthilus_call_subject(request)
    local backend_result = nauthilus_backend_result.new()
    backend_result:attributes({ dependency_attribute = "ready" })
    nauthilus_backend.apply_backend_result(backend_result)
    nauthilus_backend.remove_from_backend_result({ "stale_attribute" })
    nauthilus_backend.select_backend_server("dependency.backend.local", 2525)

    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)
	secondScriptPath := writeSubjectScript(t, scriptDir, "second.lua", `
local nauthilus_context = require("nauthilus_context")
local nauthilus_backend = require("nauthilus_backend")

function nauthilus_call_subject(request)
    local backend_result = nauthilus_backend.get_current_backend_result()
    local attributes = backend_result:attributes()
    local address, port = nauthilus_backend.get_selected_backend_server()
    local removed = nauthilus_backend.get_removed_backend_attributes()

    if attributes.dependency_attribute == "ready" and address == "dependency.backend.local" and port == 2525 and removed[1] == "stale_attribute" then
        nauthilus_context.context_set("backend_snapshot_seen", "yes")
        return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
    end

    return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_FAIL
end
`)
	first := mustNewLuaSubjectSource(t, "first", firstScriptPath)
	second := mustNewLuaSubjectSource(t, "second", secondScriptPath)
	second.Dependencies = []string{"first"}

	withTestLuaSubjectSources(t, first, second)

	request := newSubjectTestRequest(nil, nil)
	action := runCallSubjectLua(t, request)

	if action {
		t.Fatalf("expected action=false, got true")
	}

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

	withTestLuaSubjectSources(t, mustNewLuaSubjectSource(t, "instrumented_subject", scriptPath))

	request := newSubjectTestRequest(nil, nil)
	_ = runCallSubjectLua(t, request)

	spans := collector.Spans()
	attrs := []attribute.KeyValue{
		attribute.String("lua.kind", "subject"),
		attribute.String("lua.script.name", "instrumented_subject"),
	}

	for _, spanName := range []string{
		"lua.script.package_path",
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
