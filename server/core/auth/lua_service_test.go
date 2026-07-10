// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	"github.com/croessner/nauthilus/v3/server/lualib/subject"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/testing/oteltest"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

func TestDefaultLuaSubject_OverridesAccountField(t *testing.T) { //nolint:funlen
	gin.SetMode(gin.TestMode)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	scriptPath := filepath.Clean(filepath.Join(wd, "..", "..", "lualib", "subject", "testdata", "account_field.lua"))

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nt:",
			},
		},
		Lua: &config.LuaSection{
			SubjectSources: []config.LuaSubjectSource{
				{
					Name:       "account_field",
					ScriptPath: scriptPath,
				},
			},
		},
	}

	envCfg := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(envCfg)
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(envCfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	if err := subject.PreCompileLuaSubjectSources(config.GetFile()); err != nil {
		t.Fatalf("PreCompileLuaSubjectSources failed: %v", err)
	}

	redisDB, _ := redismock.NewClientMock()
	rediscli.NewTestClient(redisDB)

	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    config.GetFile(),
		Logger: log.GetLogger(),
		Redis:  rediscli.GetClient(),
	}).(*core.AuthState)

	auth.Runtime.GUID = "guid-1"
	auth.Runtime.StartTime = time.Now()
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Username = "user@example.com"
	auth.Request.Password = secret.New("secret")
	auth.Request.ClientIP = "127.0.0.1"
	auth.Runtime.AccountField = "rnsMSDovecotUser"
	auth.ReplaceAllAttributes(map[string][]any{
		"rnsMSDovecotUser": {"user@example.com"},
	})

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	result := (DefaultLuaSubject{}).Analyze(ctx, auth.View(), &core.PassDBResult{})
	if result != definitions.AuthResultFail {
		t.Fatalf("expected AuthResultFail, got %v", result)
	}

	attrs, ok := auth.GetAttribute("Account-Field")
	if !ok || len(attrs) == 0 {
		t.Fatalf("expected Account-Field attribute to be set")
	}

	value, ok := attrs[definitions.LDAPSingleValue].(string)
	if !ok {
		t.Fatalf("expected Account-Field attribute to be string")
	}

	if value != definitions.MetaUserAccount {
		t.Fatalf("expected Account-Field to be %q, got %q", definitions.MetaUserAccount, value)
	}
}

func TestDefaultLuaSubject_MergesGroupsFromBackendResult(t *testing.T) {
	auth, ctx := newLuaSubjectGroupMergeTestAuth(t)
	passDBResult := &core.PassDBResult{}

	result := (DefaultLuaSubject{}).Analyze(ctx, auth.View(), passDBResult)
	if result != definitions.AuthResultFail {
		t.Fatalf("expected AuthResultFail, got %v", result)
	}

	assertLuaSubjectMergedGroups(t, auth, passDBResult)
}

// newLuaSubjectGroupMergeTestAuth prepares AuthState for Lua subject group merge tests.
func newLuaSubjectGroupMergeTestAuth(t *testing.T) (*core.AuthState, *gin.Context) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	prepareLuaSubjectGroupMergeConfig(t)

	redisDB, _ := redismock.NewClientMock()
	rediscli.NewTestClient(redisDB)

	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    config.GetFile(),
		Logger: log.GetLogger(),
		Redis:  rediscli.GetClient(),
	}).(*core.AuthState)
	auth.Runtime.GUID = "guid-2"
	auth.Runtime.StartTime = time.Now()
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Username = "user@example.com"
	auth.Request.Password = secret.New("secret")
	auth.Request.ClientIP = "127.0.0.1"
	auth.SetResolvedGroups([]string{"Existing"}, nil)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	return auth, ctx
}

// prepareLuaSubjectGroupMergeConfig configures Lua subject source fixtures.
func prepareLuaSubjectGroupMergeConfig(t *testing.T) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	scriptPath := filepath.Clean(filepath.Join(wd, "..", "..", "lualib", "subject", "testdata", "groups_apply.lua"))

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nt:",
			},
		},
		Lua: &config.LuaSection{
			SubjectSources: []config.LuaSubjectSource{
				{
					Name:       "groups_apply",
					ScriptPath: scriptPath,
				},
			},
		},
	}

	envCfg := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(envCfg)
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(envCfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	if err := subject.PreCompileLuaSubjectSources(config.GetFile()); err != nil {
		t.Fatalf("PreCompileLuaSubjectSources failed: %v", err)
	}
}

// assertLuaSubjectMergedGroups verifies merged auth and passDB group state.
func assertLuaSubjectMergedGroups(t *testing.T, auth *core.AuthState, passDBResult *core.PassDBResult) {
	t.Helper()

	if got := auth.GetGroups(); len(got) != 3 || got[0] != "Developer" || got[1] != "Existing" || got[2] != "Ops" {
		t.Fatalf("unexpected merged groups on auth state: %v", got)
	}

	if got := passDBResult.Groups; len(got) != 3 || got[0] != "Developer" || got[1] != "Existing" || got[2] != "Ops" {
		t.Fatalf("unexpected merged groups on passDBResult: %v", got)
	}

	if got := passDBResult.GroupDistinguishedNames; len(got) != 1 || got[0] != "cn=Developer,ou=groups,dc=example,dc=org" {
		t.Fatalf("unexpected group_dns on passDBResult: %v", got)
	}
}

func newDefaultPostActionTestConfig(t *testing.T) *config.FileSettings {
	bfControl := &config.RuntimeModule{}
	if err := bfControl.Set(definitions.ControlBruteForce); err != nil {
		t.Fatalf("Set runtime module failed: %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			RuntimeModules: []*config.RuntimeModule{bfControl},
		},
		Lua: &config.LuaSection{
			Actions: []config.LuaAction{
				{ActionType: definitions.LuaActionPostName},
			},
		},
	}
}

func prepareDefaultPostActionTest(t *testing.T) *config.FileSettings {
	cfg := newDefaultPostActionTestConfig(t)
	envCfg := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(envCfg)
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(envCfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	_ = action.NewWorker(cfg, log.GetLogger(), rediscli.GetClient(), envCfg)

	return cfg
}

func newDefaultPostActionAuth(ctx *gin.Context, cfg *config.FileSettings, guid string) *core.AuthState {
	auth := core.NewAuthStateFromContextWithDeps(ctx, core.AuthDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  rediscli.GetClient(),
	}).(*core.AuthState)

	auth.Runtime.GUID = guid
	auth.Runtime.Context = &lualib.Context{}
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.ClientIP = "192.0.2.10"
	auth.Request.Service = definitions.ServNginx
	auth.Request.Username = "user@example.com"

	return auth
}

func TestDefaultPostAction_QueuesCanceledRequestWithDetachedContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := prepareDefaultPostActionTest(t)

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)

	auth := newDefaultPostActionAuth(ctx, cfg, "guid-canceled")

	DefaultPostAction{}.Run(core.PostActionInput{
		View: auth.View(),
		Result: &core.PassDBResult{
			Authenticated: true,
			UserFound:     true,
		},
	})

	select {
	case act := <-action.RequestChan:
		if act == nil {
			t.Fatal("expected post action to be scheduled")
		}

		if act.HTTPRequest == nil {
			t.Fatal("expected detached HTTP request")
		}

		if err := act.HTTPRequest.Context().Err(); err != nil {
			t.Fatalf("expected detached HTTP request context, got err=%v", err)
		}

		act.FinishedChan <- action.Done{}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected detached post action to be scheduled")
	}
}

func TestDefaultPostAction_WaitsForResponseCompletion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := prepareDefaultPostActionTest(t)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/auth", nil)
	auth := newDefaultPostActionAuth(ctx, cfg, "guid-response-gate")
	gate := core.InstallPostActionExecutionGate(ctx)

	DefaultPostAction{}.Run(core.PostActionInput{
		View: auth.View(),
		Result: &core.PassDBResult{
			Authenticated: true,
			UserFound:     true,
		},
	})

	select {
	case act := <-action.RequestChan:
		act.FinishedChan <- action.Done{}

		t.Fatal("Lua post-action started before response completion")
	case <-time.After(50 * time.Millisecond):
	}

	gate.Complete()

	select {
	case act := <-action.RequestChan:
		act.FinishedChan <- action.Done{}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Lua post-action did not start after response completion")
	}
}

func TestDefaultPostAction_ForwardsEnvironmentRejectedToLuaRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := prepareDefaultPostActionTest(t)

	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest("POST", "/auth", nil)
	ctx.Set(definitions.CtxEnvironmentRejectedKey, true)

	auth := newDefaultPostActionAuth(ctx, cfg, "guid-environment-rejected")

	DefaultPostAction{}.Run(core.PostActionInput{
		View: auth.View(),
		Result: &core.PassDBResult{
			Authenticated: false,
			UserFound:     false,
		},
		EnvironmentRejected:      ctx.GetBool(definitions.CtxEnvironmentRejectedKey),
		EnvironmentStageExpected: false,
		SubjectStageExpected:     false,
	})

	select {
	case act := <-action.RequestChan:
		if act == nil || act.CommonRequest == nil {
			t.Fatal("expected post action request")
		}

		if !act.EnvironmentRejected {
			t.Fatal("expected environment_rejected to be forwarded to the Lua request")
		}

		if act.EnvironmentStageExpected {
			t.Fatal("expected environment_stage_expected to be forwarded to the Lua request")
		}

		if act.SubjectStageExpected {
			t.Fatal("expected subject_stage_expected to be forwarded to the Lua request")
		}

		act.FinishedChan <- action.Done{}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected post action to be scheduled")
	}
}

func TestDefaultPostActionPlanStepSeedsRuntimeAndReturnsLuaDelta(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := prepareDefaultPostActionTest(t)

	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest("POST", "/auth", nil)

	auth := newDefaultPostActionAuth(ctx, cfg, "guid-plan-step")
	auth.Runtime.Context = lualib.NewContext()

	resultCh, okCh := runDefaultPostActionPlanStep(auth.Ctx(), auth)

	select {
	case act := <-action.RequestChan:
		completePlanStepAction(t, act)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected plan-step post action to be scheduled")
	}

	expectPlanStepOK(t, okCh)
	delta := expectPlanStepDelta(t, resultCh)

	if got := delta.Set["lua_value"]; got != "after" {
		t.Fatalf("delta lua_value = %#v, want after", got)
	}

	rt, ok := delta.Set["rt"].(map[string]any)
	if !ok {
		t.Fatalf("delta rt = %#v, want map[string]any", delta.Set["rt"])
	}

	if rt["existing"] != "kept" || rt["action_haveibeenpwnd"] != true || rt["native_value_available"] != true {
		t.Fatalf("delta rt = %#v, want normalized Lua context changes", rt)
	}

	if _, exists := delta.Set["native_value"]; exists {
		t.Fatalf("unchanged seeded value was returned in delta: %#v", delta.Set)
	}

	if got := auth.Runtime.Context.Get("lua_value"); got != nil {
		t.Fatalf("live auth context was mutated with %#v", got)
	}
}

func TestDefaultPostActionPlanStepKeepsCanceledRequestTrace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := prepareDefaultPostActionTest(t)
	cfg.Server.Insights.Tracing.Enabled = true
	collector := oteltest.Setup(t)
	parentCtx, parentSpan := otel.Tracer("nauthilus/core/auth/lua_service_test").Start(context.Background(), "auth.post_action.plan")
	parent := parentSpan.SpanContext()
	requestCtx, cancel := context.WithCancel(parentCtx)
	workerCtx := context.WithoutCancel(requestCtx)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/auth", nil).WithContext(requestCtx)
	auth := newDefaultPostActionAuth(ctx, cfg, "guid-canceled-plan-trace")

	cancel()

	resultCh, okCh := runDefaultPostActionPlanStep(workerCtx, auth)

	var actionParent trace.SpanContext

	select {
	case act := <-action.RequestChan:
		actionParent = act.OTelParentSpanContext
		if got := act.OTelParentSpanContext.TraceID(); got != parent.TraceID() {
			t.Errorf("post-action TraceID = %s, want %s", got, parent.TraceID())
		}

		act.FinishedChan <- action.Done{}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected plan-step post action to be scheduled")
	}

	expectPlanStepOK(t, okCh)
	_ = expectPlanStepDelta(t, resultCh)

	parentSpan.End()

	var luaSpan trace.SpanContext

	for _, span := range collector.Spans() {
		if span.Name() != "auth.lua.post_action" {
			continue
		}

		luaSpan = span.SpanContext()
		if span.Parent().SpanID() != parent.SpanID() {
			t.Fatalf("auth.lua.post_action parent = %s, want plan %s", span.Parent().SpanID(), parent.SpanID())
		}
	}

	if !luaSpan.IsValid() {
		t.Fatal("missing auth.lua.post_action span")
	}

	if actionParent.SpanID() != luaSpan.SpanID() {
		t.Fatalf("Lua action parent = %s, want auth.lua.post_action %s", actionParent.SpanID(), luaSpan.SpanID())
	}
}

// runDefaultPostActionPlanStep starts the plan-step runner and returns its result channels.
func runDefaultPostActionPlanStep(ctx context.Context, auth *core.AuthState) (<-chan pluginapi.RuntimeDelta, <-chan bool) {
	resultCh := make(chan pluginapi.RuntimeDelta, 1)
	okCh := make(chan bool, 1)
	runner := DefaultPostAction{}.PreparePlanStep(core.PostActionInput{
		View: auth.View(),
		Result: &core.PassDBResult{
			Authenticated: true,
			UserFound:     true,
		},
	})

	go func() {
		delta, ok := runner.RunPlanStep(ctx, core.PostActionPlanInput{
			Runtime: map[string]any{
				"native_value": "visible-to-lua",
				"rt":           map[string]any{"existing": "kept"},
			},
		})

		resultCh <- delta

		okCh <- ok
	}()

	return resultCh, okCh
}

// completePlanStepAction verifies seeded runtime values and finishes the Lua action.
func completePlanStepAction(t *testing.T, act *action.Action) {
	t.Helper()

	if act == nil || act.Context == nil {
		t.Fatal("expected Lua post-action request with context")
	}

	if got := act.Get("native_value"); got != "visible-to-lua" {
		t.Fatalf("seeded runtime value = %#v, want visible-to-lua", got)
	}

	act.Set("lua_value", "after")
	act.Set("rt", map[any]any{
		"existing":               "kept",
		"action_haveibeenpwnd":   true,
		"native_value_available": act.Get("native_value") == "visible-to-lua",
	})

	act.FinishedChan <- action.Done{}
}

// expectPlanStepOK waits for the plan-step runner success flag.
func expectPlanStepOK(t *testing.T, okCh <-chan bool) {
	t.Helper()

	select {
	case ok := <-okCh:
		if !ok {
			t.Fatal("RunPlanStep() ok = false, want true")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("RunPlanStep() did not return ok")
	}
}

// expectPlanStepDelta waits for the plan-step runner delta.
func expectPlanStepDelta(t *testing.T, resultCh <-chan pluginapi.RuntimeDelta) pluginapi.RuntimeDelta {
	t.Helper()

	select {
	case delta := <-resultCh:
		return delta
	case <-time.After(250 * time.Millisecond):
		t.Fatal("RunPlanStep() did not return delta")
	}

	return pluginapi.RuntimeDelta{}
}

func TestAuthStateSubjectLua_SkipsCanceledRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Lua: &config.LuaSection{
			SubjectSources: []config.LuaSubjectSource{
				{Name: "noop"},
			},
		},
	}

	envCfg := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(envCfg)
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(envCfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)

	auth := core.NewAuthStateFromContextWithDeps(ctx, core.AuthDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  rediscli.GetClient(),
	}).(*core.AuthState)

	auth.Runtime.GUID = "guid-canceled-subject"
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Service = definitions.ServNginx
	auth.Request.Username = "user@example.com"

	result := auth.SubjectLua(ctx, &core.PassDBResult{})
	if result != definitions.AuthResultTempFail {
		t.Fatalf("expected AuthResultTempFail, got %v", result)
	}
}
