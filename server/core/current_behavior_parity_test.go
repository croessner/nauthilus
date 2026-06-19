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

package core

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/lualib"
	environmentlib "github.com/croessner/nauthilus/v3/server/lualib/environment"
	"github.com/croessner/nauthilus/v3/server/lualib/pipeline"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

type currentBehaviorBuiltInControlCase struct {
	name       string
	control    string
	configure  func(*config.FileSettings)
	beforeRun  func(t *testing.T)
	wantResult definitions.AuthResult
}

func TestCurrentBehaviorParityLuaEnvironmentTriggerAndAbort(t *testing.T) {
	cases := []struct {
		name        string
		script      string
		wantResult  definitions.AuthResult
		wantMessage string
	}{
		{
			name: "trigger returns Lua environment result",
			script: `
function nauthilus_call_environment(request)
    nauthilus_builtin.status_message_set("Lua environment denied")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`,
			wantResult: definitions.AuthResultLuaEnvironment,
		},
		{
			name: "abort allows remaining auth flow",
			script: `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_YES, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`,
			wantResult: definitions.AuthResultOK,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t, definitions.ControlLua)
			auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
			withCurrentBehaviorLuaEnvironment(t, testCase.script)

			got := auth.HandleEnvironment(ctx)
			if got != testCase.wantResult {
				t.Fatalf("environment result = %v, want %v", got, testCase.wantResult)
			}

			if auth.Runtime.StatusMessage != testCase.wantMessage {
				t.Fatalf("status message = %q, want %q", auth.Runtime.StatusMessage, testCase.wantMessage)
			}

			if testCase.wantResult == definitions.AuthResultLuaEnvironment && !ctx.GetBool(definitions.CtxEnvironmentRejectedKey) {
				t.Fatal("expected environment rejection flag for triggered Lua environment source")
			}
		})
	}
}

func TestCurrentBehaviorParityBuiltInPreAuthControls(t *testing.T) {
	for _, testCase := range currentBehaviorBuiltInControlCases() {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t, testCase.control)
			if testCase.configure != nil {
				testCase.configure(cfg)
			}

			if testCase.beforeRun != nil {
				testCase.beforeRun(t)
			}

			auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
			auth.Request.Username = "user@foreign.test"

			got := auth.HandleEnvironment(ctx)
			if got != testCase.wantResult {
				t.Fatalf("pre-auth result = %v, want %v", got, testCase.wantResult)
			}
		})
	}
}

func TestCurrentBehaviorParityPolicyConfigDoesNotChangePreAuthControls(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.Auth = &config.AuthSection{
		Policy: config.AuthPolicySection{
			Mode:          "enforce",
			DefaultPolicy: policy.BuiltinDefaultSet,
		},
	}

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultPreAuthTLS {
		t.Fatalf("pre-auth result = %v, want %v", got, definitions.AuthResultPreAuthTLS)
	}
}

func currentBehaviorBuiltInControlCases() []currentBehaviorBuiltInControlCase {
	return []currentBehaviorBuiltInControlCase{
		{
			name:    "tls without accepted transport is temporary failure control",
			control: definitions.ControlTLSEncryption,
			configure: func(cfg *config.FileSettings) {
				cfg.ClearTextList = nil
			},
			wantResult: definitions.AuthResultPreAuthTLS,
		},
		{
			name:    "unknown relay domain is deny control",
			control: definitions.ControlRelayDomains,
			configure: func(cfg *config.FileSettings) {
				cfg.RelayDomains = &config.RelayDomainsSection{
					StaticDomains: []string{"example.test"},
				}
			},
			wantResult: definitions.AuthResultPreAuthRelayDomain,
		},
		{
			name:    "rbl threshold match is deny control",
			control: definitions.ControlRBL,
			configure: func(cfg *config.FileSettings) {
				cfg.RBLs = &config.RBLSection{Threshold: 5}
			},
			beforeRun: func(t *testing.T) {
				t.Helper()

				previous := GetRBLService()
				RegisterRBLService(currentBehaviorRBLService{score: 5, threshold: 5})
				t.Cleanup(func() {
					RegisterRBLService(previous)
				})
			},
			wantResult: definitions.AuthResultPreAuthRBL,
		},
	}
}

func TestCurrentBehaviorParityBruteForceDirectBlock(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	cfg.BruteForce = &config.BruteForceSection{
		Buckets: []config.BruteForceRule{
			{
				Name:           "existing_block",
				Period:         time.Hour,
				CIDR:           24,
				IPv4:           true,
				FailedRequests: 5,
			},
		},
	}
	cfg.Server.BruteForceProtocols = []*config.Protocol{config.NewProtocol(definitions.ProtoIMAP)}

	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.9"
	auth.Request.Username = "blocked@example.test"
	auth.Request.Password = secret.New("blocked-secret")
	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	l1.GetEngine().Clear()

	l1.GetEngine().Set(
		ctx.Request.Context(),
		l1.KeyNetwork("203.0.113.0/24"),
		l1.L1Decision{Blocked: true, Rule: "existing_block"},
		time.Minute,
	)

	mock.Regexp().ExpectHGet(".*", ".*").RedisNil()
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-current-window")
	mock.Regexp().ExpectEvalSha("sha-current-window", []string{".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
		SetVal([]any{"3", int64(1), "4"})
	mock.ExpectScriptLoad(rediscli.LuaScripts["IncrementAndExpire"]).SetVal("sha-current-burst")
	mock.Regexp().ExpectEvalSha("sha-current-burst", []string{".*"}, ".*").SetVal(int64(2))
	mock.Regexp().ExpectGet(".*").RedisNil()
	mock.Regexp().ExpectSCard(".*").SetVal(0)

	if !auth.CheckBruteForce(ctx) {
		t.Fatal("expected current direct brute-force block to reject the request")
	}

	if auth.Runtime.EnvironmentName != definitions.ControlBruteForce {
		t.Fatalf("environment name = %q, want %q", auth.Runtime.EnvironmentName, definitions.ControlBruteForce)
	}

	if auth.Security.BruteForceName != "existing_block" {
		t.Fatalf("brute-force name = %q, want existing_block", auth.Security.BruteForceName)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func TestCurrentBehaviorParityLuaSubjectStatusMessage(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	service, mock := newCurrentBehaviorApplicationService(t, cfg)
	username := "subject-denied@example.test"
	expectCurrentBehaviorAccountMapping(t, cfg, mock, username, definitions.ProtoIMAP)

	previousVerifier := getPasswordVerifier()
	previousSubject := getLuaSubject()
	previousPostAction := getPostAction()
	RegisterPasswordVerifier(currentBehaviorPasswordVerifier{})
	RegisterLuaSubject(currentBehaviorDenyingSubject{message: "Lua subject denied"})
	RegisterPostAction(currentBehaviorPostAction{})
	t.Cleanup(func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterLuaSubject(previousSubject)
		RegisterPostAction(previousPostAction)
	})

	outcome, err := service.Authenticate(context.Background(), NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
		Username: username,
		Password: "secret",
		ClientIP: "203.0.113.20",
		Protocol: definitions.ProtoIMAP,
		Method:   "plain",
	}))
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if outcome.Decision != AuthDecisionFail {
		t.Fatalf("decision = %q, want %q", outcome.Decision, AuthDecisionFail)
	}

	if outcome.StatusMessage != "Lua subject denied" {
		t.Fatalf("status message = %q, want Lua subject denied", outcome.StatusMessage)
	}

	if outcome.TerminalState != string(authFSMStateAuthFail) {
		t.Fatalf("terminal state = %q, want %q", outcome.TerminalState, authFSMStateAuthFail)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func newCurrentBehaviorConfig(t *testing.T, enabledRuntimeModules ...string) *config.FileSettings {
	t.Helper()

	env := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(env)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			RuntimeModules:            make([]*config.RuntimeModule, 0, len(enabledRuntimeModules)),
			MaxLoginAttempts:          5,
			MaxPasswordHistoryEntries: 10,
			LocalCacheAuthTTL:         time.Minute,
			Redis: config.Redis{
				Prefix:      "parity:",
				NegCacheTTL: time.Hour,
			},
		},
	}

	for _, environmentName := range enabledRuntimeModules {
		cfg.Server.RuntimeModules = append(cfg.Server.RuntimeModules, mustCurrentBehaviorModule(t, environmentName))
	}

	config.SetTestFile(cfg)
	SetDefaultConfigFile(cfg)
	SetDefaultEnvironment(env)
	SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(env)

	return cfg
}

func mustCurrentBehaviorModule(t *testing.T, name string) *config.RuntimeModule {
	t.Helper()

	runtimeModule := &config.RuntimeModule{}
	if err := runtimeModule.Set(name); err != nil {
		t.Fatalf("runtimeModule.Set(%q) failed: %v", name, err)
	}

	return runtimeModule
}

func newCurrentBehaviorAuthState(t *testing.T, cfg *config.FileSettings) (*AuthState, *gin.Context, redismock.ClientMock) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", http.NoBody)

	db, mock := redismock.NewClientMock()
	deps := AuthDeps{
		Cfg:          cfg,
		Env:          config.NewTestEnvironmentConfig(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:        rediscli.NewTestClient(db),
		AccountCache: accountcache.NewManager(cfg),
	}

	auth := NewAuthStateFromContextWithDeps(ctx, deps).(*AuthState)
	auth.Runtime.GUID = "guid-current-behavior"
	auth.Runtime.Context = lualib.NewContext()
	auth.Request.Service = definitions.ServJSON
	auth.Request.Protocol = config.NewProtocol(definitions.ProtoIMAP)
	auth.Request.ClientIP = "203.0.113.10"
	auth.Request.Username = "user@example.test"
	auth.Request.Password = secret.New("secret")
	auth.SetStatusCodes(auth.Request.Service)

	return auth, ctx, mock
}

func withCurrentBehaviorLuaEnvironment(t *testing.T, script string) {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "environment.lua")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("failed to write Lua environment source: %v", err)
	}

	luaEnvironment, err := environmentlib.NewLuaEnvironmentSource("current_behavior_environment", scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua environment source: %v", err)
	}

	luaEnvironment.Modes = pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth

	previous := environmentlib.LuaEnvironmentSources
	compiled := &environmentlib.PreCompiledLuaEnvironmentSources{LuaScripts: []*environmentlib.LuaEnvironmentSource{luaEnvironment}}
	if err := compiled.RebuildPlans(); err != nil {
		t.Fatalf("failed to build Lua environment plan: %v", err)
	}

	environmentlib.LuaEnvironmentSources = compiled
	t.Cleanup(func() {
		environmentlib.LuaEnvironmentSources = previous
	})
}

func newCurrentBehaviorApplicationService(
	t *testing.T,
	cfg *config.FileSettings,
) (AuthApplicationService, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	deps := AuthDeps{
		Cfg:          cfg,
		Env:          config.NewTestEnvironmentConfig(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:        rediscli.NewTestClient(db),
		AccountCache: accountcache.NewManager(cfg),
	}

	return NewAuthApplicationService(deps), mock
}

func expectCurrentBehaviorAccountMapping(
	t *testing.T,
	cfg *config.FileSettings,
	mock redismock.ClientMock,
	username string,
	protocol string,
) {
	t.Helper()

	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	mock.ExpectHGet(key, field).RedisNil()
	mock.ExpectHSet(key, field, username).SetVal(1)
}

type currentBehaviorRBLService struct {
	score     int
	threshold int
}

func (s currentBehaviorRBLService) Score(*gin.Context, *StateView) (int, error) {
	return s.score, nil
}

func (s currentBehaviorRBLService) Threshold() int {
	return s.threshold
}

type currentBehaviorPasswordVerifier struct{}

func (currentBehaviorPasswordVerifier) Verify(
	ctx *gin.Context,
	auth *AuthState,
	_ []*PassDBMap,
) (*PassDBResult, error) {
	result := GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = true
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendTest
	result.Attributes = map[string][]any{
		"uid": {auth.Request.Username},
	}
	updateAuthentication(ctx, auth, result, nil)

	return result, nil
}

type currentBehaviorDenyingSubject struct {
	message string
}

func (s currentBehaviorDenyingSubject) Analyze(_ *gin.Context, view *StateView, _ *PassDBResult) definitions.AuthResult {
	view.Auth().Runtime.StatusMessage = s.message

	return definitions.AuthResultFail
}

type currentBehaviorPostAction struct{}

func (currentBehaviorPostAction) Run(PostActionInput) {}
