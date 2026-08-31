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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/util"

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

type currentBehaviorLuaEnvironmentCase struct {
	name        string
	script      string
	wantMessage string
	wantTrigger bool
	wantAbort   bool
}

func TestGenerationOwnedLuaEnvironmentSourceTriggerAndAbort(t *testing.T) {
	cases := []currentBehaviorLuaEnvironmentCase{
		{
			name: "trigger returns Lua environment result",
			script: `
function nauthilus_call_environment(request)
    nauthilus_builtin.status_message_set("Lua environment denied")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`,
			wantTrigger: true,
			wantMessage: "Lua environment denied",
		},
		{
			name: "abort allows remaining auth flow",
			script: `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_YES, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`,
			wantAbort: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			assertCurrentBehaviorLuaEnvironmentCase(t, testCase)
		})
	}
}

// assertCurrentBehaviorLuaEnvironmentCase executes and verifies one captured environment source.
func assertCurrentBehaviorLuaEnvironmentCase(t *testing.T, testCase currentBehaviorLuaEnvironmentCase) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t, definitions.ControlLua)
	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	scriptPath := withCurrentBehaviorLuaEnvironment(t, testCase.script)

	prototype, err := compileLuaTestFile(scriptPath)
	if err != nil {
		t.Fatalf("compile generation-owned Lua environment source: %v", err)
	}

	triggered, aborted, err := auth.EnvironmentLuaSource(
		ctx,
		"current_behavior_environment",
		prototype,
		vmpool.NewManager(),
		vmpool.PoolKey("test:current_behavior_environment:"+testCase.name),
		nil,
	)
	if err != nil {
		t.Fatalf("EnvironmentLuaSource() error = %v", err)
	}

	if triggered != testCase.wantTrigger || aborted != testCase.wantAbort {
		t.Fatalf(
			"EnvironmentLuaSource() = triggered:%t aborted:%t, want triggered:%t aborted:%t",
			triggered,
			aborted,
			testCase.wantTrigger,
			testCase.wantAbort,
		)
	}

	if auth.Runtime.StatusMessage != testCase.wantMessage {
		t.Fatalf("status message = %q, want %q", auth.Runtime.StatusMessage, testCase.wantMessage)
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
		l1.Decision{Blocked: true, Rule: "existing_block"},
		time.Minute,
	)

	mock.Regexp().ExpectHGet(".*", ".*").RedisNil()
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-current-window")
	mock.Regexp().ExpectEvalSha("sha-current-window", []string{".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
		SetVal([]any{"3", int64(1), "4"})
	mock.ExpectScriptLoad(rediscli.LuaScripts["IncrementAndExpire"]).SetVal("sha-current-burst")
	mock.Regexp().ExpectEvalSha("sha-current-burst", []string{".*"}, ".*").SetVal(int64(2))
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
	cfg.Policy.API.Enabled = true
	cfg.Policy.API.HTTP.Enabled = true
	cfg.Policy.API.GRPC.Enabled = true

	for _, environmentName := range enabledRuntimeModules {
		cfg.Server.RuntimeModules = append(cfg.Server.RuntimeModules, mustCurrentBehaviorModule(t, environmentName))
	}

	config.SetTestFile(cfg)
	SetDefaultEnvironment(env)
	SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
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
		HostServices: registeredAuthnHostServices(),
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

// withCurrentBehaviorLuaEnvironment writes one source and returns its exact path.
func withCurrentBehaviorLuaEnvironment(t *testing.T, script string) string {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "environment.lua")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("failed to write Lua environment source: %v", err)
	}

	return scriptPath
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
