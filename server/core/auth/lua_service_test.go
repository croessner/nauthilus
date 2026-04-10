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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

func TestDefaultLuaFilter_OverridesAccountField(t *testing.T) {
	gin.SetMode(gin.TestMode)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	scriptPath := filepath.Clean(filepath.Join(wd, "..", "..", "lualib", "filter", "testdata", "account_field.lua"))

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nt:",
			},
		},
		Lua: &config.LuaSection{
			Filters: []config.LuaFilter{
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

	if err := filter.PreCompileLuaFilters(config.GetFile()); err != nil {
		t.Fatalf("PreCompileLuaFilters failed: %v", err)
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

	result := (DefaultLuaFilter{}).Filter(ctx, auth.View(), &core.PassDBResult{})
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

func TestDefaultLuaFilter_MergesGroupsFromBackendResult(t *testing.T) {
	gin.SetMode(gin.TestMode)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	scriptPath := filepath.Clean(filepath.Join(wd, "..", "..", "lualib", "filter", "testdata", "groups_apply.lua"))

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nt:",
			},
		},
		Lua: &config.LuaSection{
			Filters: []config.LuaFilter{
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

	if err := filter.PreCompileLuaFilters(config.GetFile()); err != nil {
		t.Fatalf("PreCompileLuaFilters failed: %v", err)
	}

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

	passDBResult := &core.PassDBResult{}
	result := (DefaultLuaFilter{}).Filter(ctx, auth.View(), passDBResult)
	if result != definitions.AuthResultFail {
		t.Fatalf("expected AuthResultFail, got %v", result)
	}

	if got := auth.GetGroups(); len(got) != 3 || got[0] != "Developer" || got[1] != "Existing" || got[2] != "Ops" {
		t.Fatalf("unexpected merged groups on auth state: %v", got)
	}

	if got := passDBResult.Groups; len(got) != 3 || got[0] != "Developer" || got[1] != "Existing" || got[2] != "Ops" {
		t.Fatalf("unexpected merged groups on passDBResult: %v", got)
	}

	if got := passDBResult.GroupDNs; len(got) != 1 || got[0] != "cn=Developer,ou=groups,dc=example,dc=org" {
		t.Fatalf("unexpected group_dns on passDBResult: %v", got)
	}
}

func newDefaultPostActionTestConfig(t *testing.T) *config.FileSettings {
	bfFeature := &config.Feature{}
	if err := bfFeature.Set(definitions.FeatureBruteForce); err != nil {
		t.Fatalf("Set feature failed: %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{bfFeature},
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

func TestDefaultPostAction_ForwardsFeatureRejectedToLuaRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := prepareDefaultPostActionTest(t)

	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest("POST", "/auth", nil)
	ctx.Set(definitions.CtxFeatureRejectedKey, true)

	auth := newDefaultPostActionAuth(ctx, cfg, "guid-feature-rejected")

	DefaultPostAction{}.Run(core.PostActionInput{
		View: auth.View(),
		Result: &core.PassDBResult{
			Authenticated: false,
			UserFound:     false,
		},
		FeatureRejected:      ctx.GetBool(definitions.CtxFeatureRejectedKey),
		FeatureStageExpected: false,
		FilterStageExpected:  false,
	})

	select {
	case act := <-action.RequestChan:
		if act == nil || act.CommonRequest == nil {
			t.Fatal("expected post action request")
		}

		if !act.FeatureRejected {
			t.Fatal("expected feature_rejected to be forwarded to the Lua request")
		}

		if act.FeatureStageExpected {
			t.Fatal("expected feature_stage_expected to be forwarded to the Lua request")
		}

		if act.FilterStageExpected {
			t.Fatal("expected filter_stage_expected to be forwarded to the Lua request")
		}

		act.FinishedChan <- action.Done{}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected post action to be scheduled")
	}
}

func TestAuthStateFilterLua_SkipsCanceledRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Lua: &config.LuaSection{
			Filters: []config.LuaFilter{
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

	auth.Runtime.GUID = "guid-canceled-filter"
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Service = definitions.ServNginx
	auth.Request.Username = "user@example.com"

	result := auth.FilterLua(ctx, &core.PassDBResult{})
	if result != definitions.AuthResultTempFail {
		t.Fatalf("expected AuthResultTempFail, got %v", result)
	}
}
