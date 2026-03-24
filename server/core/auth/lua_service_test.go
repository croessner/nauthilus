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

func TestDefaultPostAction_SkipsCanceledRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	bfFeature := &config.Feature{}
	if err := bfFeature.Set(definitions.FeatureBruteForce); err != nil {
		t.Fatalf("Set feature failed: %v", err)
	}

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{bfFeature},
		},
		Lua: &config.LuaSection{
			Actions: []config.LuaAction{
				{ActionType: definitions.LuaActionPostName},
			},
		},
	}

	envCfg := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(envCfg)
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(envCfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
	_ = action.NewWorker(cfg, log.GetLogger(), rediscli.GetClient(), envCfg)

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

	auth.Runtime.GUID = "guid-canceled"
	auth.Runtime.Context = &lualib.Context{}
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Service = definitions.ServNginx
	auth.Request.Username = "user@example.com"

	DefaultPostAction{}.Run(core.PostActionInput{
		View: auth.View(),
		Result: &core.PassDBResult{
			Authenticated: true,
			UserFound:     true,
		},
	})

	select {
	case act := <-action.RequestChan:
		t.Fatalf("expected no post action to be scheduled, got %+v", act)
	case <-time.After(100 * time.Millisecond):
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
