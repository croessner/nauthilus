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

package auth

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

func TestDefaultActionDispatcher_SkipsCanceledRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Lua: &config.LuaSection{
			Actions: []config.LuaAction{
				{ActionType: definitions.LuaActionLuaName},
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

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)

	auth := core.NewAuthStateFromContextWithDeps(ctx, core.AuthDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  rediscli.GetClient(),
	}).(*core.AuthState)

	auth.Runtime.GUID = "guid-canceled-action"
	auth.Runtime.Context = &lualib.Context{}
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Request.Service = definitions.ServNginx
	auth.Request.Username = "user@example.com"

	DefaultActionDispatcher{}.Dispatch(auth.View(), definitions.FeatureLua, definitions.LuaActionLua)

	select {
	case act := <-action.RequestChan:
		t.Fatalf("expected no Lua action to be dispatched, got %+v", act)
	case <-time.After(100 * time.Millisecond):
	}
}
