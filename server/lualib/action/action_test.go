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

package action

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	lua "github.com/yuin/gopher-lua"
)

func newActionWorkerTestScript(t *testing.T) (string, *lua.FunctionProto) {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "busy_loop.lua")
	script := []byte("local i = 0\nwhile true do\n  i = i + 1\nend\nreturn 0\n")

	if err := os.WriteFile(scriptPath, script, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	compiled, err := lualib.CompileLua(scriptPath)
	if err != nil {
		t.Fatalf("CompileLua failed: %v", err)
	}

	return scriptPath, compiled
}

func newActionWorkerReturnTestScript(t *testing.T) (string, *lua.FunctionProto) {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "return_ok.lua")
	script := []byte("return 0\n")

	if err := os.WriteFile(scriptPath, script, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	compiled, err := lualib.CompileLua(scriptPath)
	if err != nil {
		t.Fatalf("CompileLua failed: %v", err)
	}

	return scriptPath, compiled
}

func newActionWorkerUnderTest(t *testing.T) (*Worker, *http.Request, context.CancelFunc, context.CancelFunc) {
	t.Helper()

	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
	}

	config.SetTestFile(cfg)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	scriptPath, compiled := newActionWorkerTestScript(t)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)

	workerCtx, cancelWorker := context.WithCancel(context.Background())

	worker := NewWorker(cfg, log.GetLogger(), rediscli.GetClient(), util.GetDefaultEnvironment())
	worker.ctx = workerCtx
	worker.actionScripts = []*LuaScriptAction{
		{
			ScriptPath:     scriptPath,
			ScriptCompiled: compiled,
			ScriptName:     "busy_loop",
			LuaAction:      definitions.LuaActionPost,
		},
	}
	worker.luaActionRequest = &Action{
		LuaAction:    definitions.LuaActionPost,
		Context:      &lualib.Context{},
		FinishedChan: make(chan Done, 1),
		HTTPRequest:  req,
		CommonRequest: &lualib.CommonRequest{
			Session:  "guid-1",
			Username: "user@example.com",
			Service:  definitions.ServNginx,
		},
	}

	return worker, req, cancelReq, cancelWorker
}

func TestHandleRequest_StopsWhenHTTPRequestContextIsCanceled(t *testing.T) {
	worker, req, cancelReq, cancelWorker := newActionWorkerUnderTest(t)
	defer cancelWorker()

	done := make(chan struct{})

	go func() {
		worker.handleRequest(req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancelReq()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		cancelWorker()

		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("handleRequest did not stop after HTTP request cancellation")
		}
	}
}

func TestHandleRequest_PostActionIgnoresCanceledHTTPRequestContext(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
	}

	config.SetTestFile(cfg)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	scriptPath, compiled := newActionWorkerReturnTestScript(t)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	cancelReq()

	req := httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)

	worker := NewWorker(cfg, log.GetLogger(), rediscli.GetClient(), util.GetDefaultEnvironment())
	worker.ctx = context.Background()
	worker.actionScripts = []*LuaScriptAction{
		{
			ScriptPath:     scriptPath,
			ScriptCompiled: compiled,
			ScriptName:     "return_ok",
			LuaAction:      definitions.LuaActionPost,
		},
	}
	worker.luaActionRequest = &Action{
		LuaAction:    definitions.LuaActionPost,
		Context:      &lualib.Context{},
		FinishedChan: make(chan Done, 1),
		HTTPRequest:  req,
		CommonRequest: &lualib.CommonRequest{
			Session:  "guid-2",
			Username: "user@example.com",
			Service:  definitions.ServNginx,
		},
	}

	done := make(chan struct{})

	go func() {
		worker.handleRequest(req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handleRequest did not process post action with canceled HTTP request context")
	}
}
