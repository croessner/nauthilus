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

package connmgr

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/util"
	lua "github.com/yuin/gopher-lua"
)

const luaRequestEnvKey = "__NAUTH_REQ_ENV"
const luaRuntimeContextKey = "__NAUTH_REQ_RUNTIME_CONTEXT"

func TestConnectionManager(t *testing.T) {
	ctx := context.Background()

	setupConnectionManagerTest()

	t.Run("Register and GetCount", func(t *testing.T) {
		assertRegisterAndGetCount(ctx, t)
	})

	t.Run("Register existing", func(t *testing.T) {
		assertRegisterExistingTarget(ctx, t)
	})

	t.Run("GetCount non-existing", func(t *testing.T) {
		assertMissingConnectionCount(t)
	})

	t.Run("Lua Register and GetCount", func(t *testing.T) {
		assertLuaRegisterAndGetCount(ctx, t)
	})
}

// setupConnectionManagerTest configures a fresh manager test environment.
func setupConnectionManagerTest() {
	testFile := &config.FileSettings{
		Server: &config.ServerSection{
			DNS: config.DNS{
				Timeout: 100 * time.Millisecond,
			}}}
	config.SetTestFile(testFile)
	util.SetDefaultConfigFile(testFile)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	manager = GetConnectionManager()
}

// assertRegisterAndGetCount verifies that a registered target is visible.
func assertRegisterAndGetCount(ctx context.Context, t *testing.T) {
	t.Helper()

	manager.Register(ctx, config.GetFile(), "127.0.0.1:8000", "local", "test")

	_, ok := manager.GetCount("127.0.0.1:8000")
	if !ok {
		t.Errorf("Failed to register and retrieve target")
	}
}

// assertRegisterExistingTarget verifies that duplicate registrations keep the original counter.
func assertRegisterExistingTarget(ctx context.Context, t *testing.T) {
	t.Helper()

	manager.Register(ctx, config.GetFile(), "127.0.0.1:8000", "local", "test")

	target := "127.0.0.1:8000"

	manager.Register(ctx, config.GetFile(), target, "remote", "test")

	count, ok := manager.GetCount(target)
	if !ok || count != 0 {
		t.Errorf("Failed to prevent duplicate registration")
	}
}

// assertMissingConnectionCount verifies that unknown targets are absent.
func assertMissingConnectionCount(t *testing.T) {
	t.Helper()

	_, ok := manager.GetCount("non-existing")
	if ok {
		t.Errorf("Failed to return false for non-existing target")
	}
}

// assertLuaRegisterAndGetCount verifies the Lua-facing registration and count functions.
func assertLuaRegisterAndGetCount(ctx context.Context, t *testing.T) {
	t.Helper()

	L := newConnectionManagerLuaState(ctx)
	defer L.Close()

	if err := L.DoString(`register("127.0.0.1:9000", "remote", "test")`); err != nil {
		t.Errorf("Lua register failed: %v", err)
	}

	if err := L.DoString(`
		    count = count("127.0.0.1:9000")
		    if type(count) ~= 'number' then
			  error('Count is not a number')
		    end
    `); err != nil {
		t.Errorf("Lua count failed: %v", err)
	}
}

// newConnectionManagerLuaState exposes connection manager functions to a Lua state.
func newConnectionManagerLuaState(ctx context.Context) *lua.LState {
	L := lua.NewState()
	reqEnv := L.NewTable()
	L.SetGlobal(luaRequestEnvKey, reqEnv)

	m := NewPsnetManager(ctx, config.GetFile(), nil)
	mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"register": m.luaRegisterTarget,
		"count":    m.luaCountOpenConnections,
	})

	userData := L.NewUserData()
	userData.Value = ctx
	L.SetField(reqEnv, luaRuntimeContextKey, userData)
	L.SetGlobal("register", mod.RawGetString("register"))
	L.SetGlobal("count", mod.RawGetString("count"))

	return L
}

func TestStartTicker(t *testing.T) {
	manager = GetConnectionManager()
	done := make(chan struct{})

	go func() {
		manager.StartTicker(100 * time.Millisecond)

		close(done)
	}()

	select {
	case <-done:
		t.Errorf("StartTicker ended too soon")
	case <-time.After(500 * time.Millisecond):
		// Test passed if still running after 500ms
	}
}
