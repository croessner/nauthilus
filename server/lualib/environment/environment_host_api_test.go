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

package environment

import (
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/luaapiprobe"
	"github.com/go-redis/redismock/v9"
)

// TestCallEnvironmentLuaSourceExposesFullHostAPI proves environment sources run with the same Lua API as hooks.
func TestCallEnvironmentLuaSourceExposesFullHostAPI(t *testing.T) {
	db, mock := redismock.NewClientMock()
	mock.ExpectSet("nauthilus_lua_api_probe", "environment", 0).SetVal("OK")

	scriptPath := writeEnvironmentScript(t, t.TempDir(), "probe.lua", luaapiprobe.Script(t, `
function nauthilus_call_environment(_request)
    probe.run()

    local _, err = require("nauthilus_redis").redis_set("default", "nauthilus_lua_api_probe", "environment")
    assert(err == nil, "redis_set failed: " .. tostring(err))

    require("nauthilus_http_response").set_http_response_header("X-Lua-Api-Probe", "environment")

    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`))
	ginCtx := newEnvironmentTestContext()
	manager := vmpool.NewManager()

	_, _, err := newEnvironmentTestRequest().CallEnvironmentLuaSource(
		ginCtx,
		newEnvironmentTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		rediscli.NewTestClientForHandle(db),
		mustNewLuaEnvironmentSource(t, "probe", scriptPath),
		manager,
		environmentTestPoolKey(t, manager, "probe"),
	)
	if err != nil {
		t.Fatalf("CallEnvironmentLuaSource returned error: %v", err)
	}

	if got := ginCtx.Writer.Header().Get("X-Lua-Api-Probe"); got != "environment" {
		t.Fatalf("response header = %q, want the environment source to mutate the live response", got)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis write expectations: %v", err)
	}
}
