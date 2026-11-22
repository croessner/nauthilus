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

package subject

import (
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/luaapiprobe"
	"github.com/go-redis/redismock/v9"
)

// TestCallSubjectLuaSourceExposesFullHostAPI proves subject sources run with the same Lua API as hooks and
// can select the backend server again.
func TestCallSubjectLuaSourceExposesFullHostAPI(t *testing.T) {
	db, mock := redismock.NewClientMock()
	mock.ExpectSet("nauthilus_lua_api_probe", "subject", 0).SetVal("OK")

	scriptPath := writeSubjectScript(t, t.TempDir(), "probe.lua", luaapiprobe.Script(t, `
function nauthilus_call_subject(_request)
    probe.run()
    probe.backend_selection()
    assert(type(rawget(_G, "nauthilus_backend_result")) == "table", "nauthilus_backend_result is not a global")

    local _, err = require("nauthilus_redis").redis_set("default", "nauthilus_lua_api_probe", "subject")
    assert(err == nil, "redis_set failed: " .. tostring(err))

    require("nauthilus_http_response").set_http_response_header("X-Lua-Api-Probe", "subject")
    require("nauthilus_backend").select_backend_server("192.0.2.77", 993)

    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`))

	request := newSubjectTestRequest(nil, nil)
	ginCtx := newSubjectTestContext()
	pools := vmpool.NewManager()

	rejected, _, _, err := request.CallSubjectLuaSource(
		ginCtx,
		newSubjectTestConfig(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		rediscli.NewTestClientForHandle(db),
		mustNewLuaSubjectSource(t, "probe", scriptPath),
		pools,
		subjectTestPoolKey(t, pools, "probe"),
	)
	if err != nil {
		t.Fatalf("CallSubjectLuaSource returned error: %v", err)
	}

	if rejected {
		t.Fatal("probe subject source rejected the request")
	}

	if got := ginCtx.Writer.Header().Get("X-Lua-Api-Probe"); got != "subject" {
		t.Fatalf("response header = %q, want the subject source to mutate the live response", got)
	}

	assertSelectedBackend(t, request, "192.0.2.77", 993)

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis write expectations: %v", err)
	}
}
