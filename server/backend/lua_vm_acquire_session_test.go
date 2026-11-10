// Copyright (C) 2026 Christian Roessner
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

package backend

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
)

// TestLuaVMAcquireFailureLogsRequestSession pins that a Lua backend request that cannot borrow a VM names the request
// session in its warning.
func TestLuaVMAcquireFailureLogsRequestSession(t *testing.T) {
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	pool := vmpool.NewManager().GetOrCreate("backend:session-test", vmpool.PoolOptions{MaxVMs: 1, Config: cfg})

	held, err := pool.AcquireLease(t.Context())
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	defer held.Release()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var buf bytes.Buffer

	request := &bktype.LuaRequest{CommonRequest: &lualib.CommonRequest{Session: "luaAcquireSessionGUID"}}
	handleLuaRequest(ctx, cfg, slog.New(slog.NewJSONHandler(&buf, nil)), nil, request, nil, pool)

	line := logLineContaining(buf.String(), "lua_vm_acquire_failed")
	if !strings.Contains(line, `"session":"luaAcquireSessionGUID"`) {
		t.Fatalf("acquire failure log = %q, want session luaAcquireSessionGUID in %s", line, buf.String())
	}
}

// logLineContaining returns the first log line that contains marker.
func logLineContaining(output string, marker string) string {
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, marker) {
			return line
		}
	}

	return ""
}
