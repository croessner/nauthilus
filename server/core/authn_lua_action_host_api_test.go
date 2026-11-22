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
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/testing/luaapiprobe"
)

// TestAuthnLuaActionExposesFullHostAPI proves synchronous actions and post-actions run with the same Lua API
// as hooks. Only the live response differs: a post-action runs after the response left the server.
func TestAuthnLuaActionExposesFullHostAPI(t *testing.T) {
	for _, test := range []struct {
		name       string
		wantHeader string
		postAction bool
	}{
		{name: "synchronous action mutates the live response", wantHeader: "action"},
		{name: "post-action keeps the response API without effect", postAction: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "probe-action.lua")
			source := luaapiprobe.Script(t, `
function nauthilus_call_action(_request)
    probe.run()
    require("nauthilus_http_response").set_http_response_header("X-Lua-Api-Probe", "action")

    return nauthilus_builtin.ACTION_RESULT_OK
end
`)

			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatalf("write probe action: %v", err)
			}

			prototype, err := compileLuaTestFile(path)
			if err != nil {
				t.Fatalf("compile probe action: %v", err)
			}

			cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
			auth, ginCtx, _ := newCurrentBehaviorAuthState(t, cfg)
			program := authnLuaActionTestProgram{prototype: prototype, pools: vmpool.NewManager()}
			host := &authnCandidateExecution{auth: auth, ginCtx: ginCtx}

			invocation, err := host.newAuthnLuaActionInvocation(
				t.Context(),
				program,
				newAuthnLuaActionTestExecution(t),
				test.postAction,
			)
			if err != nil {
				t.Fatalf("newAuthnLuaActionInvocation() error = %v", err)
			}
			defer invocation.cleanup()

			if err = invocation.run(t.Context()); err != nil {
				t.Fatalf("probe action failed: %v", err)
			}

			if got := ginCtx.Writer.Header().Get("X-Lua-Api-Probe"); got != test.wantHeader {
				t.Fatalf("response header = %q, want %q", got, test.wantHeader)
			}
		})
	}
}
