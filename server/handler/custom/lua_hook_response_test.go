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

package custom

import (
	"net/http"
	"testing"
)

// luaHookResponseCase describes one hook body and the HTTP response it must produce.
type luaHookResponseCase struct {
	name       string
	hookBody   string
	wantStatus int
	wantBody   string
	wantHeader string
}

// luaHookResponseCases lists status, header and explicit body combinations for custom hooks.
func luaHookResponseCases() []luaHookResponseCase {
	return []luaHookResponseCase{
		{
			name:       "status keeps JSON result",
			hookBody:   `nauthilus_http_response.set_http_status(400)`,
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"result":"table"}`,
		},
		{
			name:       "header keeps JSON result",
			hookBody:   `nauthilus_http_response.set_http_response_header("X-Hook", "yes")`,
			wantStatus: http.StatusOK,
			wantBody:   `{"result":"table"}`,
			wantHeader: "yes",
		},
		{
			name:       "status and header keep JSON result",
			hookBody:   "nauthilus_http_response.set_http_status(422)\n\tnauthilus_http_response.add_http_response_header(\"X-Hook\", \"yes\")",
			wantStatus: http.StatusUnprocessableEntity,
			wantBody:   `{"result":"table"}`,
			wantHeader: "yes",
		},
		{
			name:       "explicit body wins over table",
			hookBody:   `nauthilus_http_response.string(201, "raw")`,
			wantStatus: http.StatusCreated,
			wantBody:   "raw",
		},
	}
}

// TestLuaHookResultUsesResponseStateSetByLua verifies that status and header calls keep the returned
// Lua table as JSON body, while explicit body writers own the response.
func TestLuaHookResultUsesResponseStateSetByLua(t *testing.T) {
	for _, tt := range luaHookResponseCases() {
		t.Run(tt.name, func(t *testing.T) {
			router := newLuaHookAuthTestRouter(t, luaHookAuthTestConfig{
				location: "/response-hook",
				method:   http.MethodGet,
				public:   true,
				script: `local nauthilus_http_response = require("nauthilus_http_response")

function nauthilus_run_hook(request)
	` + tt.hookBody + `

	return { result = "table" }
end
`,
			})

			rec := performLuaHookAuthRequest(router, http.MethodGet, "/api/v1/custom/response-hook", "", "")

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}

			if got := rec.Body.String(); got != tt.wantBody {
				t.Fatalf("body = %q, want %q", got, tt.wantBody)
			}

			if got := rec.Header().Get("X-Hook"); got != tt.wantHeader {
				t.Fatalf("X-Hook = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}
