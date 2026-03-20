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

package filter

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/yuin/gopher-lua"
)

func TestGetBackendServers(t *testing.T) {
	tests := []struct {
		name         string
		serversInput []*config.BackendServer
		wantLen      int
	}{
		{
			name:         "NoServers",
			serversInput: []*config.BackendServer{},
			wantLen:      0,
		},
		{
			name: "SingleServer",
			serversInput: []*config.BackendServer{
				{
					Protocol:  "http",
					Host:      "192.168.1.1",
					Port:      8000,
					HAProxyV2: false,
					TLS:       false,
				},
			},
			wantLen: 1,
		},
		{
			name: "MultipleServersIncludingNil",
			serversInput: []*config.BackendServer{
				{
					Protocol:  "http",
					Host:      "192.168.1.1",
					Port:      8000,
					HAProxyV2: false,
					TLS:       false,
				},
				nil,
				{
					Protocol:  "https",
					Host:      "192.168.1.2",
					Port:      443,
					HAProxyV2: true,
					TLS:       true,
				},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lState := lua.NewState()
			defer lState.Close()

			getServersFunc := getBackendServers(tt.serversInput)
			getServersFunc(lState)

			serverTable := lState.Get(-1).(*lua.LTable)

			if serverTable.Len() != tt.wantLen {
				t.Errorf("Expected length %d but got %d", tt.wantLen, serverTable.Len())
			}
		})
	}
}

func TestSelectBackendServer(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		port    int
		expServ string
		expPort int
		wantErr bool
	}{
		{
			name:    "httpServerAndPort",
			server:  "192.168.1.1",
			port:    8000,
			expServ: "192.168.1.1",
			expPort: 8000,
			wantErr: false,
		},
		{
			name:    "httpsServerAndPort",
			server:  "192.168.1.2",
			port:    443,
			expServ: "192.168.1.2",
			expPort: 443,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			var server *string
			var port *int

			fn := selectBackendServer(&server, &port)

			L.Push(lua.LString(tt.server))
			L.Push(lua.LNumber(tt.port))

			err := L.CallByParam(lua.P{
				Fn:      L.NewFunction(fn),
				NRet:    0,
				Protect: true,
			}, L.Get(-2), L.Get(-1))

			if err != nil {
				if !tt.wantErr {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if server == nil || port == nil || *server != tt.expServ || *port != tt.expPort {
					t.Errorf("Expected server %s and port %d but got server %v and port %v", tt.expServ, tt.expPort, server, port)
				}
			}
		})
	}
}

func TestSelectBackendServerUpdatesExistingPointers(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	initialServer := "10.0.0.1"
	initialPort := 143
	request := &Request{
		UsedBackendAddress: &initialServer,
		UsedBackendPort: &initialPort,
	}
	originalAddrPtr := request.UsedBackendAddress
	originalPortPtr := request.UsedBackendPort

	selectBackendServerFn := selectBackendServer(&request.UsedBackendAddress, &request.UsedBackendPort)

	err := L.CallByParam(lua.P{
		Fn:      L.NewFunction(selectBackendServerFn),
		NRet:    0,
		Protect: true,
	}, lua.LString("127.0.0.1"), lua.LNumber(993))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if request.UsedBackendAddress != originalAddrPtr {
		t.Fatalf("expected UsedBackendAddress pointer to remain unchanged")
	}

	if request.UsedBackendPort != originalPortPtr {
		t.Fatalf("expected UsedBackendPort pointer to remain unchanged")
	}

	if *request.UsedBackendAddress != "127.0.0.1" {
		t.Fatalf("expected updated server %q, got %q", "127.0.0.1", *request.UsedBackendAddress)
	}

	if *request.UsedBackendPort != 993 {
		t.Fatalf("expected updated port %d, got %d", 993, *request.UsedBackendPort)
	}
}

func writeFilterScript(t *testing.T, dir, name, content string) string {
	t.Helper()

	scriptPath := filepath.Join(dir, name)
	if err := os.WriteFile(scriptPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing script %s: %v", scriptPath, err)
	}

	return scriptPath
}

func mustNewLuaFilter(t *testing.T, name, scriptPath string) *LuaFilter {
	t.Helper()

	lf, err := NewLuaFilter(name, scriptPath)
	if err != nil {
		t.Fatalf("failed to compile Lua filter %q: %v", name, err)
	}

	lf.WhenAuthenticated = true
	lf.WhenUnauthenticated = true
	lf.WhenNoAuth = true

	return lf
}

func withTestLuaFilters(t *testing.T, filters ...*LuaFilter) {
	t.Helper()

	original := LuaFilters
	LuaFilters = &PreCompiledLuaFilters{LuaScripts: filters}

	t.Cleanup(func() {
		LuaFilters = original
	})
}

func newFilterTestContext() *gin.Context {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	return ctx
}

func newFilterTestRequest(addr *string, port *int) *Request {
	return &Request{
		UsedBackendAddress: addr,
		UsedBackendPort: port,
		Context:         lualib.NewContext(),
		CommonRequest:   &lualib.CommonRequest{},
	}
}

func selectBackendFilterScript(address string, port int) string {
	return `
local nauthilus_backend = require("nauthilus_backend")

function nauthilus_call_filter(request)
    nauthilus_backend.select_backend_server("` + address + `", ` + lua.LNumber(port).String() + `)
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
`
}

func runCallFilterLua(t *testing.T, request *Request) bool {
	t.Helper()

	if !config.IsFileLoaded() {
		config.SetTestFile(&config.FileSettings{})
	}

	viper.Set(definitions.LogKeyLuaScripttimeout, 10)

	action, _, _, err := request.CallFilterLua(newFilterTestContext())
	if err != nil {
		t.Fatalf("CallFilterLua returned error: %v", err)
	}

	return action
}

func assertSelectedBackend(t *testing.T, request *Request, expectedAddr string, expectedPort int) {
	t.Helper()

	if request.UsedBackendAddress == nil || request.UsedBackendPort == nil {
		t.Fatalf("expected selected backend address/port to be set")
	}

	if *request.UsedBackendAddress != expectedAddr {
		t.Fatalf("expected selected backend address %q, got %q", expectedAddr, *request.UsedBackendAddress)
	}

	if *request.UsedBackendPort != expectedPort {
		t.Fatalf("expected selected backend port %d, got %d", expectedPort, *request.UsedBackendPort)
	}
}

func TestCallFilterLuaSelectBackendServerDelegatesSingleScript(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := writeFilterScript(t, scriptDir, "single.lua", selectBackendFilterScript("single.backend.local", 1143))

	withTestLuaFilters(t, mustNewLuaFilter(t, "single-select", scriptPath))

	initialAddr := "initial.backend.local"
	initialPort := 25
	request := newFilterTestRequest(&initialAddr, &initialPort)
	action := runCallFilterLua(t, request)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	assertSelectedBackend(t, request, "single.backend.local", 1143)
}

func TestCallFilterLuaSelectBackendServerDelegatesTwoScriptsDeterministic(t *testing.T) {
	scriptDir := t.TempDir()
	firstScriptPath := writeFilterScript(t, scriptDir, "first.lua", selectBackendFilterScript("first.backend.local", 2001))
	secondScriptPath := writeFilterScript(t, scriptDir, "second.lua", selectBackendFilterScript("second.backend.local", 2002))

	withTestLuaFilters(t,
		mustNewLuaFilter(t, "first-select", firstScriptPath),
		mustNewLuaFilter(t, "second-select", secondScriptPath),
	)

	initialAddr := "initial.backend.local"
	initialPort := 25
	request := newFilterTestRequest(&initialAddr, &initialPort)
	action := runCallFilterLua(t, request)

	if action {
		t.Fatalf("expected action=false, got true")
	}

	assertSelectedBackend(t, request, "first.backend.local", 2001)
}
