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
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/config"
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

			request := &Request{
				BackendServers: tt.serversInput,
			}
			manager := NewFilterBackendManager(context.TODO(), nil, nil, request, nil, nil)
			manager.getBackendServers(lState)

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

			request := &Request{
				UsedBackendAddr: server,
				UsedBackendPort: port,
			}
			manager := NewFilterBackendManager(context.TODO(), nil, nil, request, nil, nil)

			L.Push(lua.LString(tt.server))
			L.Push(lua.LNumber(tt.port))

			err := L.CallByParam(lua.P{
				Fn:      L.NewFunction(manager.selectBackendServer),
				NRet:    0,
				Protect: true,
			}, L.Get(-2), L.Get(-1))

			if err != nil {
				if !tt.wantErr {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				if request.UsedBackendAddr == nil || request.UsedBackendPort == nil || *request.UsedBackendAddr != tt.expServ || *request.UsedBackendPort != tt.expPort {
					t.Errorf("Expected server %s and port %d but got server %v and port %v", tt.expServ, tt.expPort, request.UsedBackendAddr, request.UsedBackendPort)
				}
			}
		})
	}
}
