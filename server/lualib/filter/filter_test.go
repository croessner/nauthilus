package filter

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	lua "github.com/yuin/gopher-lua"
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
					IP:        "192.168.1.1",
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
					IP:        "192.168.1.1",
					Port:      8000,
					HAProxyV2: false,
					TLS:       false,
				},
				nil,
				{
					Protocol:  "https",
					IP:        "192.168.1.2",
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
