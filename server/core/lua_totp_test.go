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
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockLuaConfig struct {
	mock.Mock
	config.File
	server *config.ServerSection
}

func (m *mockLuaConfig) GetLuaSearchProtocol(protocol string, backendName string) (*config.LuaSearchProtocol, error) {
	args := m.Called(protocol, backendName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*config.LuaSearchProtocol), args.Error(1)
}

func (m *mockLuaConfig) GetServer() *config.ServerSection {
	if m.server != nil {
		return m.server
	}

	return &config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
	}
}

func TestLuaAddTOTPSecret(t *testing.T) {
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	protocol := &config.LuaSearchProtocol{
		BackendName: "test",
		CacheName:   "test",
		Protocols:   []string{"oidc"},
	}

	serverCfg := &config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	}

	mcfg := &mockLuaConfig{server: serverCfg}
	mcfg.On("GetLuaSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username: "jdoe",
			Protocol: new(config.Protocol),
		},
		Runtime: AuthRuntime{
			GUID: "test-guid",
		},
	}
	auth.Request.Protocol.Set("oidc")

	priorityqueue.LuaQueue.AddBackendName("test")

	go func() {
		req := priorityqueue.LuaQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LuaCommandAddMFAValue, req.Command)
			assert.Equal(t, "secret", req.TOTPSecret)

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{}
			}
		}
	}()

	err := lm.AddTOTPSecret(auth, mfa.NewTOTPSecret("secret"))
	assert.NoError(t, err)
}

func TestLuaDeleteTOTPSecret(t *testing.T) {
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	protocol := &config.LuaSearchProtocol{
		BackendName: "test",
		CacheName:   "test",
		Protocols:   []string{"oidc"},
	}

	serverCfg := &config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	}

	mcfg := &mockLuaConfig{server: serverCfg}
	mcfg.On("GetLuaSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username: "jdoe",
			Protocol: new(config.Protocol),
		},
		Runtime: AuthRuntime{
			GUID: "test-guid",
		},
	}
	auth.Request.Protocol.Set("oidc")

	priorityqueue.LuaQueue.AddBackendName("test")

	go func() {
		req := priorityqueue.LuaQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LuaCommandDeleteMFAValue, req.Command)

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{}
			}
		}
	}()

	err := lm.DeleteTOTPSecret(auth)
	assert.NoError(t, err)
}

func TestLuaAddTOTPRecoveryCodes(t *testing.T) {
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	protocol := &config.LuaSearchProtocol{
		BackendName: "test",
		CacheName:   "test",
		Protocols:   []string{"oidc"},
	}

	serverCfg := &config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	}

	mcfg := &mockLuaConfig{server: serverCfg}
	mcfg.On("GetLuaSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username: "jdoe",
			Protocol: new(config.Protocol),
		},
		Runtime: AuthRuntime{
			GUID: "test-guid",
		},
	}
	auth.Request.Protocol.Set("oidc")

	recovery := mfa.NewTOTPRecovery([]string{"code1", "code2"})

	priorityqueue.LuaQueue.AddBackendName("test")

	go func() {
		req := priorityqueue.LuaQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LuaCommandAddTOTPRecoveryCodes, req.Command)
			assert.NotNil(t, req.CommonRequest)
			assert.Equal(t, []string{"code1", "code2"}, req.CommonRequest.TOTPRecoveryCodes)

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{}
			}
		}
	}()

	err := lm.AddTOTPRecoveryCodes(auth, recovery)
	assert.NoError(t, err)
}

func TestLuaDeleteTOTPRecoveryCodes(t *testing.T) {
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	protocol := &config.LuaSearchProtocol{
		BackendName: "test",
		CacheName:   "test",
		Protocols:   []string{"oidc"},
	}

	serverCfg := &config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	}

	mcfg := &mockLuaConfig{server: serverCfg}
	mcfg.On("GetLuaSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username: "jdoe",
			Protocol: new(config.Protocol),
		},
		Runtime: AuthRuntime{
			GUID: "test-guid",
		},
	}
	auth.Request.Protocol.Set("oidc")

	priorityqueue.LuaQueue.AddBackendName("test")

	go func() {
		req := priorityqueue.LuaQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LuaCommandDeleteTOTPRecoveryCodes, req.Command)

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{}
			}
		}
	}()

	err := lm.DeleteTOTPRecoveryCodes(auth)
	assert.NoError(t, err)
}
