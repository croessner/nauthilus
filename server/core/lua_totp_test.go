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

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
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

// setupLuaTOTPTest creates the common test fixtures for TOTP/recovery code tests.
func setupLuaTOTPTest(t *testing.T) (*luaManagerImpl, *AuthState) {
	t.Helper()

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

	return lm, auth
}

func TestLuaAddTOTPSecret(t *testing.T) {
	lm, auth := setupLuaTOTPTest(t)

	go func() {
		assertLuaTOTPQueueRequest(t, definitions.LuaCommandAddMFAValue, func(req *bktype.LuaRequest) {
			assert.Equal(t, "secret", req.TOTPSecret)
		})
	}()

	err := lm.AddTOTPSecret(auth, mfa.NewTOTPSecret("secret"))
	assert.NoError(t, err)
}

func TestLuaDeleteTOTPSecret(t *testing.T) {
	lm, auth := setupLuaTOTPTest(t)

	go func() {
		assertLuaTOTPQueueRequest(t, definitions.LuaCommandDeleteMFAValue, nil)
	}()

	err := lm.DeleteTOTPSecret(auth)
	assert.NoError(t, err)
}

func TestLuaAddTOTPRecoveryCodes(t *testing.T) {
	lm, auth := setupLuaTOTPTest(t)

	recovery := mfa.NewTOTPRecovery([]string{"code1", "code2"})

	go func() {
		assertLuaTOTPQueueRequest(t, definitions.LuaCommandAddTOTPRecoveryCodes, func(req *bktype.LuaRequest) {
			assert.NotNil(t, req.CommonRequest)
			assert.Equal(t, []string{"code1", "code2"}, req.TOTPRecoveryCodes)
		})
	}()

	err := lm.AddTOTPRecoveryCodes(auth, recovery)
	assert.NoError(t, err)
}

func TestLuaDeleteTOTPRecoveryCodes(t *testing.T) {
	lm, auth := setupLuaTOTPTest(t)

	go func() {
		assertLuaTOTPQueueRequest(t, definitions.LuaCommandDeleteTOTPRecoveryCodes, nil)
	}()

	err := lm.DeleteTOTPRecoveryCodes(auth)
	assert.NoError(t, err)
}

// assertLuaTOTPQueueRequest verifies and acknowledges one Lua MFA queue request.
func assertLuaTOTPQueueRequest(t *testing.T, command definitions.LuaCommand, assertRequest func(*bktype.LuaRequest)) {
	t.Helper()

	req := priorityqueue.LuaQueue.Pop("test")
	if req == nil {
		return
	}

	assert.Equal(t, command, req.Command)

	if assertRequest != nil {
		assertRequest(req)
	}

	if req.LuaReplyChan != nil {
		req.LuaReplyChan <- &lualib.LuaBackendResult{}
	}
}
