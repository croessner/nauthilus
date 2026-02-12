// Copyright (C) 2025 Christian Rößner
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
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func TestLuaGetWebAuthnCredentials(t *testing.T) {
	mcfg := new(mockConfig)
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	mcfg.On("GetServer").Return(&config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	})

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	cred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
		Name: "Test Key",
	}
	credBytes, err := json.Marshal(cred)
	assert.NoError(t, err)

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
			assert.Equal(t, definitions.LuaCommandGetWebAuthnCredentials, req.Command)

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{
					WebAuthnCredentials: []string{string(credBytes)},
				}
			}
		}
	}()

	credentials, err := lm.GetWebAuthnCredentials(auth)
	assert.NoError(t, err)
	assert.Len(t, credentials, 1)
	assert.True(t, bytes.Equal(cred.ID, credentials[0].ID))
	assert.Equal(t, cred.Name, credentials[0].Name)
}

func TestLuaSaveWebAuthnCredential(t *testing.T) {
	mcfg := new(mockConfig)
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	mcfg.On("GetServer").Return(&config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	})

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	cred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
		Name: "Test Key",
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
			assert.Equal(t, definitions.LuaCommandSaveWebAuthnCredential, req.Command)
			assert.NotEmpty(t, req.WebAuthnCredential)

			var credPopped webauthn.Credential
			_ = json.Unmarshal([]byte(req.WebAuthnCredential), &credPopped)
			assert.True(t, bytes.Equal(cred.ID, credPopped.ID))

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{Err: nil}
			}
		}
	}()

	err := lm.SaveWebAuthnCredential(auth, cred)
	assert.NoError(t, err)
}

func TestLuaDeleteWebAuthnCredential(t *testing.T) {
	mcfg := new(mockConfig)
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	mcfg.On("GetServer").Return(&config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	})

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	cred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
		Name: "Test Key",
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
			assert.Equal(t, definitions.LuaCommandDeleteWebAuthnCredential, req.Command)
			assert.NotEmpty(t, req.WebAuthnCredential)

			var credPopped webauthn.Credential
			_ = json.Unmarshal([]byte(req.WebAuthnCredential), &credPopped)
			assert.True(t, bytes.Equal(cred.ID, credPopped.ID))

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{Err: nil}
			}
		}
	}()

	err := lm.DeleteWebAuthnCredential(auth, cred)
	assert.NoError(t, err)
}

func TestLuaUpdateWebAuthnCredential(t *testing.T) {
	mcfg := new(mockConfig)
	var verbosity config.Verbosity
	_ = verbosity.Set("debug")

	mcfg.On("GetServer").Return(&config.ServerSection{
		Timeouts: config.Timeouts{
			LuaBackend: 2 * time.Second,
		},
		Log: config.Log{
			Level: verbosity,
		},
	})

	deps := AuthDeps{Cfg: mcfg}
	lm := &luaManagerImpl{
		backendName: "test",
		deps:        deps,
	}

	oldCred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("old-id"),
		},
		Name: "Old Key",
	}
	newCred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("new-id"),
		},
		Name: "New Key",
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

	priorityqueue.LuaQueue.AddBackendName("test")

	go func() {
		req := priorityqueue.LuaQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LuaCommandUpdateWebAuthnCredential, req.Command)
			assert.NotEmpty(t, req.WebAuthnCredential)
			assert.NotEmpty(t, req.WebAuthnOldCredential)

			var oldCredPopped webauthn.Credential
			var newCredPopped webauthn.Credential
			_ = json.Unmarshal([]byte(req.WebAuthnOldCredential), &oldCredPopped)
			_ = json.Unmarshal([]byte(req.WebAuthnCredential), &newCredPopped)
			assert.True(t, bytes.Equal(oldCred.ID, oldCredPopped.ID))
			assert.True(t, bytes.Equal(newCred.ID, newCredPopped.ID))

			if req.LuaReplyChan != nil {
				req.LuaReplyChan <- &lualib.LuaBackendResult{Err: nil}
			}
		}
	}()

	err := lm.UpdateWebAuthnCredential(auth, oldCred, newCred)
	assert.NoError(t, err)
}
