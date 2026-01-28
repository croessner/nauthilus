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
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockConfig struct {
	mock.Mock
	config.File
}

func (m *mockConfig) GetLDAPSearchProtocol(protocol string, poolName string) (*config.LDAPSearchProtocol, error) {
	args := m.Called(protocol, poolName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*config.LDAPSearchProtocol), args.Error(1)
}

func (m *mockConfig) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Timeouts: config.Timeouts{
			LDAPSearch: 2 * time.Second,
			LDAPModify: 2 * time.Second,
		},
	}
}

func TestLDAPGetWebAuthnCredentials(t *testing.T) {
	protocol := &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
		},
		BaseDN: "dc=example,dc=com",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
	}
	mcfg := new(mockConfig)
	mcfg.On("GetLDAPSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &ldapManagerImpl{
		poolName: "test",
		deps:     deps,
	}

	priorityqueue.LDAPQueue.AddPoolName("test")

	cred := mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
	}
	credJSON, _ := json.Marshal(cred)

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username:          "jdoe",
			Protocol:          new(config.Protocol),
			HTTPClientRequest: req,
		},
	}
	auth.Request.Protocol.Set("oidc")

	go func() {
		req := priorityqueue.LDAPQueue.Pop("test")
		if req != nil && req.LDAPReplyChan != nil {
			req.LDAPReplyChan <- &bktype.LDAPReply{
				Result: bktype.AttributeMapping{
					"nauthilusFido2Credential": {string(credJSON)},
				},
			}
		}
	}()

	credentials, err := lm.GetWebAuthnCredentials(auth)
	assert.NoError(t, err)
	assert.Len(t, credentials, 1)
	assert.Equal(t, cred.ID, credentials[0].ID)
}

func TestLDAPSaveWebAuthnCredential(t *testing.T) {
	protocol := &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
		},
		BaseDN: "dc=example,dc=com",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
	}
	mcfg := new(mockConfig)
	mcfg.On("GetLDAPSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &ldapManagerImpl{
		poolName: "test",
		deps:     deps,
	}

	priorityqueue.LDAPQueue.AddPoolName("test")

	cred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
	}

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username:          "jdoe",
			Protocol:          new(config.Protocol),
			HTTPClientRequest: req,
		},
	}
	auth.Request.Protocol.Set("oidc")

	go func() {
		req := priorityqueue.LDAPQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LDAPModify, req.Command)
			assert.Equal(t, definitions.LDAPModifyAdd, req.SubCommand)
			if req.LDAPReplyChan != nil {
				req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
			}
		}
	}()

	err := lm.SaveWebAuthnCredential(auth, cred)
	assert.NoError(t, err)
}

func TestLDAPDeleteWebAuthnCredential(t *testing.T) {
	protocol := &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
		},
		BaseDN: "dc=example,dc=com",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
	}
	mcfg := new(mockConfig)
	mcfg.On("GetLDAPSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &ldapManagerImpl{
		poolName: "test",
		deps:     deps,
	}

	priorityqueue.LDAPQueue.AddPoolName("test")

	cred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
	}

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username:          "jdoe",
			Protocol:          new(config.Protocol),
			HTTPClientRequest: req,
		},
	}
	auth.Request.Protocol.Set("oidc")

	go func() {
		req := priorityqueue.LDAPQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LDAPModify, req.Command)
			assert.Equal(t, definitions.LDAPModifyDelete, req.SubCommand)
			if req.LDAPReplyChan != nil {
				req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
			}
		}
	}()

	err := lm.DeleteWebAuthnCredential(auth, cred)
	assert.NoError(t, err)
}

func TestLDAPUpdateWebAuthnCredential(t *testing.T) {
	protocol := &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
		},
		BaseDN: "dc=example,dc=com",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
	}
	mcfg := new(mockConfig)
	mcfg.On("GetLDAPSearchProtocol", mock.Anything, "test").Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &ldapManagerImpl{
		poolName: "test",
		deps:     deps,
	}

	priorityqueue.LDAPQueue.AddPoolName("test")

	oldCred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
	}
	newCred := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
	}

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username:          "jdoe",
			Protocol:          new(config.Protocol),
			HTTPClientRequest: req,
		},
	}
	auth.Request.Protocol.Set("oidc")

	go func() {
		// First: Delete old credential
		req := priorityqueue.LDAPQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LDAPModify, req.Command)
			assert.Equal(t, definitions.LDAPModifyDelete, req.SubCommand)
			if req.LDAPReplyChan != nil {
				req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
			}
		}

		// Second: Add new credential
		req = priorityqueue.LDAPQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LDAPModify, req.Command)
			assert.Equal(t, definitions.LDAPModifyAdd, req.SubCommand)
			if req.LDAPReplyChan != nil {
				req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
			}
		}
	}()

	err := lm.UpdateWebAuthnCredential(auth, oldCred, newCred)
	assert.NoError(t, err)
}
