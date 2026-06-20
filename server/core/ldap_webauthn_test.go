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

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/go-ldap/ldap/v3"
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

// newLDAPWebAuthnTestProtocol returns the common LDAP WebAuthn protocol fixture.
func newLDAPWebAuthnTestProtocol() *config.LDAPSearchProtocol {
	return &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
			WebAuthnObjectClass:     "nauthilusFido2Account",
		},
		BaseDN: "dc=example,dc=com",
		Scope:  "sub",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
	}
}

// newLDAPWebAuthnTestManager creates a manager, deps, and mock config for WebAuthn LDAP tests.
func newLDAPWebAuthnTestManager(poolName string, protocolName string) (*ldapManagerImpl, AuthDeps, *mockConfig) {
	protocol := newLDAPWebAuthnTestProtocol()
	mcfg := new(mockConfig)
	mcfg.On("GetLDAPSearchProtocol", protocolName, poolName).Return(protocol, nil)

	deps := AuthDeps{Cfg: mcfg}
	lm := &ldapManagerImpl{
		poolName: poolName,
		deps:     deps,
	}

	priorityqueue.LDAPQueue.AddPoolName(poolName)

	return lm, deps, mcfg
}

// newLDAPWebAuthnTestAuth creates an AuthState with an optional request protocol.
func newLDAPWebAuthnTestAuth(deps AuthDeps, protocolName string) *AuthState {
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username:          "jdoe",
			HTTPClientRequest: req,
		},
	}

	if protocolName != "" {
		auth.Request.Protocol = new(config.Protocol)
		auth.Request.Protocol.Set(protocolName)
	}

	return auth
}

// newLDAPWebAuthnTestCredential returns a credential and its JSON representation.
func newLDAPWebAuthnTestCredential(t *testing.T, name string) (mfa.PersistentCredential, string) {
	t.Helper()

	cred := mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("test-id"),
		},
		Name: name,
	}
	credJSON, err := json.Marshal(cred)
	assert.NoError(t, err)

	return cred, string(credJSON)
}

// replyLDAPWebAuthnObjectClassSearch acknowledges the initial objectClass search.
func replyLDAPWebAuthnObjectClassSearch(t *testing.T, poolName string) {
	t.Helper()

	req := priorityqueue.LDAPQueue.Pop(poolName)
	if req == nil {
		return
	}

	assert.Equal(t, definitions.LDAPSearch, req.Command)
	assert.Equal(t, []string{"objectClass"}, req.SearchAttributes)

	if req.LDAPReplyChan != nil {
		req.LDAPReplyChan <- &bktype.LDAPReply{
			Result: bktype.AttributeMapping{
				"objectClass": {"inetOrgPerson"},
			},
		}
	}
}

// replyLDAPWebAuthnObjectClassAdd acknowledges adding the WebAuthn objectClass.
func replyLDAPWebAuthnObjectClassAdd(t *testing.T, poolName string) {
	t.Helper()

	req := priorityqueue.LDAPQueue.Pop(poolName)
	if req == nil {
		return
	}

	assert.Equal(t, definitions.LDAPModify, req.Command)
	assert.Equal(t, definitions.LDAPModifyAdd, req.SubCommand)
	assert.Equal(t, []string{"nauthilusFido2Account"}, req.ModifyAttributes["objectClass"])

	if req.LDAPReplyChan != nil {
		req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
	}
}

func TestLDAPGetWebAuthnCredentials(t *testing.T) {
	protocol := &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
			WebAuthnObjectClass:     "nauthilusFido2Account",
		},
		BaseDN: "dc=example,dc=com",
		Scope:  "sub",
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
		Name: "Test Key",
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

func TestLDAPGetWebAuthnCredentialsDefaultsProtocol(t *testing.T) {
	protocol := &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
			WebAuthnObjectClass:     "nauthilusFido2Account",
		},
		BaseDN: "dc=example,dc=com",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
	}
	mcfg := new(mockConfig)
	mcfg.On("GetLDAPSearchProtocol", definitions.ProtoIDP, "test").Return(protocol, nil)

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
		Name: "Test Key",
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

func TestLDAPGetWebAuthnCredentialsNilProtocolDefaults(t *testing.T) {
	protocol := &config.LDAPSearchProtocol{
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			WebAuthnCredentialField: "nauthilusFido2Credential",
			WebAuthnObjectClass:     "nauthilusFido2Account",
		},
		BaseDN: "dc=example,dc=com",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
	}
	mcfg := new(mockConfig)
	mcfg.On("GetLDAPSearchProtocol", definitions.ProtoIDP, "test").Return(protocol, nil)

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
		Name: "Test Key",
	}
	credJSON, _ := json.Marshal(cred)

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			Username:          "jdoe",
			HTTPClientRequest: req,
		},
	}

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

func TestLDAPGetWebAuthnCredentialsDefaultsPoolName(t *testing.T) {
	defaultPoolName := definitions.DefaultBackendName
	_, deps, _ := newLDAPWebAuthnTestManager(defaultPoolName, mock.Anything)
	manager := NewLDAPManager("", deps)
	lm := manager.(*ldapManagerImpl)

	_, credJSON := newLDAPWebAuthnTestCredential(t, "Test Key")
	auth := newLDAPWebAuthnTestAuth(deps, "oidc")

	poolNameChan := make(chan string, 1)

	go func() {
		popCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		ldapReq := priorityqueue.LDAPQueue.PopWithContext(popCtx, defaultPoolName)
		if ldapReq == nil {
			poolNameChan <- ""

			return
		}

		poolNameChan <- ldapReq.PoolName

		if ldapReq.LDAPReplyChan != nil {
			ldapReq.LDAPReplyChan <- &bktype.LDAPReply{
				Result: bktype.AttributeMapping{
					"nauthilusFido2Credential": {credJSON},
				},
			}
		}
	}()

	credentials, err := lm.GetWebAuthnCredentials(auth)
	assert.NoError(t, err)
	assert.Len(t, credentials, 1)
	assert.Equal(t, defaultPoolName, <-poolNameChan)
}

func TestLDAPSaveWebAuthnCredential(t *testing.T) {
	lm, deps, _ := newLDAPWebAuthnTestManager("test", "oidc")
	credValue, _ := newLDAPWebAuthnTestCredential(t, "Test Key")
	cred := &credValue
	auth := newLDAPWebAuthnTestAuth(deps, "oidc")

	go func() {
		replyLDAPWebAuthnObjectClassSearch(t, "test")
		replyLDAPWebAuthnObjectClassAdd(t, "test")

		req := priorityqueue.LDAPQueue.Pop("test")
		if req != nil {
			assert.Equal(t, definitions.LDAPModify, req.Command)
			assert.Equal(t, definitions.LDAPModifyAdd, req.SubCommand)
			assert.Contains(t, req.ModifyAttributes, "nauthilusFido2Credential")

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
			WebAuthnObjectClass:     "nauthilusFido2Account",
		},
		BaseDN: "dc=example,dc=com",
		Scope:  "sub",
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
		Name: "Test Key",
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
		assertLDAPWebAuthnCredentialModifyRequest(t, req, definitions.LDAPModifyDelete)
	}()

	err := lm.DeleteWebAuthnCredential(auth, cred)
	assert.NoError(t, err)
}

func TestLDAPUpdateWebAuthnCredential(t *testing.T) {
	lm, deps, _ := newLDAPWebAuthnTestManager("test", "oidc")
	oldCredValue, _ := newLDAPWebAuthnTestCredential(t, "Old Key")
	newCredValue, _ := newLDAPWebAuthnTestCredential(t, "New Key")
	oldCred := &oldCredValue
	newCred := &newCredValue
	auth := newLDAPWebAuthnTestAuth(deps, "oidc")

	go func() {
		replyLDAPWebAuthnObjectClassSearch(t, "test")
		replyLDAPWebAuthnObjectClassAdd(t, "test")

		req := priorityqueue.LDAPQueue.Pop("test")
		assertLDAPWebAuthnCredentialModifyRequest(t, req, definitions.LDAPModifyAdd)

		req = priorityqueue.LDAPQueue.Pop("test")
		assertLDAPWebAuthnCredentialModifyRequest(t, req, definitions.LDAPModifyDelete)
	}()

	err := lm.UpdateWebAuthnCredential(auth, oldCred, newCred)
	assert.NoError(t, err)
}

// assertLDAPWebAuthnCredentialModifyRequest verifies and acknowledges one credential modify request.
func assertLDAPWebAuthnCredentialModifyRequest(t *testing.T, req *bktype.LDAPRequest, subCommand definitions.LDAPSubCommand) {
	t.Helper()

	if req == nil {
		return
	}

	assert.Equal(t, definitions.LDAPModify, req.Command)
	assert.Equal(t, subCommand, req.SubCommand)
	assert.Equal(t, ldap.ScopeWholeSubtree, req.Scope.Get())
	_, hasObjectClass := req.ModifyAttributes[ldapAttributeObjectClass]
	assert.False(t, hasObjectClass)

	if req.LDAPReplyChan != nil {
		req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
	}
}
