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

package idp

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/security"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func setupMfaMockContext(ctx *gin.Context, guid, service string) {
	ctx.Set(definitions.CtxGUIDKey, guid)
	ctx.Set(definitions.CtxServiceKey, service)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
}

func TestMFAService_GenerateTOTPSecret(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				TotpIssuer: "NauthilusTest",
			},
		},
	}

	d := &deps.Deps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
	}
	s := NewMFAService(d)

	ctx, _ := gin.CreateTestContext(nil)
	username := "testuser"

	secret, qrURL, err := s.GenerateTOTPSecret(ctx, username)

	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, qrURL, "otpauth://totp/NauthilusTest:testuser")
	assert.Contains(t, qrURL, "secret="+secret)
	assert.Contains(t, qrURL, "issuer=NauthilusTest")
}

func TestMFAService_VerifyAndSaveTOTP_LDAP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	backend := &config.Backend{}
	_ = backend.Set("ldap")
	encryptionSecret := secret.New("testsecret12345678")

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Backends: []*config.Backend{backend},
		},
		LDAP: &config.LDAPSection{
			Config: &config.LDAPConf{
				EncryptionSecret: encryptionSecret,
			},
			Search: []config.LDAPSearchProtocol{
				{
					Protocols: []string{"idp"},
					CacheName: "idp",
					BaseDN:    "ou=users,dc=example,dc=com",
					LDAPFilter: config.LDAPFilter{
						User: "(uid=%s)",
					},
					LDAPAttributeMapping: config.LDAPAttributeMapping{
						AccountField:    "uid",
						TOTPSecretField: "nauthilusTotpSecret",
					},
					Attributes: []string{"uid"},
					PoolName:   definitions.DefaultBackendName,
				},
			},
		},
	}

	d := &deps.Deps{
		Cfg:    cfg,
		Env:    config.NewTestEnvironmentConfig(),
		Logger: log.GetLogger(),
	}
	s := NewMFAService(d)

	secret := "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/", strings.NewReader("{}"))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.RemoteAddr = "127.0.0.1:12345"
	setupMfaMockContext(ctx, "test-guid", definitions.ServIdP)

	priorityqueue.LDAPQueue.AddPoolName(definitions.DefaultBackendName)

	go func() {
		req := priorityqueue.LDAPQueue.Pop(definitions.DefaultBackendName)
		if req != nil {
			assert.Equal(t, definitions.LDAPModify, req.Command)

			encryptedSecret := req.ModifyAttributes["nauthilusTotpSecret"][0]
			securityManager := security.NewManager(encryptionSecret)
			decryptedSecret, decryptErr := securityManager.Decrypt(encryptedSecret)
			assert.NoError(t, decryptErr)
			assert.Equal(t, secret, decryptedSecret)

			req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
		}
	}()

	err = s.VerifyAndSaveTOTP(ctx, "testuser", secret, code, uint8(definitions.BackendLDAP))
	assert.NoError(t, err)
}

func TestMFAService_DeleteTOTP_LDAP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	backend := &config.Backend{}
	_ = backend.Set("ldap")
	encryptionSecret := secret.New("testsecret12345678")

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Backends: []*config.Backend{backend},
		},
		LDAP: &config.LDAPSection{
			Config: &config.LDAPConf{
				EncryptionSecret: encryptionSecret,
			},
			Search: []config.LDAPSearchProtocol{
				{
					Protocols: []string{"idp"},
					CacheName: "idp",
					BaseDN:    "ou=users,dc=example,dc=com",
					LDAPFilter: config.LDAPFilter{
						User: "(uid=%s)",
					},
					LDAPAttributeMapping: config.LDAPAttributeMapping{
						AccountField:    "uid",
						TOTPSecretField: "nauthilusTotpSecret",
					},
					Attributes: []string{"uid"},
					PoolName:   definitions.DefaultBackendName,
				},
			},
		},
	}

	d := &deps.Deps{
		Cfg:    cfg,
		Env:    config.NewTestEnvironmentConfig(),
		Logger: log.GetLogger(),
	}
	s := NewMFAService(d)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/", strings.NewReader("{}"))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.RemoteAddr = "127.0.0.1:12345"
	setupMfaMockContext(ctx, "test-guid", definitions.ServIdP)

	priorityqueue.LDAPQueue.AddPoolName(definitions.DefaultBackendName)

	go func() {
		req := priorityqueue.LDAPQueue.Pop(definitions.DefaultBackendName)
		if req != nil {
			assert.Equal(t, definitions.LDAPModify, req.Command)
			assert.Equal(t, definitions.LDAPModifyDelete, req.SubCommand)
			req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
		}
	}()

	err := s.DeleteTOTP(ctx, "testuser", uint8(definitions.BackendLDAP))
	assert.NoError(t, err)
}
