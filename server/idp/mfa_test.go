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

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	_ "github.com/croessner/nauthilus/server/core/auth"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/security"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func setupMfaMockContext(ctx *gin.Context, guid, service string) {
	ctx.Set(definitions.CtxGUIDKey, guid)
	ctx.Set(definitions.CtxServiceKey, service)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
}

const (
	mfaLDAPTestUser       = "testuser"
	mfaLDAPUIDAttr        = "uid"
	mfaLDAPRecoveryAttr   = "nauthilusRecoveryCode"
	mfaLDAPTOTPSecretAttr = "nauthilusTotpSecret"
)

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
	username := mfaLDAPTestUser

	secret, qrURL, err := s.GenerateTOTPSecret(ctx, username)

	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, qrURL, "otpauth://totp/NauthilusTest:"+mfaLDAPTestUser)
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
						AccountField:    mfaLDAPUIDAttr,
						TOTPSecretField: mfaLDAPTOTPSecretAttr,
					},
					Attributes: []string{mfaLDAPUIDAttr},
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

			encryptedSecret := req.ModifyAttributes[mfaLDAPTOTPSecretAttr][0]
			securityManager := security.NewManager(encryptionSecret)
			decryptedSecret, decryptErr := securityManager.Decrypt(encryptedSecret)
			assert.NoError(t, decryptErr)
			assert.Equal(t, secret, decryptedSecret)

			req.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
		}
	}()

	err = s.VerifyAndSaveTOTP(ctx, mfaLDAPTestUser, secret, code, uint8(definitions.BackendLDAP))
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
						AccountField:    mfaLDAPUIDAttr,
						TOTPSecretField: mfaLDAPTOTPSecretAttr,
					},
					Attributes: []string{mfaLDAPUIDAttr},
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

	err := s.DeleteTOTP(ctx, mfaLDAPTestUser, uint8(definitions.BackendLDAP))
	assert.NoError(t, err)
}

func TestMFAService_GenerateRecoveryCodesLDAPContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newMFALDAPFixture(t)
	requestCh := fixture.replyToNextLDAPModify()

	codes, err := fixture.service.GenerateRecoveryCodes(fixture.ctx, mfaLDAPTestUser, uint8(definitions.BackendLDAP))
	assert.NoError(t, err)
	assert.Len(t, codes, core.DefaultNumberOfBackupCodes)

	request := fixture.nextRequest(t, requestCh)
	assert.Equal(t, definitions.LDAPModify, request.Command)
	assert.Equal(t, definitions.LDAPModifyReplace, request.SubCommand)
	assert.Equal(t, codes, fixture.decryptValues(t, request.ModifyAttributes[mfaLDAPRecoveryAttr]))
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestMFAService_SaveRecoveryCodesLDAPContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newMFALDAPFixture(t)
	requestCh := fixture.replyToNextLDAPModify()
	codes := []string{"alpha-1", "bravo-2", "charlie-3"}

	err := fixture.service.SaveRecoveryCodes(fixture.ctx, mfaLDAPTestUser, codes, uint8(definitions.BackendLDAP))
	assert.NoError(t, err)

	request := fixture.nextRequest(t, requestCh)
	assert.Equal(t, definitions.LDAPModify, request.Command)
	assert.Equal(t, definitions.LDAPModifyReplace, request.SubCommand)
	assert.Equal(t, codes, fixture.decryptValues(t, request.ModifyAttributes[mfaLDAPRecoveryAttr]))
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestMFAService_UseRecoveryCodeConsumesOnlyMatchingCodeLDAPContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newMFALDAPFixture(t)
	fixture.expectAccountMapping(mfaLDAPTestUser, definitions.ProtoIDP, mfaLDAPTestUser)
	fixture.expectAccountMapping(mfaLDAPTestUser, definitions.ProtoIDP, mfaLDAPTestUser)
	requestCh := fixture.replyToNextLDAPSearchAndModify(
		bktype.AttributeMapping{
			definitions.DistinguishedName: {"uid=testuser,ou=users,dc=example,dc=com"},
			mfaLDAPUIDAttr:                {mfaLDAPTestUser},
			mfaLDAPRecoveryAttr: {
				fixture.encrypt(t, "keep-1"),
				fixture.encrypt(t, "use-me"),
				fixture.encrypt(t, "keep-2"),
			},
		},
	)

	valid, err := fixture.service.UseRecoveryCode(fixture.ctx, mfaLDAPTestUser, "use-me", uint8(definitions.BackendLDAP))
	assert.NoError(t, err)
	assert.True(t, valid)

	request := fixture.nextRequest(t, requestCh)
	assert.Equal(t, definitions.LDAPModify, request.Command)
	assert.Equal(t, definitions.LDAPModifyReplace, request.SubCommand)
	assert.Equal(t, []string{"keep-1", "keep-2"}, fixture.decryptValues(t, request.ModifyAttributes[mfaLDAPRecoveryAttr]))
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

type mfaLDAPFixture struct {
	securityManager *security.Manager
	service         *MFAService
	ctx             *gin.Context
	cfg             *config.FileSettings
	mock            redismock.ClientMock
	poolName        string
}

func newMFALDAPFixture(t *testing.T) *mfaLDAPFixture {
	t.Helper()

	encryptionSecret := secret.New("testsecret12345678")
	cfg := newMFALDAPConfig(t, encryptionSecret)
	env := config.NewTestEnvironmentConfig()
	configureMFAGlobals(cfg, env)

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	priorityqueue.LDAPQueue.AddPoolName(definitions.DefaultBackendName)

	return &mfaLDAPFixture{
		securityManager: security.NewManager(encryptionSecret),
		service:         NewMFAService(newMFATestDeps(cfg, env, redisClient)),
		ctx:             newMFATestContext(),
		cfg:             cfg,
		mock:            mock,
		poolName:        definitions.DefaultBackendName,
	}
}

func newMFALDAPConfig(t *testing.T, encryptionSecret secret.Value) *config.FileSettings {
	t.Helper()

	backend := newMFALDAPBackend(t)

	return &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "baseline:",
			},
			Timeouts: config.Timeouts{
				LDAPSearch: time.Second,
				LDAPModify: time.Second,
				RedisRead:  time.Second,
				RedisWrite: time.Second,
			},
			Backends: []*config.Backend{backend},
		},
		LDAP: &config.LDAPSection{
			Config: &config.LDAPConf{
				EncryptionSecret: encryptionSecret,
			},
			Search: []config.LDAPSearchProtocol{
				newMFALDAPSearch(),
			},
		},
	}
}

func newMFALDAPBackend(t *testing.T) *config.Backend {
	t.Helper()

	backend := &config.Backend{}

	if err := backend.Set("ldap"); err != nil {
		t.Fatalf("backend.Set failed: %v", err)
	}

	return backend
}

func newMFALDAPSearch() config.LDAPSearchProtocol {
	return config.LDAPSearchProtocol{
		Protocols: []string{definitions.ProtoIDP},
		CacheName: "idp",
		PoolName:  definitions.DefaultBackendName,
		BaseDN:    "ou=users,dc=example,dc=com",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			AccountField:      mfaLDAPUIDAttr,
			TOTPSecretField:   mfaLDAPTOTPSecretAttr,
			TOTPRecoveryField: mfaLDAPRecoveryAttr,
		},
		Attributes: []string{mfaLDAPUIDAttr, mfaLDAPRecoveryAttr},
	}
}

func configureMFAGlobals(cfg *config.FileSettings, env config.Environment) {
	config.SetTestEnvironmentConfig(env)
	config.SetTestFile(cfg)
	core.InitPassDBResultPool()
	core.SetDefaultConfigFile(cfg)
	core.SetDefaultLogger(log.GetLogger())
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultLogger(log.GetLogger())
	util.SetDefaultEnvironment(env)
}

func newMFATestDeps(cfg *config.FileSettings, env config.Environment, redisClient rediscli.Client) *deps.Deps {
	return &deps.Deps{
		Cfg:          cfg,
		Env:          env,
		Logger:       log.GetLogger(),
		Redis:        redisClient,
		AccountCache: accountcache.NewManager(cfg),
	}
}

func newMFATestContext() *gin.Context {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/", strings.NewReader("{}"))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.RemoteAddr = "127.0.0.1:12345"
	setupMfaMockContext(ctx, "baseline-mfa-guid", definitions.ServIdP)

	return ctx
}

func (f *mfaLDAPFixture) expectAccountMapping(username, protocol, account string) {
	key := rediscli.GetUserHashKey(f.cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	f.mock.ExpectHGet(key, field).RedisNil()
	f.mock.ExpectHSet(key, field, account).SetVal(1)
}

func (f *mfaLDAPFixture) replyToNextLDAPModify() <-chan *bktype.LDAPRequest {
	requestCh := make(chan *bktype.LDAPRequest, 1)

	go func() {
		request := priorityqueue.LDAPQueue.Pop(f.poolName)
		requestCh <- request

		request.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
	}()

	return requestCh
}

func (f *mfaLDAPFixture) replyToNextLDAPSearchAndModify(searchReply bktype.AttributeMapping) <-chan *bktype.LDAPRequest {
	requestCh := make(chan *bktype.LDAPRequest, 1)

	go func() {
		searchRequest := priorityqueue.LDAPQueue.Pop(f.poolName)
		searchRequest.LDAPReplyChan <- &bktype.LDAPReply{Result: searchReply}

		modifyRequest := priorityqueue.LDAPQueue.Pop(f.poolName)
		requestCh <- modifyRequest

		modifyRequest.LDAPReplyChan <- &bktype.LDAPReply{Err: nil}
	}()

	return requestCh
}

func (f *mfaLDAPFixture) encrypt(t *testing.T, value string) string {
	t.Helper()

	encrypted, err := f.securityManager.Encrypt(value)
	if err != nil {
		t.Fatalf("failed to encrypt %q: %v", value, err)
	}

	return encrypted
}

func (f *mfaLDAPFixture) decryptValues(t *testing.T, values []string) []string {
	t.Helper()

	decrypted := make([]string, 0, len(values))
	for _, value := range values {
		plain, err := f.securityManager.Decrypt(value)
		if err != nil {
			t.Fatalf("failed to decrypt recovery code: %v", err)
		}

		decrypted = append(decrypted, plain)
	}

	return decrypted
}

func (f *mfaLDAPFixture) nextRequest(t *testing.T, requestCh <-chan *bktype.LDAPRequest) *bktype.LDAPRequest {
	t.Helper()

	select {
	case request := <-requestCh:
		if request == nil {
			t.Fatal("expected LDAP request, got nil")
		}

		return request
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LDAP request")
	}

	return nil
}
