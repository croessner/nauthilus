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
	"os"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// Provide a minimal test configuration to avoid panics from core.getDefault...
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(cfg)

	// Setup log
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
	core.SetDefaultLogger(log.GetLogger())
	core.SetDefaultConfigFile(cfg)
	core.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	core.InitPassDBResultPool()
	os.Exit(m.Run())
}

func setupMockContext(ctx *gin.Context, guid, service string) {
	ctx.Set(definitions.CtxGUIDKey, guid)
	ctx.Set(definitions.CtxServiceKey, service)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
}

func TestPrepareUserLookupAuthStateKeepsExplicitUsername(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	body := strings.NewReader("username=target%40example.test%2Amaster%40example.test&password=secret")
	ctx.Request = httptest.NewRequest("POST", "/login", body)
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setupMockContext(ctx, "test-lookup-username-guid", definitions.ServIDP)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: testRedisPrefix,
			},
		},
	}
	db, _ := redismock.NewClientMock()
	authRaw := core.NewAuthStateFromContextWithDeps(ctx, (&deps.Deps{
		Cfg:          cfg,
		Redis:        rediscli.NewTestClient(db),
		AccountCache: accountcache.NewManager(cfg),
	}).Auth())
	authState := authRaw.(*core.AuthState)

	prepareUserLookupAuthState(ctx, authState, "master@example.test", "client1", "", nil)

	assert.Equal(t, "master@example.test", authState.GetUsername())
	assert.True(t, authState.Request.NoAuth)
}

func TestNauthilusIDP_Authenticate_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "test:",
			},
		},
	}

	d := &deps.Deps{
		Cfg:          cfg,
		Redis:        redisClient,
		AccountCache: accountcache.NewManager(cfg),
	}
	idp := NewNauthilusIDP(d)

	for _, tc := range authIntegrationFlowCases() {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthIntegrationFlow(t, idp, mock, tc)
		})
	}

	t.Run("GetUserByUsername Setup", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest("GET", "/user", nil)
		setupMockContext(ctx, "test-getuser-guid", definitions.ServIDP)

		user, err := idp.GetUserByUsername(ctx, "user3", "client1", "")

		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "failed to load user")
	})
}

type authIntegrationFlowCase struct {
	name              string
	guid              string
	remoteAddr        string
	redisKey          string
	redisField        string
	username          string
	password          string
	clientID          string
	serviceProviderID string
}

func authIntegrationFlowCases() []authIntegrationFlowCase {
	return []authIntegrationFlowCase{
		{
			name:       "OIDC Authentication Flow Setup",
			guid:       "test-oidc-guid",
			remoteAddr: "192.168.1.100:12345",
			redisKey:   "test:user:{55}",
			redisField: "user1|oidc|client1",
			username:   "user1",
			password:   "pass1",
			clientID:   "client1",
		},
		{
			name:              "SAML Authentication Flow Setup",
			guid:              "test-saml-guid",
			remoteAddr:        "192.168.1.101:54321",
			redisKey:          "test:user:{ef}",
			redisField:        "user2|saml|",
			username:          "user2",
			password:          "pass2",
			serviceProviderID: "sp1",
		},
	}
}

// assertAuthIntegrationFlow checks that an integration login reaches password handling.
func assertAuthIntegrationFlow(t *testing.T, idp *NauthilusIDP, mock redismock.ClientMock, tc authIntegrationFlowCase) {
	t.Helper()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/login", nil)
	ctx.Request.RemoteAddr = tc.remoteAddr
	setupMockContext(ctx, tc.guid, definitions.ServIDP)

	mock.ExpectHGet(tc.redisKey, tc.redisField).RedisNil()

	// Authentication is expected to fail because this test intentionally omits backends.
	user, err := idp.Authenticate(ctx, tc.username, tc.password, tc.clientID, tc.serviceProviderID)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "authentication failed with result")
}
