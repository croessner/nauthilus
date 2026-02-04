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
	"testing"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/rediscli"
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

func TestNauthilusIdP_Authenticate_Integration(t *testing.T) {
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
	idp := NewNauthilusIdP(d)

	t.Run("OIDC Authentication Flow Setup", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest("POST", "/login", nil)
		ctx.Request.RemoteAddr = "192.168.1.100:12345"
		setupMockContext(ctx, "test-oidc-guid", definitions.ServIdP)

		// Mock Redis lookup for user account
		userKey := "test:user:{55}" // Shard for user1 with prefix test:
		mock.ExpectHGet(userKey, "user1|oidc|client1").RedisNil()

		// We expect authentication to fail because no backends are configured,
		// but we want to ensure it reaches the HandlePassword stage.
		user, err := idp.Authenticate(ctx, "user1", "pass1", "client1", "")

		assert.Error(t, err)
		assert.Nil(t, user)
		// AuthResultFail is typical when no backends are found or configured
		assert.Contains(t, err.Error(), "authentication failed with result")
	})

	t.Run("SAML Authentication Flow Setup", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest("POST", "/login", nil)
		ctx.Request.RemoteAddr = "192.168.1.101:54321"
		setupMockContext(ctx, "test-saml-guid", definitions.ServIdP)

		// Mock Redis lookup for user account
		userKey := "test:user:{ef}" // Shard for user2 with prefix test:
		mock.ExpectHGet(userKey, "user2|saml|").RedisNil()

		user, err := idp.Authenticate(ctx, "user2", "pass2", "", "sp1")

		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "authentication failed with result")
	})

	t.Run("GetUserByUsername Setup", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest("GET", "/user", nil)
		setupMockContext(ctx, "test-getuser-guid", definitions.ServIdP)

		user, err := idp.GetUserByUsername(ctx, "user3", "client1", "")

		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "failed to load user")
	})
}
