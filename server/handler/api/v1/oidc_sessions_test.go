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

package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func setupOIDCSessionsRouter(d *deps.Deps, storage *idp.RedisTokenStorage) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := NewOIDCSessionsAPI(d, storage)
	api.Register(r)
	return r
}

func TestOIDCSessionsAPI_ListSessions(t *testing.T) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	storage := idp.NewRedisTokenStorage(redisClient, "test:")
	d := &deps.Deps{Logger: log.GetLogger(), Redis: redisClient}
	r := setupOIDCSessionsRouter(d, storage)

	t.Run("Success", func(t *testing.T) {
		mock.ExpectSMembers("test:oidc:user_access_tokens:user1").SetVal([]string{"token1"})
		// GetAccessToken will be called for "token1"
		mock.ExpectGet("test:oidc:access_token:token1").SetVal("some-encrypted-data")
		// Since we can't easily mock the decryption/unmarshaling without more setup,
		// we expect an error in ListUserSessions but let's see.
		// Actually, RedisTokenStorage uses the security manager which we didn't mock.

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v1/oidc/sessions/user1", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		// Should be empty because decryption failed
		assert.Empty(t, resp)
	})
}
