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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// setupOIDCSessionsRouter builds the protected management route shape for OIDC sessions.
func setupOIDCSessionsRouter(d *deps.Deps, storage OIDCSessionStore, validator oidcbearer.TokenValidator) *gin.Engine {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(gin.Recovery())

	apiGroup := r.Group("/api/v1")
	apiGroup.Use(oidcbearer.Middleware(validator, d.Cfg, d.Logger))

	api := NewOIDCSessionsAPI(d, storage)
	api.Register(apiGroup)

	return r
}

func TestOIDCSessionsAPI_ListSessionsRequiresBackchannelAuth(t *testing.T) {
	storage := &oidcSessionsStorageSpy{}
	router := setupOIDCSessionsRouter(newOIDCSessionsTestDeps(nil), storage, newOIDCSessionsTokenValidator(""))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/sessions/user1", nil)

	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Equal(t, 0, storage.calls)
}

func TestOIDCSessionsAPI_ListSessionsSanitizesTokenKeys(t *testing.T) {
	const (
		userID       = "user1"
		sessionToken = "opaque-session-reference"
	)

	storage, mock := newOIDCSessionsRedisStorage(t)
	d := newOIDCSessionsTestDeps(storage.redis)
	router := setupOIDCSessionsRouter(d, storage.RedisTokenStorage, newOIDCSessionsTokenValidator(
		definitions.ScopeAuthenticate,
		definitions.ScopeSecurity,
	))

	session := &idp.OIDCSession{
		ClientID:    "client-a",
		UserID:      userID,
		Username:    "alice",
		DisplayName: "Alice Example",
		Scopes:      []string{"openid"},
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal OIDC session: %v", err)
	}

	mock.ExpectSMembers("test:oidc:user_access_tokens:" + userID).SetVal([]string{sessionToken})
	mock.ExpectGet("test:oidc:access_token:" + sessionToken).SetVal(string(sessionData))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/sessions/"+userID, nil)
	request.Header.Set("Authorization", "Bearer management-token")

	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.NotContains(t, response.Body.String(), sessionToken)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCSessionsAPI_DeleteAllRequiresBackchannelAuth(t *testing.T) {
	storage := &oidcSessionsStorageSpy{}
	router := setupOIDCSessionsRouter(newOIDCSessionsTestDeps(nil), storage, newOIDCSessionsTokenValidator(""))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/oidc/sessions/user1", nil)

	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Equal(t, 0, storage.calls)
}

func TestOIDCSessionsAPI_DeleteAllRejectsWrongScopeBeforeStorage(t *testing.T) {
	storage := &oidcSessionsStorageSpy{}
	router := setupOIDCSessionsRouter(newOIDCSessionsTestDeps(nil), storage, newOIDCSessionsTokenValidator(definitions.ScopeAuthenticate))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/oidc/sessions/user1", nil)
	request.Header.Set("Authorization", "Bearer base-scope-token")

	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.Equal(t, 0, storage.calls)
}

func TestOIDCSessionsAPI_DeleteSessionRejectsWrongUserToken(t *testing.T) {
	const (
		pathUserID    = "alice-id"
		tokenOwnerID  = "bob-id"
		sessionToken  = "opaque-session-reference"
		accessKeyName = "test:oidc:access_token:" + sessionToken
	)

	storage, mock := newOIDCSessionsRedisStorage(t)
	d := newOIDCSessionsTestDeps(storage.redis)
	router := setupOIDCSessionsRouter(d, storage.RedisTokenStorage, newOIDCSessionsTokenValidator(
		definitions.ScopeAuthenticate,
		definitions.ScopeSecurity,
	))

	sessionData, err := json.Marshal(&idp.OIDCSession{UserID: tokenOwnerID})
	if err != nil {
		t.Fatalf("marshal OIDC session: %v", err)
	}

	mock.ExpectGet(accessKeyName).SetVal(string(sessionData))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/oidc/sessions/"+pathUserID+"/"+sessionToken, nil)
	request.Header.Set("Authorization", "Bearer management-token")

	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

type oidcSessionsRedisStorage struct {
	*idp.RedisTokenStorage
	redis rediscli.Client
}

type oidcSessionsStorageSpy struct {
	calls int
}

func (s *oidcSessionsStorageSpy) ListUserSessions(context.Context, string) (map[string]*idp.OIDCSession, error) {
	s.calls++

	return map[string]*idp.OIDCSession{}, nil
}

func (s *oidcSessionsStorageSpy) GetAccessToken(context.Context, string) (*idp.OIDCSession, error) {
	s.calls++

	return nil, nil
}

func (s *oidcSessionsStorageSpy) DeleteAccessToken(context.Context, string) error {
	s.calls++

	return nil
}

func (s *oidcSessionsStorageSpy) FlushUserTokens(context.Context, string) error {
	s.calls++

	return nil
}

// newOIDCSessionsRedisStorage creates a mocked Redis-backed token storage fixture.
func newOIDCSessionsRedisStorage(t testing.TB) (*oidcSessionsRedisStorage, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	return &oidcSessionsRedisStorage{
		RedisTokenStorage: idp.NewRedisTokenStorage(redisClient, "test:"),
		redis:             redisClient,
	}, mock
}

// newOIDCSessionsTestDeps builds the handler dependencies needed by route tests.
func newOIDCSessionsTestDeps(redisClient rediscli.Client) *deps.Deps {
	return &deps.Deps{
		Logger: log.GetLogger(),
		Redis:  redisClient,
	}
}

type oidcSessionsTokenValidator struct {
	scope string
}

// newOIDCSessionsTokenValidator returns static bearer-token claims for route tests.
func newOIDCSessionsTokenValidator(scopes ...string) *oidcSessionsTokenValidator {
	return &oidcSessionsTokenValidator{scope: joinOIDCSessionsScopes(scopes)}
}

// ValidateToken returns the configured static claims without parsing token material.
func (v *oidcSessionsTokenValidator) ValidateToken(context.Context, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{"scope": v.scope}, nil
}

// joinOIDCSessionsScopes renders a deterministic OAuth scope claim for tests.
func joinOIDCSessionsScopes(scopes []string) string {
	result := ""

	for _, scope := range scopes {
		if result != "" {
			result += " "
		}

		result += scope
	}

	return result
}
