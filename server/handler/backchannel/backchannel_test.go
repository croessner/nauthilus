package backchannel

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/asyncjobs"
	handlerbruteforce "github.com/croessner/nauthilus/v3/server/handler/bruteforce"
	handlercache "github.com/croessner/nauthilus/v3/server/handler/cache"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type backchannelAuthConfigCase struct {
	name          string
	cfg           config.File
	developerMode bool
	usePublicAPI  bool
	wantErr       bool
}

func TestEnsureBackchannelAuthConfigured(t *testing.T) {
	for _, tt := range backchannelAuthConfigCases() {
		t.Run(tt.name, func(t *testing.T) {
			assertBackchannelAuthConfig(t, tt)
		})
	}
}

// backchannelAuthConfigCases returns configuration validation scenarios.
func backchannelAuthConfigCases() []backchannelAuthConfigCase {
	return []backchannelAuthConfigCase{
		{name: "returns error when no auth is configured", cfg: backchannelAuthConfig(false, false, false), wantErr: true},
		{name: "allows hook-only setup without auth", cfg: backchannelAuthConfig(false, false, true), usePublicAPI: true},
		{name: "allows basic auth only", cfg: backchannelAuthConfig(true, false, false)},
		{name: "allows oidc auth only", cfg: backchannelAuthConfig(false, true, false)},
		{name: "developer mode bypasses auth configuration check", cfg: backchannelAuthConfig(false, false, false), developerMode: true},
	}
}

// backchannelAuthConfig builds a minimal backchannel auth config for tests.
func backchannelAuthConfig(basicEnabled bool, oidcEnabled bool, withHook bool) config.File {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: config.BasicAuth{Enabled: basicEnabled},
			OIDCAuth:  config.OIDCAuth{Enabled: oidcEnabled},
		},
	}

	if withHook {
		cfg.Lua = &config.LuaSection{
			Hooks: []config.LuaHooks{{
				Location:   "/hooks/demo",
				Method:     "POST",
				ScriptPath: "/tmp/demo.lua",
				Public:     true,
			}},
		}
	}

	return cfg
}

// assertBackchannelAuthConfig verifies one backchannel auth configuration case.
func assertBackchannelAuthConfig(t *testing.T, tt backchannelAuthConfigCase) {
	t.Helper()

	err := ensureBackchannelAuthConfigured(tt.cfg, tt.developerMode)
	if tt.usePublicAPI {
		err = ValidateAuthConfiguration(tt.cfg, tt.developerMode)
	}

	if tt.wantErr {
		assert.ErrorIs(t, err, errBackchannelAuthNotConfigured)

		return
	}

	assert.NoError(t, err)
}

func TestBackchannelAuthMiddlewareAllowsEitherBasicOrBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: config.BasicAuth{
				Enabled:  true,
				Username: "api-client",
				Password: secret.New("api-secret-1234"),
			},
			OIDCAuth: config.OIDCAuth{Enabled: true},
		},
	}

	t.Run("allows basic auth without bearer token", func(t *testing.T) {
		validator := &recordingTokenValidator{
			claims: backchannelTestClaims(definitions.ScopeAuthenticate),
		}
		router := newBackchannelAuthTestRouter(cfg, validator)
		request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/probe", nil)
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("api-client:api-secret-1234")))

		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		assert.Equal(t, http.StatusNoContent, response.Code)
		assert.Equal(t, 0, validator.calls)
	})

	t.Run("allows bearer token without basic credentials", func(t *testing.T) {
		validator := &recordingTokenValidator{
			claims: backchannelTestClaims(definitions.ScopeAuthenticate),
		}
		router := newBackchannelAuthTestRouter(cfg, validator)
		request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/probe", nil)
		request.Header.Set("Authorization", "Bearer token-1")

		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		assert.Equal(t, http.StatusNoContent, response.Code)
		assert.Equal(t, 1, validator.calls)
	})
}

func TestSetupRegistersProtectedManagementOpenAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: config.BasicAuth{
				Enabled:  true,
				Username: "api-client",
				Password: secret.New("api-secret-1234"),
			},
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := gin.New()

	err := Setup(router, &handlerdeps.Deps{
		Cfg:    cfg,
		Logger: logger,
	})
	assert.NoError(t, err)

	unauthorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	unauthorizedResponse := httptest.NewRecorder()

	router.ServeHTTP(unauthorizedResponse, unauthorizedRequest)

	assert.Equal(t, http.StatusUnauthorized, unauthorizedResponse.Code)

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	authorizedRequest.SetBasicAuth("api-client", "api-secret-1234")

	authorizedResponse := httptest.NewRecorder()

	router.ServeHTTP(authorizedResponse, authorizedRequest)

	assert.Equal(t, http.StatusOK, authorizedResponse.Code)
	assert.Contains(t, authorizedResponse.Body.String(), "Nauthilus Management API")
}

func TestBackchannelMutationRoutesRejectBaseScopeBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "cache flush",
			method: http.MethodDelete,
			path:   "/api/v1/cache/flush",
			body:   `{"user":"alice"}`,
		},
		{
			name:   "brute-force flush",
			method: http.MethodDelete,
			path:   "/api/v1/bruteforce/flush",
			body:   `{"ip_address":"192.0.2.10","rule_name":"*"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newBackchannelMutationScopeRouter(definitions.ScopeAuthenticate)
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			request.Header.Set("Authorization", "Bearer base-scope-token")
			request.Header.Set("Content-Type", "application/json")

			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			assert.Equal(t, http.StatusForbidden, response.Code)
		})
	}
}

func TestBackchannelAsyncJobStatusRejectsBaseScopeBearer(t *testing.T) {
	router, mock := newBackchannelAsyncJobStatusRouter(t, definitions.ScopeAuthenticate)
	jobID := "job-123"
	key := "test:" + "async:job:" + jobID
	now := time.Now().UTC().Format(time.RFC3339Nano)

	mock.ExpectHGetAll(key).SetVal(map[string]string{
		"status":      "DONE",
		"type":        "TEST",
		"createdAt":   now,
		"startedAt":   now,
		"finishedAt":  now,
		"resultCount": "3",
		"error":       "",
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/async/jobs/"+jobID, nil)
	request.Header.Set("Authorization", "Bearer base-scope-token")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusForbidden, response.Code)
}

func TestBackchannelAsyncJobStatusAllowsSecurityScopeBearer(t *testing.T) {
	router, mock := newBackchannelAsyncJobStatusRouter(t, definitions.ScopeAuthenticate+" "+definitions.ScopeSecurity)
	jobID := "job-123"
	key := "test:" + "async:job:" + jobID
	now := time.Now().UTC().Format(time.RFC3339Nano)

	mock.ExpectHGetAll(key).SetVal(map[string]string{
		"status":      "DONE",
		"type":        "TEST",
		"createdAt":   now,
		"startedAt":   now,
		"finishedAt":  now,
		"resultCount": "3",
		"error":       "",
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/async/jobs/"+jobID, nil)
	request.Header.Set("Authorization", "Bearer security-scope-token")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func newBackchannelAuthTestRouter(cfg config.File, validator *recordingTokenValidator) *gin.Engine {
	router := gin.New()
	router.Use(backchannelAuthMiddleware(cfg, validator, slog.Default()))
	router.GET("/api/v1/auth/probe", func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	return router
}

func newBackchannelAsyncJobStatusRouter(t *testing.T, scope string) (*gin.Engine, redismock.ClientMock) {
	t.Helper()

	cfg := backchannelAuthConfig(false, true, false)
	cfg.GetServer().Redis.Prefix = "test:"

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	validator := &recordingTokenValidator{
		claims: backchannelTestClaims(scope),
	}

	router := gin.New()
	router.Use(gin.Recovery())

	group := router.Group("/api/v1")
	group.Use(oidcBackchannelTestMiddleware(cfg, validator))

	deps := &handlerdeps.Deps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  redisClient,
	}

	asyncjobs.New(deps).Register(group)

	return router, mock
}

// newBackchannelMutationScopeRouter builds cache and brute-force routes behind bearer base auth.
func newBackchannelMutationScopeRouter(scope string) *gin.Engine {
	cfg := backchannelAuthConfig(false, true, false)
	validator := &recordingTokenValidator{
		claims: backchannelTestClaims(scope),
	}
	router := gin.New()
	router.Use(gin.Recovery())

	group := router.Group("/api/v1")
	group.Use(oidcBackchannelTestMiddleware(cfg, validator))

	deps := &handlerdeps.Deps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	handlercache.New(deps).Register(group)
	handlerbruteforce.New(deps).Register(group)

	return router
}

// oidcBackchannelTestMiddleware simulates the shared Bearer backchannel boundary.
func oidcBackchannelTestMiddleware(cfg config.File, validator *recordingTokenValidator) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !oidcbearer.AuthorizeAuthenticateScope(ctx, validator, cfg, slog.Default()) {
			return
		}

		ctx.Next()
	}
}

type recordingTokenValidator struct {
	claims jwt.MapClaims
	calls  int
}

// backchannelTestClaims returns valid access-token claims for backchannel tests.
func backchannelTestClaims(scope string) jwt.MapClaims {
	return jwt.MapClaims{
		"aud":                      definitions.AudienceBackchannelAPI,
		"scope":                    scope,
		"sub":                      "api-client",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
}

func (v *recordingTokenValidator) ValidateToken(context.Context, string) (jwt.MapClaims, error) {
	v.calls++

	return v.claims, nil
}
