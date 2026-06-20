package core

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func newRestAdminDepsForConfigLoadTests(cfg *config.FileSettings) restAdminDeps {
	db, _ := redismock.NewClientMock()

	return restAdminDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db),
	}
}

func newConfigLoadContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/config/load", nil)
	ctx.Set(definitions.CtxGUIDKey, "guid-test")

	return ctx, w
}

func TestHandleConfigLoad_RequiresConfiguredAuthentication(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	assertConfigLoadStatus(t, newConfigLoadSettings(false, false), nil, http.StatusUnauthorized)
}

func TestHandleConfigLoad_RequiresOIDCClaimsWhenOIDCAuthEnabled(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	assertConfigLoadStatus(t, newConfigLoadSettings(false, true), nil, http.StatusUnauthorized)
}

func TestHandleConfigLoad_EnforcesSecurityOrAdminScope(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: config.BasicAuth{Enabled: false},
			OIDCAuth:  config.OIDCAuth{Enabled: true},
		},
	}
	deps := newRestAdminDepsForConfigLoadTests(cfg)

	t.Run("forbidden without required scope", func(t *testing.T) {
		ctx, w := newConfigLoadContext()
		ctx.Set(definitions.CtxOIDCClaimsKey, jwt.MapClaims{
			"scope": "openid profile",
		})

		deps.HandleConfigLoad(ctx)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("allowed with security scope", func(t *testing.T) {
		ctx, w := newConfigLoadContext()
		ctx.Set(definitions.CtxOIDCClaimsKey, jwt.MapClaims{
			"scope": definitions.ScopeSecurity,
		})

		deps.HandleConfigLoad(ctx)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleConfigLoad_RequiresValidatedBasicAuthWhenOnlyBasicAuthEnabled(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: config.BasicAuth{Enabled: true},
			OIDCAuth:  config.OIDCAuth{Enabled: false},
		},
	}
	deps := newRestAdminDepsForConfigLoadTests(cfg)

	t.Run("missing validated flag is unauthorized", func(t *testing.T) {
		ctx, w := newConfigLoadContext()

		deps.HandleConfigLoad(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("validated basic auth allows access", func(t *testing.T) {
		ctx, w := newConfigLoadContext()
		ctx.Set(definitions.CtxBasicAuthValidatedKey, true)

		deps.HandleConfigLoad(ctx)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleConfigLoad_DeveloperModeBypassesMissingAuthConfiguration(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: true})

	assertConfigLoadStatus(t, newConfigLoadSettings(false, false), nil, http.StatusOK)
}

// newConfigLoadSettings creates FileSettings with the selected REST auth flags.
func newConfigLoadSettings(basicAuthEnabled bool, oidcAuthEnabled bool) *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: config.BasicAuth{Enabled: basicAuthEnabled},
			OIDCAuth:  config.OIDCAuth{Enabled: oidcAuthEnabled},
		},
	}
}

// assertConfigLoadStatus executes HandleConfigLoad and verifies the response status.
func assertConfigLoadStatus(t *testing.T, cfg *config.FileSettings, prepare func(*gin.Context), wantStatus int) {
	t.Helper()

	deps := newRestAdminDepsForConfigLoadTests(cfg)

	ctx, w := newConfigLoadContext()
	if prepare != nil {
		prepare(ctx)
	}

	deps.HandleConfigLoad(ctx)

	assert.Equal(t, wantStatus, w.Code)
}
