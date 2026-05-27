// Copyright (C) 2026 Christian Rößner
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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const coreTestCORSOrigin = "https://app.example.com"

// TestDefaultRouterComposer_ApplyCoreMiddlewares_AppliesCORS verifies that the
// centralized CORS middleware is attached in the core middleware chain.
func TestDefaultRouterComposer_ApplyCoreMiddlewares_AppliesCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	enabled := true
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			CORS: config.CORS{
				Enabled: &enabled,
				Policies: []config.CORSPolicy{
					{
						Name:         "oidc_discovery",
						Enabled:      &enabled,
						PathPrefixes: []string{"/.well-known/"},
						AllowOrigins: []string{coreTestCORSOrigin},
						AllowMethods: []string{"GET", "OPTIONS"},
						AllowHeaders: []string{"Authorization", "Content-Type"},
					},
				},
			},
		},
	}

	composer := NewDefaultRouterComposer(HTTPDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	r := composer.ComposeEngine()
	composer.ApplyCoreMiddlewares(r)
	r.GET("/.well-known/openid-configuration", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	getReq := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	getReq.Header.Set("Origin", coreTestCORSOrigin)

	getResp := httptest.NewRecorder()
	r.ServeHTTP(getResp, getReq)

	assert.Equal(t, http.StatusOK, getResp.Code)
	assert.Equal(t, coreTestCORSOrigin, getResp.Header().Get("Access-Control-Allow-Origin"))

	optionsReq := httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil)
	optionsReq.Header.Set("Origin", coreTestCORSOrigin)
	optionsReq.Header.Set("Access-Control-Request-Method", "GET")

	optionsResp := httptest.NewRecorder()
	r.ServeHTTP(optionsResp, optionsReq)

	assert.Equal(t, http.StatusNoContent, optionsResp.Code)
	assert.Equal(t, coreTestCORSOrigin, optionsResp.Header().Get("Access-Control-Allow-Origin"))
}

func TestDefaultRouterComposer_RegisterRoutes_RegistersPublicIdPOpenAPISpec(t *testing.T) {
	gin.SetMode(gin.TestMode)

	templateDir := frontendTemplateDir(t)
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				Enabled:               true,
				HTMLStaticContentPath: templateDir,
			},
		},
	}

	composer := NewDefaultRouterComposer(HTTPDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	r := composer.ComposeEngine()
	composer.RegisterRoutes(r, nil, nil, func(*gin.Engine) {}, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openapi.yaml", nil)

	r.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Nauthilus IdP API")
}

func TestDefaultRouterComposer_RegisterRoutes_SkipsPublicIdPOpenAPIWithoutIdPSetup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	templateDir := frontendTemplateDir(t)
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				Enabled:               true,
				HTMLStaticContentPath: templateDir,
			},
		},
	}

	composer := NewDefaultRouterComposer(HTTPDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	r := composer.ComposeEngine()
	composer.RegisterRoutes(r, nil, nil, nil, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openapi.yaml", nil)

	r.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func frontendTemplateDir(t *testing.T) string {
	t.Helper()

	path, err := filepath.Abs("../../static/templates")
	if err != nil {
		t.Fatalf("filepath.Abs error = %v", err)
	}

	return path
}
