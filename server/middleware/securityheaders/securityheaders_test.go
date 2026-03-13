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

package securityheaders

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type fixedNonceGenerator struct {
	nonce string
	err   error
}

func (f fixedNonceGenerator) Generate() (string, error) {
	if f.err != nil {
		return "", f.err
	}

	return f.nonce, nil
}

func TestMiddleware_SetsStrictHeadersAndNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	enabled := true
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				SecurityHeaders: config.FrontendSecurityHeaders{
					Enabled:                 &enabled,
					ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'nonce-{{nonce}}'",
					StrictTransportSecurity: "max-age=31536000; includeSubDomains",
					XContentTypeOptions:     "nosniff",
					XFrameOptions:           "DENY",
					ReferrerPolicy:          "no-referrer",
					PermissionsPolicy:       "geolocation=()",
				},
			},
		},
	}

	mw := New(MiddlewareConfig{
		Config:         cfg,
		NonceGenerator: fixedNonceGenerator{nonce: "testnonce123"},
	})

	r := gin.New()
	r.Use(mw.Handler())
	r.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, NonceFromContext(ctx))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "testnonce123", w.Body.String())
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "geolocation=()", w.Header().Get("Permissions-Policy"))
	assert.Equal(t, "max-age=31536000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "default-src 'self'; script-src 'self' 'nonce-testnonce123'", w.Header().Get("Content-Security-Policy"))
}

func TestMiddleware_DisabledSkipsHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	enabled := false
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				SecurityHeaders: config.FrontendSecurityHeaders{
					Enabled:               &enabled,
					ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'nonce-{{nonce}}'",
				},
			},
		},
	}

	mw := New(MiddlewareConfig{
		Config:         cfg,
		NonceGenerator: fixedNonceGenerator{nonce: "testnonce123"},
	})

	r := gin.New()
	r.Use(mw.Handler())
	r.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Content-Security-Policy"))
	assert.Empty(t, w.Header().Get("X-Frame-Options"))
	assert.Empty(t, w.Header().Get("X-Content-Type-Options"))
}

func TestMiddleware_NonceFailureAborts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	enabled := true
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				SecurityHeaders: config.FrontendSecurityHeaders{
					Enabled:               &enabled,
					ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'nonce-{{nonce}}'",
				},
			},
		},
	}

	mw := New(MiddlewareConfig{
		Config:         cfg,
		NonceGenerator: fixedNonceGenerator{err: errors.New("nonce generation failed")},
	})

	r := gin.New()
	r.Use(mw.Handler())
	r.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "", w.Header().Get("Content-Security-Policy"))
}

func TestMiddleware_StyleSrcUnsafeInlineDropsNonce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	enabled := true
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				SecurityHeaders: config.FrontendSecurityHeaders{
					Enabled:               &enabled,
					ContentSecurityPolicy: "default-src 'self'; style-src 'self' 'nonce-{{nonce}}' 'unsafe-inline'; script-src 'self' 'nonce-{{nonce}}'",
				},
			},
		},
	}

	mw := New(MiddlewareConfig{
		Config:         cfg,
		NonceGenerator: fixedNonceGenerator{nonce: "testnonce123"},
	})

	r := gin.New()
	r.Use(mw.Handler())
	r.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(
		t,
		"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-testnonce123'",
		w.Header().Get("Content-Security-Policy"),
	)
}

func TestMiddleware_FormActionSelfRemainsStrict(t *testing.T) {
	gin.SetMode(gin.TestMode)

	enabled := true
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				SecurityHeaders: config.FrontendSecurityHeaders{
					Enabled:               &enabled,
					ContentSecurityPolicy: "default-src 'self'; form-action 'self'; script-src 'self' 'nonce-{{nonce}}'",
				},
			},
		},
	}

	mw := New(MiddlewareConfig{
		Config:         cfg,
		NonceGenerator: fixedNonceGenerator{nonce: "testnonce123"},
	})

	r := gin.New()
	r.Use(mw.Handler())
	r.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(
		t,
		"default-src 'self'; form-action 'self'; script-src 'self' 'nonce-testnonce123'",
		w.Header().Get("Content-Security-Policy"),
	)
}

func TestNonceFromTemplateData(t *testing.T) {
	nonce := NonceFromTemplateData(gin.H{"CSPNonce": "abc"})
	assert.Equal(t, "abc", nonce)

	nonce = NonceFromTemplateData(map[string]any{"CSPNonce": "xyz"})
	assert.Equal(t, "xyz", nonce)

	nonce = NonceFromTemplateData(nil)
	assert.Equal(t, "", nonce)
}
