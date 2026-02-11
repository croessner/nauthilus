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

package oidcbearer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// mockTokenValidator implements TokenValidator for testing.
type mockTokenValidator struct {
	claims jwt.MapClaims
	err    error
}

func (m *mockTokenValidator) ValidateToken(_ context.Context, _ string) (jwt.MapClaims, error) {
	return m.claims, m.err
}

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		scope  string
		want   bool
	}{
		{
			name:   "nil claims",
			claims: nil,
			scope:  "nauthilus:authenticate",
			want:   false,
		},
		{
			name:   "empty scope",
			claims: jwt.MapClaims{"scope": "nauthilus:authenticate"},
			scope:  "",
			want:   false,
		},
		{
			name:   "no scope claim",
			claims: jwt.MapClaims{"sub": "client-id"},
			scope:  "nauthilus:authenticate",
			want:   false,
		},
		{
			name:   "scope claim is not a string",
			claims: jwt.MapClaims{"scope": 42},
			scope:  "nauthilus:authenticate",
			want:   false,
		},
		{
			name:   "single scope match",
			claims: jwt.MapClaims{"scope": "nauthilus:authenticate"},
			scope:  "nauthilus:authenticate",
			want:   true,
		},
		{
			name:   "multiple scopes match",
			claims: jwt.MapClaims{"scope": "nauthilus:authenticate nauthilus:admin nauthilus:security"},
			scope:  "nauthilus:admin",
			want:   true,
		},
		{
			name:   "multiple scopes no match",
			claims: jwt.MapClaims{"scope": "nauthilus:authenticate nauthilus:security"},
			scope:  "nauthilus:admin",
			want:   false,
		},
		{
			name:   "partial scope name does not match",
			claims: jwt.MapClaims{"scope": "nauthilus:authenticate_extra"},
			scope:  "nauthilus:authenticate",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasScope(tt.claims, tt.scope)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasAnyScope(t *testing.T) {
	claims := jwt.MapClaims{"scope": "nauthilus:authenticate nauthilus:security"}

	t.Run("matches first scope", func(t *testing.T) {
		assert.True(t, HasAnyScope(claims, "nauthilus:authenticate", "nauthilus:admin"))
	})

	t.Run("matches second scope", func(t *testing.T) {
		assert.True(t, HasAnyScope(claims, "nauthilus:admin", "nauthilus:security"))
	})

	t.Run("no match", func(t *testing.T) {
		assert.False(t, HasAnyScope(claims, "nauthilus:admin", "nauthilus:list_accounts"))
	})

	t.Run("empty scopes list", func(t *testing.T) {
		assert.False(t, HasAnyScope(claims))
	})
}

func TestGetClaimsFromContext(t *testing.T) {
	t.Run("no claims in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		assert.Nil(t, GetClaimsFromContext(ctx))
	})

	t.Run("claims present in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		expected := jwt.MapClaims{"sub": "test-client", "scope": "nauthilus:authenticate"}
		ctx.Set(definitions.CtxOIDCClaimsKey, expected)

		got := GetClaimsFromContext(ctx)

		assert.Equal(t, expected, got)
	})

	t.Run("wrong type in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		ctx.Set(definitions.CtxOIDCClaimsKey, "not-claims")

		assert.Nil(t, GetClaimsFromContext(ctx))
	})
}

func TestMiddleware_MissingAuthHeader(t *testing.T) {
	validator := &mockTokenValidator{}

	w := httptest.NewRecorder()
	ctx, router := gin.CreateTestContext(w)

	router.Use(Middleware(validator, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, ctx.Request)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddleware_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: fmt.Errorf("invalid token"),
	}

	w := httptest.NewRecorder()
	router := gin.New()

	router.Use(Middleware(validator, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddleware_ValidToken_WithAuthenticateScope(t *testing.T) {
	validator := &mockTokenValidator{
		claims: jwt.MapClaims{
			"sub":   "test-client",
			"scope": "nauthilus:authenticate nauthilus:security",
		},
	}

	w := httptest.NewRecorder()
	router := gin.New()

	router.Use(Middleware(validator, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		claims := GetClaimsFromContext(c)

		assert.NotNil(t, claims)
		assert.Equal(t, "test-client", claims["sub"])

		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_ValidToken_MissingAuthenticateScope(t *testing.T) {
	validator := &mockTokenValidator{
		claims: jwt.MapClaims{
			"sub":   "test-client",
			"scope": "nauthilus:security",
		},
	}

	w := httptest.NewRecorder()
	router := gin.New()

	router.Use(Middleware(validator, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMiddleware_NoAuthMode_SkipsScopeCheck(t *testing.T) {
	validator := &mockTokenValidator{
		claims: jwt.MapClaims{
			"sub":   "test-client",
			"scope": "nauthilus:list_accounts",
		},
	}

	w := httptest.NewRecorder()
	router := gin.New()

	router.Use(Middleware(validator, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test?mode=no-auth", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{
			name:   "no header",
			header: "",
			wantOK: false,
		},
		{
			name:   "wrong scheme",
			header: "Basic dXNlcjpwYXNz",
			wantOK: false,
		},
		{
			name:   "bearer without token",
			header: "Bearer ",
			wantOK: false,
		},
		{
			name:      "valid bearer token",
			header:    "Bearer eyJhbGciOiJSUzI1NiJ9.test.sig",
			wantToken: "eyJhbGciOiJSUzI1NiJ9.test.sig",
			wantOK:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

			if tt.header != "" {
				ctx.Request.Header.Set("Authorization", tt.header)
			}

			token, ok := ExtractBearerToken(ctx)

			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				assert.Equal(t, tt.wantToken, token)
			}
		})
	}
}

func TestValidateAndStoreClaims_ValidToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: jwt.MapClaims{
			"sub":   "test-client",
			"scope": "nauthilus:authenticate",
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	claims := ValidateAndStoreClaims(ctx, validator, nil, nil, "valid-token")

	assert.NotNil(t, claims)
	assert.Equal(t, "test-client", claims["sub"])

	// Claims should also be stored in context
	stored := GetClaimsFromContext(ctx)

	assert.NotNil(t, stored)
	assert.Equal(t, "test-client", stored["sub"])
}

func TestValidateAndStoreClaims_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: fmt.Errorf("invalid token"),
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	claims := ValidateAndStoreClaims(ctx, validator, nil, nil, "bad-token")

	assert.Nil(t, claims)
	assert.True(t, ctx.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestValidateAndStoreClaims_NoClaims(t *testing.T) {
	// No claims stored when validation fails
	validator := &mockTokenValidator{
		err: fmt.Errorf("expired token"),
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	ValidateAndStoreClaims(ctx, validator, nil, nil, "expired-token")

	assert.Nil(t, GetClaimsFromContext(ctx))
}

func TestHasScopeFromContext(t *testing.T) {
	t.Run("no claims returns false", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		assert.False(t, HasScopeFromContext(ctx, "nauthilus:authenticate"))
	})

	t.Run("with matching scope returns true", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		ctx.Set(definitions.CtxOIDCClaimsKey, jwt.MapClaims{
			"scope": "nauthilus:authenticate nauthilus:admin",
		})

		assert.True(t, HasScopeFromContext(ctx, "nauthilus:admin"))
	})
}
