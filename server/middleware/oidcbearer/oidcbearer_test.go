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

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// mockTokenValidator implements TokenValidator for testing.
type mockTokenValidator struct {
	claims jwt.MapClaims
	err    error
}

type hasScopeCase struct {
	name   string
	claims jwt.MapClaims
	scope  string
	want   bool
}

func (m *mockTokenValidator) ValidateToken(_ context.Context, _ string) (jwt.MapClaims, error) {
	return m.claims, m.err
}

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHasScope(t *testing.T) {
	for _, tt := range hasScopeCases() {
		t.Run(tt.name, func(t *testing.T) {
			got := HasScope(tt.claims, tt.scope)

			assert.Equal(t, tt.want, got)
		})
	}
}

// hasScopeCases returns exact scope-matching scenarios.
func hasScopeCases() []hasScopeCase {
	return []hasScopeCase{
		{name: "nil claims", scope: "nauthilus:authenticate"},
		{name: "empty scope", claims: scopeClaims("nauthilus:authenticate"), scope: ""},
		{name: "no scope claim", claims: jwt.MapClaims{"sub": "client-id"}, scope: "nauthilus:authenticate"},
		{name: "scope claim is not a string", claims: jwt.MapClaims{"scope": 42}, scope: "nauthilus:authenticate"},
		{name: "single scope match", claims: scopeClaims("nauthilus:authenticate"), scope: "nauthilus:authenticate", want: true},
		{name: "multiple scopes match", claims: scopeClaims("nauthilus:authenticate nauthilus:admin nauthilus:security"), scope: "nauthilus:admin", want: true},
		{name: "multiple scopes no match", claims: scopeClaims("nauthilus:authenticate nauthilus:security"), scope: "nauthilus:admin"},
		{name: "partial scope name does not match", claims: scopeClaims("nauthilus:authenticate_extra"), scope: "nauthilus:authenticate"},
	}
}

// scopeClaims returns JWT claims with a string scope claim.
func scopeClaims(scope string) jwt.MapClaims {
	return jwt.MapClaims{"scope": scope}
}

// backchannelAccessClaims returns access-token claims for the Nauthilus backchannel API.
func backchannelAccessClaims(scope string) jwt.MapClaims {
	return jwt.MapClaims{
		"aud":                      definitions.AudienceBackchannelAPI,
		"scope":                    scope,
		"sub":                      "test-client",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
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
		claims: backchannelAccessClaims("nauthilus:authenticate nauthilus:security"),
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

// assertBearerMiddlewareStatus runs a bearer middleware request and checks the response code.
func assertBearerMiddlewareStatus(t *testing.T, scope string, target string, expectedStatus int) {
	t.Helper()

	validator := &mockTokenValidator{
		claims: backchannelAccessClaims(scope),
	}

	w := httptest.NewRecorder()
	router := gin.New()

	router.Use(Middleware(validator, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	router.ServeHTTP(w, req)

	assert.Equal(t, expectedStatus, w.Code)
}

func TestMiddleware_ValidToken_MissingAuthenticateScope(t *testing.T) {
	assertBearerMiddlewareStatus(t, "nauthilus:security", "/test", http.StatusForbidden)
}

func TestMiddleware_NoAuthMode_StillRequiresAuthenticateScope(t *testing.T) {
	assertBearerMiddlewareStatus(t, "nauthilus:list_accounts", "/test?mode=no-auth", http.StatusForbidden)
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
		claims: backchannelAccessClaims(definitions.ScopeAuthenticate),
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	claims := ValidateAndStoreClaims(ctx, validator, nil, "valid-token")

	assert.NotNil(t, claims)
	assert.Equal(t, "test-client", claims["sub"])

	// Claims should also be stored in context
	stored := GetClaimsFromContext(ctx)

	assert.NotNil(t, stored)
	assert.Equal(t, "test-client", stored["sub"])
}

func TestValidateAndStoreClaimsRejectsIDTokenTokenType(t *testing.T) {
	validator := &mockTokenValidator{
		claims: jwt.MapClaims{
			"aud":                      definitions.AudienceBackchannelAPI,
			"scope":                    definitions.ScopeAuthenticate,
			"sub":                      "test-client",
			definitions.ClaimTokenType: definitions.TokenTypeIDToken,
		},
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	claims := ValidateAndStoreClaims(ctx, validator, nil, "valid-id-token")

	assert.Nil(t, claims)
	assert.True(t, ctx.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Nil(t, GetClaimsFromContext(ctx))
}

func TestAuthorizeAuthenticateScopeRejectsWrongAudience(t *testing.T) {
	validator := &mockTokenValidator{
		claims: jwt.MapClaims{
			"aud":                      "other-resource",
			"scope":                    definitions.ScopeAuthenticate,
			"sub":                      "test-client",
			definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
		},
	}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.Header.Set("Authorization", "Bearer token")

	_, ok := EnforceBearerScopeAuth(ctx, validator, nil, EnforceBearerScopeAuthOptions{
		RequiredScopes: []string{definitions.ScopeAuthenticate},
	})

	assert.False(t, ok)
	assert.True(t, ctx.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthorizeAuthenticateScopeAcceptsAccessTokenAudience(t *testing.T) {
	validator := &mockTokenValidator{
		claims: backchannelAccessClaims(definitions.ScopeAuthenticate),
	}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.Header.Set("Authorization", "Bearer token")

	claims, ok := EnforceBearerScopeAuth(ctx, validator, nil, EnforceBearerScopeAuthOptions{
		RequiredScopes: []string{definitions.ScopeAuthenticate},
	})

	assert.True(t, ok)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "test-client", claims["sub"])
}

func TestEnforceBearerScopeAuth(t *testing.T) {
	t.Run("missing header denies", func(t *testing.T) {
		validator := &mockTokenValidator{}
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		_, ok := EnforceBearerScopeAuth(ctx, validator, nil, EnforceBearerScopeAuthOptions{
			RequiredScopes: []string{definitions.ScopeAuthenticate},
		})
		assert.False(t, ok)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("valid token with matching scope allows", func(t *testing.T) {
		validator := &mockTokenValidator{
			claims: backchannelAccessClaims(definitions.ScopeAuthenticate),
		}
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx.Request.Header.Set("Authorization", "Bearer token")

		_, ok := EnforceBearerScopeAuth(ctx, validator, nil, EnforceBearerScopeAuthOptions{
			RequiredScopes: []string{definitions.ScopeAuthenticate},
		})
		assert.True(t, ok)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("valid token with missing scope denies forbidden", func(t *testing.T) {
		validator := &mockTokenValidator{
			claims: backchannelAccessClaims(definitions.ScopeSecurity),
		}
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx.Request.Header.Set("Authorization", "Bearer token")

		_, ok := EnforceBearerScopeAuth(ctx, validator, nil, EnforceBearerScopeAuthOptions{
			RequiredScopes:      []string{definitions.ScopeAuthenticate},
			MissingScopeMessage: "missing required scope: " + definitions.ScopeAuthenticate,
		})
		assert.False(t, ok)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestScopeMiddlewareRequiresOperationScopeForBearer(t *testing.T) {
	tests := []struct {
		name       string
		claims     jwt.MapClaims
		basicAuth  bool
		wantStatus int
	}{
		{
			name:       "base scope bearer is forbidden",
			claims:     backchannelAccessClaims(definitions.ScopeAuthenticate),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "operation scope bearer is allowed",
			claims:     backchannelAccessClaims(definitions.ScopeSecurity),
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "admin bearer is allowed",
			claims:     backchannelAccessClaims(definitions.ScopeAdmin),
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "basic authenticated request is allowed",
			basicAuth:  true,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "missing authentication context is unauthorized",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			ctx, router := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest(http.MethodDelete, "/test", nil)

			router.Use(func(ctx *gin.Context) {
				if tt.claims != nil {
					ctx.Set(definitions.CtxOIDCClaimsKey, tt.claims)
				}

				if tt.basicAuth {
					ctx.Set(definitions.CtxBasicAuthValidatedKey, true)
				}

				ctx.Next()
			})
			router.Use(RequireAnyScope(definitions.ScopeSecurity, definitions.ScopeAdmin))
			router.DELETE("/test", func(ctx *gin.Context) {
				ctx.Status(http.StatusNoContent)
			})

			router.ServeHTTP(response, ctx.Request)

			assert.Equal(t, tt.wantStatus, response.Code)
		})
	}
}

func TestValidateAndStoreClaims_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		err: fmt.Errorf("invalid token"),
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	claims := ValidateAndStoreClaims(ctx, validator, nil, "bad-token")

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

	ValidateAndStoreClaims(ctx, validator, nil, "expired-token")

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
