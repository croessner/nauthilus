package adminui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type tokenValidatorMock struct {
	claims jwt.MapClaims
	err    error
}

const (
	localAdminRemoteAddr = "127.0.0.1:9999"
	sameOriginHeader     = "http://example.com"
)

func (m tokenValidatorMock) ValidateToken(_ context.Context, _ string) (jwt.MapClaims, error) {
	return m.claims, m.err
}

func TestAuthMiddleware_IDPSessionDeniedWithoutSession(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := New(
		&handlerdeps.Deps{Cfg: idpSessionTestConfig()},
		AuthModeIDPSession,
		false,
		nil,
		nil,
		nil,
		nil,
	)

	router := gin.New()
	router.GET("/auth-check", handler.authMiddleware(), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth-check", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_IDPSessionAllowsWithRoleValue(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := New(
		&handlerdeps.Deps{Cfg: idpSessionTestConfig()},
		AuthModeIDPSession,
		false,
		nil,
		nil,
		nil,
		nil,
	)

	manager := cookie.NewSecureManager([]byte("admin-ui-test-secret"), definitions.SecureDataCookieName, nil, nil)
	manager.Set(definitions.SessionKeyUsername, "alice")
	manager.Set(definitions.SessionKeyAccount, "alice")
	cookie.SetAuthResult(manager, "alice", definitions.AuthResultOK)

	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, manager)
		ctx.Set(definitions.CtxOIDCClaimsKey, jwt.MapClaims{
			"groups": []string{"nauthilus.admin"},
		})
		ctx.Next()
	})

	router.GET("/auth-check", handler.authMiddleware(), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth-check", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthMiddleware_LocalAdminRequiresSessionAndAllowlistedSourceIP(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := New(
		&handlerdeps.Deps{Cfg: localAdminTestConfig("$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo")},
		AuthModeLocalAdmin,
		false,
		nil,
		nil,
		nil,
		nil,
	)

	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		manager := cookie.NewSecureManager([]byte("admin-ui-test-secret"), definitions.SecureDataCookieName, nil, nil)
		manager.Set(adminLocalAuthSessionKey, true)
		manager.Set(adminLocalUserSessionKey, "admin")
		ctx.Set(definitions.CtxSecureDataKey, manager)
		ctx.Next()
	})

	router.GET("/auth-check", handler.authMiddleware(), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	recDenied := httptest.NewRecorder()
	reqDenied := httptest.NewRequest(http.MethodGet, "/auth-check", nil)
	reqDenied.RemoteAddr = "10.10.10.10:12345"
	router.ServeHTTP(recDenied, reqDenied)

	if recDenied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want %d", recDenied.Code, http.StatusForbidden)
	}

	recAllowed := httptest.NewRecorder()
	reqAllowed := httptest.NewRequest(http.MethodGet, "/auth-check", nil)
	reqAllowed.RemoteAddr = "127.0.0.1:43210"
	router.ServeHTTP(recAllowed, reqAllowed)

	if recAllowed.Code != http.StatusNoContent {
		t.Fatalf("allowed status = %d, want %d", recAllowed.Code, http.StatusNoContent)
	}
}

func TestLocalAdminLoginSubmit_SetsSessionAndRedirects(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := newLocalAdminHandler()
	manager := cookie.NewSecureManager([]byte("admin-ui-test-secret"), definitions.SecureDataCookieName, nil, nil)
	router := routerWithSessionManager(manager)

	router.GET("/csrf", handler.csrfMiddleware(), func(ctx *gin.Context) {
		ctx.String(http.StatusOK, csrf.Token(ctx))
	})
	router.POST("/admin/login", handler.csrfMiddleware(), handler.LocalAdminLoginSubmit)

	token, csrfCookie := fetchCSRFTokenAndCookie(t, router)

	form := url.Values{
		"username":   []string{"admin"},
		"password":   []string{"abc123"},
		"csrf_token": []string{token},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "csrf_token="+csrfCookie)
	req.Header.Set("Origin", sameOriginHeader)
	req.RemoteAddr = localAdminRemoteAddr
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	if got := rec.Header().Get("Location"); got != "/admin" {
		t.Fatalf("location = %q, want %q", got, "/admin")
	}

	if !manager.GetBool(adminLocalAuthSessionKey, false) {
		t.Fatal("expected local admin auth flag to be set in session")
	}

	if got := manager.GetString(adminLocalUserSessionKey, ""); got != "admin" {
		t.Fatalf("session username = %q, want %q", got, "admin")
	}
}

func TestLocalAdminLoginSubmit_RejectsWithoutCSRF(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := newLocalAdminHandler()

	router := routerWithSessionManager(cookie.NewSecureManager([]byte("admin-ui-test-secret"), definitions.SecureDataCookieName, nil, nil))

	router.POST("/admin/login", handler.csrfMiddleware(), handler.LocalAdminLoginSubmit)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader("username=admin&password=abc123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", sameOriginHeader)
	req.RemoteAddr = localAdminRemoteAddr
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLocalAdminLogout_ClearsSessionAndRedirects(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := newLocalAdminHandler()
	manager := cookie.NewSecureManager([]byte("admin-ui-test-secret"), definitions.SecureDataCookieName, nil, nil)
	manager.Set(adminLocalAuthSessionKey, true)
	manager.Set(adminLocalUserSessionKey, "admin")
	router := routerWithSessionManager(manager)

	router.GET("/csrf", handler.csrfMiddleware(), func(ctx *gin.Context) {
		ctx.String(http.StatusOK, csrf.Token(ctx))
	})
	router.POST("/admin/logout", handler.authMiddleware(), handler.csrfMiddleware(), handler.LocalAdminLogout)

	token, csrfCookie := fetchCSRFTokenAndCookie(t, router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", strings.NewReader("csrf_token="+url.QueryEscape(token)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "csrf_token="+csrfCookie)
	req.Header.Set("Origin", sameOriginHeader)
	req.RemoteAddr = localAdminRemoteAddr
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	if got := rec.Header().Get("Location"); got != "/admin/login" {
		t.Fatalf("location = %q, want %q", got, "/admin/login")
	}

	if manager.GetBool(adminLocalAuthSessionKey, false) {
		t.Fatal("expected local admin auth flag to be cleared")
	}

	if got := manager.GetString(adminLocalUserSessionKey, ""); got != "" {
		t.Fatalf("session username = %q, want empty", got)
	}
}

func newLocalAdminHandler() *Handler {
	return New(
		&handlerdeps.Deps{Cfg: localAdminTestConfig("$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo")},
		AuthModeLocalAdmin,
		false,
		nil,
		nil,
		nil,
		nil,
	)
}

func routerWithSessionManager(manager cookie.Manager) *gin.Engine {
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, manager)
		ctx.Next()
	})

	return router
}

func fetchCSRFTokenAndCookie(t *testing.T, router *gin.Engine) (string, string) {
	t.Helper()

	csrfRec := httptest.NewRecorder()
	csrfReq := httptest.NewRequest(http.MethodGet, "/csrf", nil)
	router.ServeHTTP(csrfRec, csrfReq)

	token := strings.TrimSpace(csrfRec.Body.String())
	if token == "" {
		t.Fatal("expected csrf token in response body")
	}

	csrfCookie := extractCookieValue(csrfRec.Header().Values("Set-Cookie"), "csrf_token")
	if csrfCookie == "" {
		t.Fatal("expected csrf cookie to be set")
	}

	return token, csrfCookie
}

func extractCookieValue(setCookies []string, name string) string {
	prefix := name + "="

	for _, setCookie := range setCookies {
		parts := strings.Split(setCookie, ";")
		if len(parts) == 0 {
			continue
		}

		valuePart := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(valuePart, prefix) {
			continue
		}

		return strings.TrimPrefix(valuePart, prefix)
	}

	return ""
}

func TestAPIOIDCMiddleware_EnforcesRoleValue(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	cfg := idpSessionWithAPIOIDCTestConfig()

	tests := []struct {
		name   string
		groups []string
		want   int
	}{
		{name: "missing role value", groups: []string{"other.group"}, want: http.StatusForbidden},
		{name: "matching role value", groups: []string{"nauthilus.admin"}, want: http.StatusNoContent},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := runAPIOIDCAuthCheck(t, cfg, tt.groups)
			if got != tt.want {
				t.Fatalf("status = %d, want %d", got, tt.want)
			}
		})
	}
}

func runAPIOIDCAuthCheck(t *testing.T, cfg config.File, groups []string) int {
	t.Helper()

	handler := New(
		&handlerdeps.Deps{Cfg: cfg},
		AuthModeIDPSession,
		true,
		tokenValidatorMock{
			claims: jwt.MapClaims{
				"scope":  "nauthilus:admin",
				"groups": groups,
			},
		},
		nil,
		nil,
		nil,
	)

	router := gin.New()
	router.GET("/oidc-check", handler.apiOIDCMiddleware(), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oidc-check", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(rec, req)

	return rec.Code
}

func idpSessionTestConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{
			AdminUI: config.AdminUI{
				Enabled:  true,
				AuthMode: "idp_session",
				Authorization: config.AdminUIAuthorization{
					RequiredRoleValues: []string{"nauthilus.admin"},
				},
			},
		},
	}
}

func idpSessionWithAPIOIDCTestConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{
			AdminUI: config.AdminUI{
				Enabled:  true,
				AuthMode: "idp_session",
				Authorization: config.AdminUIAuthorization{
					RequiredRoleValues: []string{"nauthilus.admin"},
					RequiredScopes:     []string{"nauthilus:admin"},
				},
				APIOIDC: config.AdminUIAPIOIDC{
					Enabled: true,
				},
			},
		},
	}
}

func localAdminTestConfig(passwordHash string) config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{
			AdminUI: config.AdminUI{
				Enabled:  true,
				AuthMode: "local_admin",
				LocalAdmin: config.AdminUILocalAdmin{
					Enabled: true,
					Users: []config.AdminUILocalUser{
						{Username: "admin", PasswordHash: passwordHash},
					},
				},
				Network: config.AdminUINetwork{
					EnforceForLocalAdmin: true,
					SourceIPAllowlist:    []string{"127.0.0.1/32"},
				},
			},
		},
	}
}
