package adminui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type bruteForceServiceMock struct {
	listCalls     int
	freeIPCalls   int
	freeUserCalls int
}

func (m *bruteForceServiceMock) List(ctx *gin.Context) {
	m.listCalls++
	ctx.JSON(http.StatusOK, gin.H{"ok": true})
}

func (m *bruteForceServiceMock) FreeIP(ctx *gin.Context) {
	m.freeIPCalls++
	ctx.JSON(http.StatusOK, gin.H{"ok": true})
}

func (m *bruteForceServiceMock) FreeUser(ctx *gin.Context) {
	m.freeUserCalls++
	ctx.JSON(http.StatusOK, gin.H{"ok": true})
}

func TestRegisterRoutes_DefaultBasePath(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	New(nil, AuthModeIDPSession, false, nil, nil, nil, nil).Register(router)

	type routeKey struct {
		method string
		path   string
	}

	have := map[routeKey]struct{}{}
	for _, route := range router.Routes() {
		have[routeKey{method: route.Method, path: route.Path}] = struct{}{}
	}

	want := []routeKey{
		{method: http.MethodGet, path: "/admin"},
		{method: http.MethodGet, path: "/admin/login"},
		{method: http.MethodPost, path: "/admin/login"},
		{method: http.MethodPost, path: "/admin/logout"},
		{method: http.MethodGet, path: "/admin/partial/dashboard"},
		{method: http.MethodGet, path: "/admin/partial/bruteforce"},
		{method: http.MethodGet, path: "/admin/partial/clickhouse"},
		{method: http.MethodGet, path: "/admin/partial/hooktester"},
		{method: http.MethodGet, path: "/admin/api/bruteforce/list"},
		{method: http.MethodPost, path: "/admin/api/bruteforce/free-ip"},
		{method: http.MethodPost, path: "/admin/api/bruteforce/free-user"},
		{method: http.MethodGet, path: "/admin/api/clickhouse/query"},
		{method: http.MethodPost, path: "/admin/api/hooktester/send"},
	}

	for _, expected := range want {
		if _, ok := have[expected]; !ok {
			t.Fatalf("route missing: %s %s", expected.method, expected.path)
		}
	}
}

func TestAPIMiddlewareChain_CSRFAndOptionalOIDC(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	// API OIDC disabled: POST without token should be rejected by CSRF.
	routerCSRF := gin.New()
	New(nil, AuthModeIDPSession, false, nil, nil, nil, nil).Register(routerCSRF)

	reqNoToken := httptest.NewRequest(http.MethodPost, "/admin/api/bruteforce/free-ip", nil)
	recNoToken := httptest.NewRecorder()
	routerCSRF.ServeHTTP(recNoToken, reqNoToken)

	if recNoToken.Code != http.StatusBadRequest {
		t.Fatalf("expected CSRF rejection status %d, got %d", http.StatusBadRequest, recNoToken.Code)
	}

	// API OIDC enabled with Bearer header: rejected early when validator is not configured.
	routerOIDC := gin.New()
	New(nil, AuthModeIDPSession, true, nil, nil, nil, nil).Register(routerOIDC)

	reqBearer := httptest.NewRequest(http.MethodPost, "/admin/api/bruteforce/free-ip", nil)
	reqBearer.Header.Set("Authorization", "Bearer test-token")
	recBearer := httptest.NewRecorder()
	routerOIDC.ServeHTTP(recBearer, reqBearer)

	if recBearer.Code != http.StatusUnauthorized {
		t.Fatalf("expected OIDC middleware rejection status %d, got %d", http.StatusUnauthorized, recBearer.Code)
	}
}

func TestAuthMiddleware_AccessDecisionByMode(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name string
		mode AuthMode
	}{
		{name: "idp session", mode: AuthModeIDPSession},
		{name: "local admin", mode: AuthModeLocalAdmin},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			router := gin.New()
			handler := New(nil, tt.mode, false, nil, nil, nil, nil)
			router.GET("/auth-check", handler.authMiddleware(), func(ctx *gin.Context) {
				ctx.Status(http.StatusNoContent)
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/auth-check", nil)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("mode %q status = %d, want %d", tt.mode, rec.Code, http.StatusNoContent)
			}
		})
	}
}

func TestCSRFRejectionOnMutatingRoutes(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	New(nil, AuthModeIDPSession, false, nil, nil, nil, nil).Register(router)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "bruteforce free ip", method: http.MethodPost, path: "/admin/api/bruteforce/free-ip"},
		{name: "bruteforce free user", method: http.MethodPost, path: "/admin/api/bruteforce/free-user"},
		{name: "hook tester send", method: http.MethodPost, path: "/admin/api/hooktester/send"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %s status = %d, want %d", tt.method, tt.path, rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestBruteForceEndpoints_DelegateToService(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	mock := &bruteForceServiceMock{}

	router := gin.New()
	New(nil, AuthModeIDPSession, false, nil, mock, nil, nil).Register(router)

	// Directly call handlers to verify delegation without middleware side-effects.
	wList := httptest.NewRecorder()
	reqList := httptest.NewRequest(http.MethodGet, "/admin/api/bruteforce/list", nil)
	router.ServeHTTP(wList, reqList)

	wFreeIP := httptest.NewRecorder()
	reqFreeIP := httptest.NewRequest(http.MethodPost, "/admin/api/bruteforce/free-ip", nil)
	reqFreeIP.Header.Set("X-CSRF-Token", "test")
	router.ServeHTTP(wFreeIP, reqFreeIP)

	wFreeUser := httptest.NewRecorder()
	reqFreeUser := httptest.NewRequest(http.MethodPost, "/admin/api/bruteforce/free-user", nil)
	reqFreeUser.Header.Set("X-CSRF-Token", "test")
	router.ServeHTTP(wFreeUser, reqFreeUser)

	if mock.listCalls == 0 {
		t.Fatalf("expected List to be delegated at least once")
	}

	// CSRF middleware may block POST in this test context; verify GET delegation and direct method delegation below.
	if mock.freeIPCalls != 0 || mock.freeUserCalls != 0 {
		return
	}

	h := New(nil, AuthModeIDPSession, false, nil, mock, nil, nil)
	recIP := httptest.NewRecorder()
	ctxIP, _ := gin.CreateTestContext(recIP)
	h.BruteForceFreeIP(ctxIP)
	if recIP.Code != http.StatusOK {
		t.Fatalf("BruteForceFreeIP() status = %d, want %d", recIP.Code, http.StatusOK)
	}

	recUser := httptest.NewRecorder()
	ctxUser, _ := gin.CreateTestContext(recUser)
	h.BruteForceFreeUser(ctxUser)
	if recUser.Code != http.StatusOK {
		t.Fatalf("BruteForceFreeUser() status = %d, want %d", recUser.Code, http.StatusOK)
	}
}
