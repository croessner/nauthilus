// Copyright (C) 2024 Christian Rößner
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

package csrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNewHandler(t *testing.T) {
	h := NewHandler()

	if h == nil {
		t.Fatal("NewHandler() returned nil")
	}

	if h.generator == nil {
		t.Error("NewHandler() generator is nil")
	}

	if h.masker == nil {
		t.Error("NewHandler() masker is nil")
	}

	if h.validator == nil {
		t.Error("NewHandler() validator is nil")
	}

	if h.encoder == nil {
		t.Error("NewHandler() encoder is nil")
	}

	if h.originValidator == nil {
		t.Error("NewHandler() originValidator is nil")
	}
}

func TestNewHandler_WithOptions(t *testing.T) {
	customCookie := http.Cookie{
		Name:   "custom_csrf",
		MaxAge: 100,
	}

	customHandler := func(ctx *gin.Context) {
		ctx.String(http.StatusTeapot, "custom failure")
		ctx.Abort()
	}

	h := NewHandler(
		WithBaseCookie(customCookie),
		WithFailureHandler(customHandler),
	)

	if h.baseCookie.Name != "custom_csrf" {
		t.Errorf("WithBaseCookie() name = %s, want custom_csrf", h.baseCookie.Name)
	}

	if h.baseCookie.MaxAge != 100 {
		t.Errorf("WithBaseCookie() maxAge = %d, want 100", h.baseCookie.MaxAge)
	}
}

func TestMiddleware_GETRequest(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())
	router.GET("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET request status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should set a CSRF cookie
	cookies := w.Result().Cookies()
	found := false

	for _, c := range cookies {
		if c.Name == CookieName {
			found = true

			break
		}
	}

	if !found {
		t.Error("GET request should set CSRF cookie")
	}
}

func TestMiddleware_POSTWithoutToken(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())
	router.POST("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("Host", "localhost")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != FailureCode {
		t.Errorf("POST without token status = %d, want %d", w.Code, FailureCode)
	}
}

func TestMiddleware_POSTWithValidToken(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())

	var csrfToken string

	router.GET("/get-token", func(ctx *gin.Context) {
		csrfToken = h.Token(ctx)
		ctx.String(http.StatusOK, csrfToken)
	})
	router.POST("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	// First, get a token
	getReq := httptest.NewRequest(http.MethodGet, "http://example.com/get-token", nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("GET token request failed: %d", getW.Code)
	}

	csrfToken = getW.Body.String()
	cookies := getW.Result().Cookies()

	// Now POST with the token
	postBody := strings.NewReader(FormFieldName + "=" + url.QueryEscape(csrfToken))
	postReq := httptest.NewRequest(http.MethodPost, "http://example.com/test", postBody)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Origin", "http://example.com")

	for _, c := range cookies {
		postReq.AddCookie(c)
	}

	postW := httptest.NewRecorder()
	router.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Errorf("POST with valid token status = %d, want %d", postW.Code, http.StatusOK)
	}
}

func TestMiddleware_POSTWithHeaderToken(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())

	var csrfToken string

	router.GET("/get-token-h", func(ctx *gin.Context) {
		csrfToken = h.Token(ctx)
		ctx.String(http.StatusOK, csrfToken)
	})
	router.POST("/test-h", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	// First, get a token
	getReq := httptest.NewRequest(http.MethodGet, "http://example.com/get-token-h", nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)

	csrfToken = getW.Body.String()
	cookies := getW.Result().Cookies()

	// Now POST with the token in header
	postReq := httptest.NewRequest(http.MethodPost, "http://example.com/test-h", nil)
	postReq.Header.Set(HeaderName, csrfToken)
	postReq.Header.Set("Origin", "http://example.com")

	for _, c := range cookies {
		postReq.AddCookie(c)
	}

	postW := httptest.NewRecorder()
	router.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Errorf("POST with header token status = %d, want %d", postW.Code, http.StatusOK)
	}
}

func TestMiddleware_SafeMethods(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())

	methods := []string{"GET", "HEAD", "OPTIONS", "TRACE"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			router.Handle(method, "/safe-"+method, func(ctx *gin.Context) {
				ctx.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(method, "/safe-"+method, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("%s request status = %d, want %d", method, w.Code, http.StatusOK)
			}
		})
	}
}

func TestMiddleware_SecFetchSite(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())

	var csrfToken string

	router.GET("/get-token", func(ctx *gin.Context) {
		csrfToken = h.Token(ctx)
		ctx.String(http.StatusOK, csrfToken)
	})
	router.POST("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	// Get token first
	getReq := httptest.NewRequest(http.MethodGet, "http://example.com/get-token", nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)

	csrfToken = getW.Body.String()
	cookies := getW.Result().Cookies()

	// POST with Sec-Fetch-Site: same-origin should pass origin checks
	postBody := strings.NewReader(FormFieldName + "=" + url.QueryEscape(csrfToken))
	postReq := httptest.NewRequest(http.MethodPost, "http://example.com/test", postBody)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")

	for _, c := range cookies {
		postReq.AddCookie(c)
	}

	postW := httptest.NewRecorder()
	router.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Errorf("POST with Sec-Fetch-Site: same-origin status = %d, want %d", postW.Code, http.StatusOK)
	}
}

func TestMiddleware_InvalidOrigin(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())

	var csrfToken string

	router.GET("/get-token", func(ctx *gin.Context) {
		csrfToken = h.Token(ctx)
		ctx.String(http.StatusOK, csrfToken)
	})
	router.POST("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	// Get token first
	getReq := httptest.NewRequest(http.MethodGet, "/get-token", nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)

	csrfToken = getW.Body.String()
	cookies := getW.Result().Cookies()

	// POST with different origin should fail
	postBody := strings.NewReader(FormFieldName + "=" + url.QueryEscape(csrfToken))
	postReq := httptest.NewRequest(http.MethodPost, "/test", postBody)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Origin", "http://evil.com")
	postReq.Host = "localhost"

	for _, c := range cookies {
		postReq.AddCookie(c)
	}

	postW := httptest.NewRecorder()
	router.ServeHTTP(postW, postReq)

	if postW.Code != FailureCode {
		t.Errorf("POST with invalid origin status = %d, want %d", postW.Code, FailureCode)
	}
}

func TestToken_WithoutMiddleware(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(ctx *gin.Context) {
		token := Token(ctx)
		ctx.String(http.StatusOK, token)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should return empty string when middleware not used
	if w.Body.String() != "" {
		t.Errorf("Token() without middleware = %q, want empty string", w.Body.String())
	}
}

func TestNew(t *testing.T) {
	mw := New()

	if mw == nil {
		t.Fatal("New() returned nil")
	}
}

func TestDefaultOriginValidator_SameOrigin(t *testing.T) {
	validator := NewOriginValidator()
	selfOrigin := &url.URL{Scheme: "https", Host: "example.com"}

	tests := []struct {
		name       string
		origin     string
		referer    string
		wantErr    bool
		errMessage string
	}{
		{
			name:    "same origin header",
			origin:  "https://example.com",
			wantErr: false,
		},
		{
			name:       "different origin header",
			origin:     "https://evil.com",
			wantErr:    true,
			errMessage: "bad origin",
		},
		{
			name:    "same origin via referer",
			referer: "https://example.com/page",
			wantErr: false,
		},
		{
			name:       "different origin via referer",
			referer:    "https://evil.com/page",
			wantErr:    true,
			errMessage: "bad referer",
		},
		{
			name:       "no origin or referer",
			wantErr:    true,
			errMessage: "no referer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test", nil)

			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			err := validator.ValidateOrigin(req, selfOrigin)

			if tt.wantErr && err == nil {
				t.Error("ValidateOrigin() should return error")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("ValidateOrigin() error = %v", err)
			}
		})
	}
}

func TestDefaultOriginValidator_AllowedOrigins(t *testing.T) {
	validator := NewOriginValidator("https://trusted.com", "https://partner.com")
	selfOrigin := &url.URL{Scheme: "https", Host: "example.com"}

	tests := []struct {
		name    string
		origin  string
		wantErr bool
	}{
		{
			name:    "self origin",
			origin:  "https://example.com",
			wantErr: false,
		},
		{
			name:    "trusted origin",
			origin:  "https://trusted.com",
			wantErr: false,
		},
		{
			name:    "partner origin",
			origin:  "https://partner.com",
			wantErr: false,
		},
		{
			name:    "untrusted origin",
			origin:  "https://evil.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test", nil)
			req.Header.Set("Origin", tt.origin)

			err := validator.ValidateOrigin(req, selfOrigin)

			if tt.wantErr && err == nil {
				t.Error("ValidateOrigin() should return error")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("ValidateOrigin() error = %v", err)
			}
		})
	}
}

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		name string
		u1   *url.URL
		u2   *url.URL
		want bool
	}{
		{
			name: "same origin",
			u1:   &url.URL{Scheme: "https", Host: "example.com"},
			u2:   &url.URL{Scheme: "https", Host: "example.com"},
			want: true,
		},
		{
			name: "different scheme",
			u1:   &url.URL{Scheme: "https", Host: "example.com"},
			u2:   &url.URL{Scheme: "http", Host: "example.com"},
			want: false,
		},
		{
			name: "different host",
			u1:   &url.URL{Scheme: "https", Host: "example.com"},
			u2:   &url.URL{Scheme: "https", Host: "other.com"},
			want: false,
		},
		{
			name: "different port",
			u1:   &url.URL{Scheme: "https", Host: "example.com:443"},
			u2:   &url.URL{Scheme: "https", Host: "example.com:8443"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameOrigin(tt.u1, tt.u2); got != tt.want {
				t.Errorf("sameOrigin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_RegenerateToken(t *testing.T) {
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())

	var token1, token2 string

	router.GET("/get", func(ctx *gin.Context) {
		token1 = h.Token(ctx)
		token2 = h.RegenerateToken(ctx)
		ctx.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/get", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if token1 == "" {
		t.Error("Token() should return non-empty string")
	}

	if token2 == "" {
		t.Error("RegenerateToken() should return non-empty string")
	}

	if token1 == token2 {
		t.Error("RegenerateToken() should generate a new token")
	}
}

func TestHandler_Reason(t *testing.T) {
	var reason error

	h := NewHandler(
		WithFailureHandler(func(ctx *gin.Context) {
			// Get the csrfContext from context to access the reason
			csrfCtx, ok := ctx.Get(csrfContextKey)
			if ok {
				if c, ok := csrfCtx.(*csrfContext); ok {
					reason = c.reason
				}
			}
			ctx.String(FailureCode, "failed")
			ctx.Abort()
		}),
	)

	router := gin.New()
	router.Use(h.Middleware())
	router.POST("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	// POST without token should set a reason
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Origin", "http://localhost")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if reason == nil {
		t.Error("Reason() should return error for failed CSRF check")
	}
}

func TestHandler_SetBaseCookie(t *testing.T) {
	h := NewHandler()
	customCookie := http.Cookie{
		Name:     "my_csrf",
		Domain:   "example.com",
		Secure:   true,
		HttpOnly: true,
	}

	h.SetBaseCookie(customCookie)

	if h.baseCookie.Name != "my_csrf" {
		t.Errorf("SetBaseCookie() name = %s, want my_csrf", h.baseCookie.Name)
	}
}

func TestHandler_SetFailureHandler(t *testing.T) {
	h := NewHandler()
	customHandler := func(ctx *gin.Context) {
		ctx.String(http.StatusTeapot, "I'm a teapot")
		ctx.Abort()
	}

	h.SetFailureHandler(customHandler)

	router := gin.New()
	router.Use(h.Middleware())
	router.POST("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Origin", "http://localhost")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("SetFailureHandler() status = %d, want %d", w.Code, http.StatusTeapot)
	}
}

func TestGetToken(t *testing.T) {
	// GetToken is an alias for Token
	h := NewHandler()
	router := gin.New()
	router.Use(h.Middleware())

	var token1, token2 string

	router.GET("/test", func(ctx *gin.Context) {
		token1 = Token(ctx)
		token2 = GetToken(ctx)
		ctx.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if token1 != token2 {
		t.Error("Token() and GetToken() should return the same value")
	}
}
