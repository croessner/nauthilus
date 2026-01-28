package idp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestLoginRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := cookie.NewStore([]byte("secret"))

	t.Run("Redirect to home if already logged in", func(t *testing.T) {
		r := gin.New()
		r.Use(sessions.Sessions("test-session", store))
		r.Use(func(ctx *gin.Context) {
			session := sessions.Default(ctx)
			session.Set(definitions.CookieAccount, "testuser")
			session.Save()
			ctx.Next()
		})

		h := &FrontendHandler{} // Minimal handler for testing Login redirect

		r.GET("/login", h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/login", nil)

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/2fa/v1/register/home", w.Header().Get("Location"))
	})

	t.Run("Redirect to return_to if already logged in", func(t *testing.T) {
		r := gin.New()
		r.Use(sessions.Sessions("test-session", store))
		r.Use(func(ctx *gin.Context) {
			session := sessions.Default(ctx)
			session.Set(definitions.CookieAccount, "testuser")
			session.Save()
			ctx.Next()
		})

		h := &FrontendHandler{}

		r.GET("/login", h.Login)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/login?return_to=/foo", nil)

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/foo", w.Header().Get("Location"))
	})
}
