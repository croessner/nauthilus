package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestIPRateLimiter_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Allow requests within limit", func(t *testing.T) {
		r := gin.New()
		limiter := NewIPRateLimiter(rate.Limit(10), 1)
		r.Use(limiter.Middleware())
		r.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ok", w.Body.String())
	})

	t.Run("Block requests exceeding limit", func(t *testing.T) {
		r := gin.New()
		// Rate of 1 per second, burst of 1
		limiter := NewIPRateLimiter(rate.Limit(1), 1)
		r.Use(limiter.Middleware())
		r.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		// First request - allowed
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req1.RemoteAddr = "192.168.1.2:1234"
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Second request - blocked
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = "192.168.1.2:1234"
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	})

	t.Run("Separate limits for different IPs", func(t *testing.T) {
		r := gin.New()
		limiter := NewIPRateLimiter(rate.Limit(1), 1)
		r.Use(limiter.Middleware())
		r.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		// IP 1 - allowed
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req1.RemoteAddr = "192.168.1.3:1234"
		r.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// IP 2 - allowed
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = "192.168.1.4:1234"
		r.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)
	})
}

func BenchmarkIPRateLimiter_Middleware(b *testing.B) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	limiter := NewIPRateLimiter(rate.Limit(1000000), 1000000)
	r.Use(limiter.Middleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}
