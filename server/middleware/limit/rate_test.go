package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

// setupRateLimitedRouter creates a gin router with the given rate limiter applied
// and a simple /test endpoint returning "ok".
func setupRateLimitedRouter(rateLimit rate.Limit, burst int) *gin.Engine {
	r := gin.New()
	limiter := NewIPRateLimiter(rateLimit, burst)

	r.Use(limiter.Middleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	return r
}

// serveAndRecord sends a GET /test request from the given remote address and returns the recorder.
func serveAndRecord(r *gin.Engine, remoteAddr string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = remoteAddr

	r.ServeHTTP(w, req)

	return w
}

func TestIPRateLimiter_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Allow requests within limit", func(t *testing.T) {
		r := setupRateLimitedRouter(rate.Limit(10), 1)

		w := serveAndRecord(r, "192.168.1.1:1234")

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "ok", w.Body.String())
	})

	t.Run("Block requests exceeding limit", func(t *testing.T) {
		r := setupRateLimitedRouter(rate.Limit(1), 1)

		w1 := serveAndRecord(r, "192.168.1.2:1234")
		assert.Equal(t, http.StatusOK, w1.Code)

		w2 := serveAndRecord(r, "192.168.1.2:1234")
		assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	})

	t.Run("Separate limits for different IPs", func(t *testing.T) {
		r := setupRateLimitedRouter(rate.Limit(1), 1)

		w1 := serveAndRecord(r, "192.168.1.3:1234")
		assert.Equal(t, http.StatusOK, w1.Code)

		w2 := serveAndRecord(r, "192.168.1.4:1234")
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
