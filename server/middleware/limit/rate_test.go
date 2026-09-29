package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
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

// serveRequest sends one request with the given method and path from remoteAddr.
func serveRequest(r *gin.Engine, method string, path string, remoteAddr string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr

	r.ServeHTTP(w, req)

	return w
}

// newExemptRouteTestRouter builds a router whose GET /exempt route is exempted from the global middleware and
// whose handler uses the limiter as failure budget, like the backchannel caller authentication. Requests without
// ?authenticated=true count as failed caller authentications.
func newExemptRouteTestRouter(limiter *IPRateLimiter) *gin.Engine {
	r := gin.New()
	r.Use(limiter.Middleware())

	handler := func(c *gin.Context) {
		if limiter.AbortIfExhausted(c) {
			return
		}

		if c.Query("authenticated") != "true" {
			limiter.ChargeFailure(c)
			c.Status(http.StatusUnauthorized)

			return
		}

		c.Status(http.StatusNoContent)
	}

	plain := func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	}

	r.GET("/exempt", handler)
	r.POST("/exempt", plain)
	r.GET("/other", plain)

	limiter.ExemptRoute(http.MethodGet, "/exempt")

	return r
}

// TestIPRateLimiterExemptRouteSkipsGlobalMiddleware pins that an exempted route is not limited by the global
// middleware, while the same path with another method and all other routes keep the limit.
func TestIPRateLimiterExemptRouteSkipsGlobalMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := newExemptRouteTestRouter(NewIPRateLimiter(rate.Limit(0.001), 2))

	for range 10 {
		assert.Equal(t, http.StatusNoContent, serveRequest(r, http.MethodGet, "/exempt?authenticated=true", "192.0.2.20:1234").Code)
	}

	assert.Equal(t, http.StatusNoContent, serveRequest(r, http.MethodPost, "/exempt?authenticated=true", "192.0.2.21:1234").Code)
	assert.Equal(t, http.StatusNoContent, serveRequest(r, http.MethodPost, "/exempt?authenticated=true", "192.0.2.21:1234").Code)
	assert.Equal(t, http.StatusTooManyRequests, serveRequest(r, http.MethodPost, "/exempt?authenticated=true", "192.0.2.21:1234").Code)

	assert.Equal(t, http.StatusNoContent, serveRequest(r, http.MethodGet, "/other", "192.0.2.22:1234").Code)
	assert.Equal(t, http.StatusNoContent, serveRequest(r, http.MethodGet, "/other", "192.0.2.22:1234").Code)
	assert.Equal(t, http.StatusTooManyRequests, serveRequest(r, http.MethodGet, "/other", "192.0.2.22:1234").Code)
}

// TestIPRateLimiterFailureBudget pins that only charged failures consume the budget, and that an exhausted budget
// rejects every request of the address with the unchanged rate-limit response.
func TestIPRateLimiterFailureBudget(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := newExemptRouteTestRouter(NewIPRateLimiter(rate.Limit(0.001), 2))

	const remoteAddr = "192.0.2.30:1234"

	assert.Equal(t, http.StatusUnauthorized, serveRequest(r, http.MethodGet, "/exempt", remoteAddr).Code)
	assert.Equal(t, http.StatusUnauthorized, serveRequest(r, http.MethodGet, "/exempt", remoteAddr).Code)

	limited := serveRequest(r, http.MethodGet, "/exempt?authenticated=true", remoteAddr)

	assert.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.JSONEq(t, `{"msg":"Rate limit exceeded","scope":"rate","ip":"192.0.2.30"}`, limited.Body.String())
	assert.Equal(t, http.StatusTooManyRequests, serveRequest(r, http.MethodGet, "/other", remoteAddr).Code)
}

// TestIPRateLimiterFailureBudgetSharesGlobalState pins that the global middleware and the failure budget draw on
// one per-IP state.
func TestIPRateLimiterFailureBudgetSharesGlobalState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := newExemptRouteTestRouter(NewIPRateLimiter(rate.Limit(0.001), 2))

	const remoteAddr = "192.0.2.31:1234"

	assert.Equal(t, http.StatusNoContent, serveRequest(r, http.MethodGet, "/other", remoteAddr).Code)
	assert.Equal(t, http.StatusUnauthorized, serveRequest(r, http.MethodGet, "/exempt", remoteAddr).Code)
	assert.Equal(t, http.StatusTooManyRequests, serveRequest(r, http.MethodGet, "/exempt?authenticated=true", remoteAddr).Code)
}

// TestIPRateLimiterAbortIfExhaustedDoesNotConsume pins that the budget check alone never consumes a token.
func TestIPRateLimiterAbortIfExhaustedDoesNotConsume(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewIPRateLimiter(rate.Limit(0.001), 1)

	for range 10 {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodGet, "/exempt", nil)

		assert.False(t, limiter.AbortIfExhausted(ctx))
	}
}

// TestIPRateLimiterAbortIfExhaustedSetsReason pins the context reason that the access log reports for 429 answers.
func TestIPRateLimiterAbortIfExhaustedSetsReason(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewIPRateLimiter(0, 0)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/exempt", nil)

	assert.True(t, limiter.AbortIfExhausted(ctx))
	assert.True(t, ctx.IsAborted())
	assert.Equal(t, limitScopeRate, ctx.GetString(definitions.CtxRateLimitReasonKey))
}
