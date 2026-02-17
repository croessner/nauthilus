package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestBasicAuthBruteForce_Metrics(t *testing.T) {
	gin.SetMode(gin.TestMode)

	f := &config.Feature{}
	_ = f.Set(definitions.FeatureBruteForce)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{f},
			BasicAuth: config.BasicAuth{
				Enabled:  true,
				Username: "admin",
				Password: secret.New("password"),
			},
		},
	}

	// Reset global cache
	authFailCache.Flush()

	clientIP := "1.2.3.4"

	// Trigger 5 failures on /metrics
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		router := gin.New()
		router.GET("/metrics", func(c *gin.Context) {
			if CheckAndRequireBasicAuth(c, cfg) {
				c.Status(http.StatusOK)
			}
		})

		req := httptest.NewRequest("GET", "/metrics", nil)
		req.RemoteAddr = clientIP + ":12345"
		req.SetBasicAuth("admin", "wrong")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}

	// 6th attempt should NOT be throttled on /metrics, even with correct password
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/metrics", func(c *gin.Context) {
		if CheckAndRequireBasicAuth(c, cfg) {
			c.Status(http.StatusOK)
		}
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.RemoteAddr = clientIP + ":12345"
	req.SetBasicAuth("admin", "password")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// However, failures on another path SHOULD lead to throttling
	// First, trigger 5 failures on another path
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		router := gin.New()
		router.GET("/other", func(c *gin.Context) {
			if CheckAndRequireBasicAuth(c, cfg) {
				c.Status(http.StatusOK)
			}
		})

		req := httptest.NewRequest("GET", "/other", nil)
		req.RemoteAddr = clientIP + ":12345"
		req.SetBasicAuth("admin", "wrong")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}

	// 6th attempt on /other should be throttled
	w = httptest.NewRecorder()
	router = gin.New()
	router.GET("/other", func(c *gin.Context) {
		if CheckAndRequireBasicAuth(c, cfg) {
			c.Status(http.StatusOK)
		}
	})

	req = httptest.NewRequest("GET", "/other", nil)
	req.RemoteAddr = clientIP + ":12345"
	req.SetBasicAuth("admin", "password")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
