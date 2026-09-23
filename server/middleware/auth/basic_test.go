package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// serveBasicAuthAttempt executes one Basic Auth request against a minimal test route.
func serveBasicAuthAttempt(path string, cfg config.File, clientIP string, password string) int {
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET(path, func(c *gin.Context) {
		if CheckAndRequireBasicAuth(c, cfg) {
			c.Status(http.StatusOK)
		}
	})

	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = clientIP + ":12345"
	req.SetBasicAuth("admin", password)
	router.ServeHTTP(w, req)

	return w.Code
}

func TestBasicAuthBruteForce_Metrics(t *testing.T) {
	gin.SetMode(gin.TestMode)

	f := &config.RuntimeModule{}
	_ = f.Set(definitions.ControlBruteForce)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			RuntimeModules: []*config.RuntimeModule{f},
			BasicAuth: config.BasicAuth{
				Enabled:  true,
				Username: "admin",
				Password: secret.New("password"),
			},
		},
	}

	// Reset global cache
	callerLockout.reset()

	clientIP := "1.2.3.4"

	// Trigger 5 failures on /metrics
	for range 5 {
		assert.Equal(t, http.StatusUnauthorized, serveBasicAuthAttempt("/metrics", cfg, clientIP, "wrong"))
	}

	// 6th attempt should NOT be throttled on /metrics, even with correct password
	assert.Equal(t, http.StatusOK, serveBasicAuthAttempt("/metrics", cfg, clientIP, "password"))

	// However, failures on another path SHOULD lead to throttling
	// First, trigger 5 failures on another path
	for range 5 {
		assert.Equal(t, http.StatusUnauthorized, serveBasicAuthAttempt("/other", cfg, clientIP, "wrong"))
	}

	// 6th attempt on /other should be throttled
	assert.Equal(t, http.StatusTooManyRequests, serveBasicAuthAttempt("/other", cfg, clientIP, "password"))
}

// TestBasicAuthExemptValidCredentialsPassBlockedBucket pins the Basic pattern for exempt callers: wrong
// passwords are throttled once the identity counter is blocked, the right password still passes.
func TestBasicAuthExemptValidCredentialsPassBlockedBucket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	callerLockout.reset()

	f := &config.RuntimeModule{}
	_ = f.Set(definitions.ControlBruteForce)

	cfg := &config.FileSettings{Server: &config.ServerSection{
		RuntimeModules: []*config.RuntimeModule{f},
		BasicAuth:      config.BasicAuth{Enabled: true, Username: "admin", Password: secret.New("password")},
		BackchannelLockout: config.BackchannelLockout{
			Threshold: 2, ExemptThreshold: 2, SleepOnFail: time.Millisecond,
		},
	}}

	for range 2 {
		assert.Equal(t, http.StatusUnauthorized, serveBasicAuthAttempt("/other", cfg, "127.0.0.1", "wrong"))
	}

	assert.Equal(t, http.StatusTooManyRequests, serveBasicAuthAttempt("/other", cfg, "127.0.0.1", "wrong"))
	assert.Equal(t, http.StatusOK, serveBasicAuthAttempt("/other", cfg, "127.0.0.1", "password"))
}
