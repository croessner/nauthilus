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
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = clientIP + ":12345"
	req.SetBasicAuth("admin", password)

	return serveBasicAuthRequest(cfg, req)
}

// serveBasicAuthRequest executes one prepared request against a minimal Basic Auth test route.
func serveBasicAuthRequest(cfg config.File, req *http.Request) int {
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET(req.URL.Path, func(c *gin.Context) {
		if CheckAndRequireBasicAuth(c, cfg) {
			c.Status(http.StatusOK)
		}
	})

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

// TestBasicAuthForwardedExemptClientKeepsIdentityBrake reproduces the production path HAProxy -> loopback
// sidecar -> Nauthilus: the sidecar appends its TCP peer (the load balancer) to X-Forwarded-For. The load
// balancer address is exempt, so one identity with a stale password is blocked after exempt_threshold
// rejections without locking out other identities, and valid credentials always pass.
func TestBasicAuthForwardedExemptClientKeepsIdentityBrake(t *testing.T) {
	gin.SetMode(gin.TestMode)
	callerLockout.reset()

	f := &config.RuntimeModule{}
	_ = f.Set(definitions.ControlBruteForce)

	cfg := &config.FileSettings{Server: &config.ServerSection{
		RuntimeModules: []*config.RuntimeModule{f},
		TrustedProxies: []string{"127.0.0.1", "::1"},
		BasicAuth:      config.BasicAuth{Enabled: true, Username: "admin", Password: secret.New("password")},
		BackchannelLockout: config.BackchannelLockout{
			ExemptNetworks: []string{"127.0.0.0/8", "::1/128", "192.168.0.5/32", "192.168.0.6/32"},
			Threshold:      5, ExemptThreshold: 50, SleepOnFail: time.Millisecond,
		},
	}}
	attempt := func(username string, password string) int {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Forwarded-For", "203.0.113.9, 192.168.0.5")
		req.SetBasicAuth(username, password)

		return serveBasicAuthRequest(cfg, req)
	}

	for index := range 49 {
		assert.Equal(t, http.StatusUnauthorized, attempt("admin", "stale"), "rejection %d", index+1)
	}

	assert.Equal(t, http.StatusUnauthorized, attempt("admin", "stale"), "the 50th rejection is still answered")
	assert.Equal(t, http.StatusTooManyRequests, attempt("admin", "stale"), "the identity is blocked after exempt_threshold")
	assert.Equal(t, http.StatusUnauthorized, attempt("other", "stale"), "another identity behind the load balancer stays unblocked")
	assert.Equal(t, http.StatusOK, attempt("admin", "password"), "valid credentials always pass")
}
