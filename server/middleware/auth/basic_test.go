package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// basicAuthTestConfig enables Basic auth together with the brute-force control, which must never turn into
// a lockout of backchannel callers.
func basicAuthTestConfig() *config.FileSettings {
	f := &config.RuntimeModule{}
	_ = f.Set(definitions.ControlBruteForce)

	return &config.FileSettings{
		Server: &config.ServerSection{
			RuntimeModules: []*config.RuntimeModule{f},
			BasicAuth: config.BasicAuth{
				Enabled:  true,
				Username: "admin",
				Password: secret.New("password"),
			},
		},
	}
}

// httpCallerAuthCount reads one HTTP outcome of the backchannel caller authentication counter.
func httpCallerAuthCount(outcome string) float64 {
	return testutil.ToFloat64(stats.GetMetrics().GetBackchannelCallerAuthTotal().WithLabelValues(CallerTransportHTTP, outcome))
}

// TestBasicAuthRepeatedRejectionsNeverBlock pins that wrong Basic credentials never block a caller address,
// neither on backchannel routes nor on the bypass routes, and that the right password always passes.
func TestBasicAuthRepeatedRejectionsNeverBlock(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Cleanup(SetCallerRejectionDelayForTest(time.Millisecond))

	cfg := basicAuthTestConfig()
	clientIP := "1.2.3.4"

	for _, path := range []string{"/metrics", "/other"} {
		t.Run(path, func(t *testing.T) {
			for range 20 {
				assert.Equal(t, http.StatusUnauthorized, serveBasicAuthAttempt(path, cfg, clientIP, "wrong"))
			}

			assert.Equal(t, http.StatusOK, serveBasicAuthAttempt(path, cfg, clientIP, "password"))
		})
	}
}

// TestBasicAuthAccountsOnlyBackchannelRoutes pins that rejections on backchannel routes are recorded while
// the bypass routes are only delayed.
func TestBasicAuthAccountsOnlyBackchannelRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Cleanup(SetCallerRejectionDelayForTest(time.Millisecond))

	cfg := basicAuthTestConfig()
	rejectedBefore := httpCallerAuthCount(callerOutcomeRejected)
	acceptedBefore := httpCallerAuthCount(callerOutcomeAccepted)

	assert.Equal(t, http.StatusUnauthorized, serveBasicAuthAttempt("/metrics", cfg, "1.2.3.5", "wrong"))
	assert.Equal(t, http.StatusUnauthorized, serveBasicAuthAttempt("/other", cfg, "1.2.3.5", "wrong"))
	assert.Equal(t, http.StatusOK, serveBasicAuthAttempt("/other", cfg, "1.2.3.5", "password"))

	assert.InDelta(t, 1, httpCallerAuthCount(callerOutcomeRejected)-rejectedBefore, 0)
	assert.InDelta(t, 1, httpCallerAuthCount(callerOutcomeAccepted)-acceptedBefore, 0)
}

// TestBasicAuthRejectionIsDelayed pins the fixed delay of a rejected Basic credential.
func TestBasicAuthRejectionIsDelayed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const delay = 50 * time.Millisecond

	t.Cleanup(SetCallerRejectionDelayForTest(delay))

	started := time.Now()

	assert.Equal(t, http.StatusUnauthorized, serveBasicAuthAttempt("/other", basicAuthTestConfig(), "1.2.3.6", "wrong"))
	assert.GreaterOrEqual(t, time.Since(started), delay)
}

// TestCallerRejectionDelayDefault pins the fixed production delay.
func TestCallerRejectionDelayDefault(t *testing.T) {
	assert.Equal(t, 300*time.Millisecond, callerRejectionDelay)
}
