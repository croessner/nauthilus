// Copyright (C) 2026 Christian Rößner
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

package backchannel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	servererrors "github.com/croessner/nauthilus/v4/server/errors"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"
	mdlimit "github.com/croessner/nauthilus/v4/server/middleware/limit"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const (
	// rateTestBurst is the per-IP burst of the rate-limit tests. The refill rate is negligible, so the tests
	// never depend on wall-clock timing.
	rateTestBurst      = 2
	rateTestRate       = 0.001
	rateTestRequests   = 10
	rateTestRemoteAddr = "198.51.100.7:40000"
	rateTestUsername   = "api-client"
	rateTestPassword   = "api-secret-1234"
	rateTestOpenAPI    = "/api/v1/openapi.yaml"
	rateTestFrontend   = "/login"
)

// rateTestRequest describes the credentials of one request in a rate-limit test.
type rateTestRequest struct {
	authorization string
	basicUser     string
	basicPassword string
}

// serveRateTestRequests sends count identical requests from one client IP and returns their status codes.
func serveRateTestRequests(router *gin.Engine, method string, path string, credentials rateTestRequest, count int) []int {
	codes := make([]int, 0, count)

	for range count {
		request := httptest.NewRequest(method, path, nil)
		request.RemoteAddr = rateTestRemoteAddr

		if credentials.basicUser != "" {
			request.SetBasicAuth(credentials.basicUser, credentials.basicPassword)
		}

		if credentials.authorization != "" {
			request.Header.Set("Authorization", credentials.authorization)
		}

		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		codes = append(codes, response.Code)
	}

	return codes
}

// repeatedStatus returns count copies of status.
func repeatedStatus(status int, count int) []int {
	codes := make([]int, count)
	for index := range codes {
		codes[index] = status
	}

	return codes
}

// limitedAfterBurst returns the expected codes of requests that answer status within the burst and 429 after it.
func limitedAfterBurst(status int, count int) []int {
	codes := repeatedStatus(http.StatusTooManyRequests, count)
	for index := range min(rateTestBurst, count) {
		codes[index] = status
	}

	return codes
}

// rateTestBasicConfig enables backchannel Basic Auth with the fixed test credentials.
func rateTestBasicConfig() config.File {
	return &config.FileSettings{Server: &config.ServerSection{BasicAuth: config.BasicAuth{
		Enabled:  true,
		Username: rateTestUsername,
		Password: secret.New(rateTestPassword),
	}}}
}

// newRateLimitedSetupRouter composes the global per-IP limiter and the production backchannel setup like the
// HTTP server does, and adds a frontend route outside the backchannel groups.
func newRateLimitedSetupRouter(t *testing.T, cfg config.File, env config.Environment) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	limiter := mdlimit.NewIPRateLimiter(rateTestRate, rateTestBurst)
	router := gin.New()
	router.Use(limiter.Middleware())

	err := Setup(router, &handlerdeps.Deps{
		Cfg:               cfg,
		Env:               env,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		CallerRateLimiter: limiter,
	})
	if err != nil {
		t.Fatalf("backchannel setup: %v", err)
	}

	router.GET(rateTestFrontend, func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	return router
}

func TestBackchannelAuthenticatedBasicCallerBypassesIPRateLimit(t *testing.T) {
	router := newRateLimitedSetupRouter(t, rateTestBasicConfig(), nil)
	valid := rateTestRequest{basicUser: rateTestUsername, basicPassword: rateTestPassword}

	codes := serveRateTestRequests(router, http.MethodGet, rateTestOpenAPI, valid, rateTestRequests)

	assert.Equal(t, repeatedStatus(http.StatusOK, rateTestRequests), codes)
}

func TestBackchannelUnauthenticatedBasicCallerKeepsIPRateLimit(t *testing.T) {
	defer mdauth.SetCallerRejectionDelayForTest(0)()

	for _, testCase := range []struct {
		name        string
		credentials rateTestRequest
	}{
		{name: "wrong password", credentials: rateTestRequest{basicUser: rateTestUsername, basicPassword: "wrong"}},
		{name: "missing credentials"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router := newRateLimitedSetupRouter(t, rateTestBasicConfig(), nil)

			codes := serveRateTestRequests(router, http.MethodGet, rateTestOpenAPI, testCase.credentials, rateTestRequests)
			assert.Equal(t, limitedAfterBurst(http.StatusUnauthorized, rateTestRequests), codes)

			// The exhausted failure budget blocks every request of the address, valid credentials included.
			valid := rateTestRequest{basicUser: rateTestUsername, basicPassword: rateTestPassword}
			assert.Equal(t, []int{http.StatusTooManyRequests}, serveRateTestRequests(router, http.MethodGet, rateTestOpenAPI, valid, 1))
		})
	}
}

func TestBackchannelSetupKeepsIPRateLimitOutsideCallerAuth(t *testing.T) {
	router := newRateLimitedSetupRouter(t, rateTestBasicConfig(), nil)
	valid := rateTestRequest{basicUser: rateTestUsername, basicPassword: rateTestPassword}

	assert.Equal(t, limitedAfterBurst(http.StatusNoContent, 4), serveRateTestRequests(router, http.MethodGet, rateTestFrontend, valid, 4))

	router = newRateLimitedSetupRouter(t, rateTestBasicConfig(), nil)
	assert.Equal(t, limitedAfterBurst(http.StatusNotFound, 4), serveRateTestRequests(router, http.MethodGet, "/api/v1/unknown/route", valid, 4))
}

func TestBackchannelDeveloperModeWithoutCallerAuthKeepsIPRateLimit(t *testing.T) {
	router := newRateLimitedSetupRouter(t, backchannelAuthConfig(false, false, false), &config.EnvironmentSettings{DevMode: true})

	codes := serveRateTestRequests(router, http.MethodGet, rateTestOpenAPI, rateTestRequest{}, 4)

	assert.Equal(t, limitedAfterBurst(http.StatusOK, 4), codes)
}

// rateTestTokenValidator accepts one token with fixed claims, reports an undecided validation for another, and
// rejects every other token. It counts how often the credential check ran.
type rateTestTokenValidator struct {
	claims jwt.MapClaims
	calls  int
}

// ValidateToken returns the fixed claims for the valid token and an error otherwise.
func (v *rateTestTokenValidator) ValidateToken(_ context.Context, token string) (jwt.MapClaims, error) {
	v.calls++

	switch token {
	case "valid-token":
		return v.claims, nil
	case "undecided-token":
		return nil, servererrors.ErrTokenValidationUnavailable
	default:
		return nil, errors.New("invalid token")
	}
}

// newRateLimitedMiddlewareRouter composes the global limiter with the backchannel caller-auth middleware for a
// probe route and the Basic-endpoint route that passes the middleware without caller authentication.
func newRateLimitedMiddlewareRouter(cfg config.File, scope string) *gin.Engine {
	router, _ := newRateLimitedMiddlewareRouterWithRate(cfg, scope, rateTestRate)

	return router
}

// newRateLimitedMiddlewareRouterWithRate is newRateLimitedMiddlewareRouter with an explicit refill rate. It also
// returns the counting token validator.
func newRateLimitedMiddlewareRouterWithRate(cfg config.File, scope string, refill float64) (*gin.Engine, *rateTestTokenValidator) {
	gin.SetMode(gin.TestMode)

	limiter := mdlimit.NewIPRateLimiter(mdlimit.Rate(refill), rateTestBurst)
	validator := &rateTestTokenValidator{claims: backchannelTestClaims(scope)}
	router := gin.New()
	router.Use(limiter.Middleware())

	group := router.Group("/api/v1")
	group.Use(backchannelAuthMiddleware(cfg, validator, slog.Default(), limiter))

	callerAuthRouteExemption{router: router, limiter: limiter}.register(func() {
		for _, path := range []string{"/auth/probe", "/" + definitions.CatAuth + "/" + definitions.ServBasic} {
			group.GET(path, func(ctx *gin.Context) {
				ctx.Status(http.StatusNoContent)
			})
		}
	})

	return router, validator
}

func TestBackchannelBearerCallerRateLimit(t *testing.T) {
	defer mdauth.SetCallerRejectionDelayForTest(0)()

	cfg := backchannelAuthConfig(false, true, false)

	for _, testCase := range []struct {
		name          string
		scope         string
		authorization string
		want          []int
	}{
		{name: "valid token bypasses the limit", scope: definitions.ScopeAuthenticate, authorization: "Bearer valid-token", want: repeatedStatus(http.StatusNoContent, rateTestRequests)},
		{name: "invalid token keeps the limit", scope: definitions.ScopeAuthenticate, authorization: "Bearer other-token", want: limitedAfterBurst(http.StatusUnauthorized, rateTestRequests)},
		{name: "missing token keeps the limit", scope: definitions.ScopeAuthenticate, want: limitedAfterBurst(http.StatusUnauthorized, rateTestRequests)},
		{name: "token without authenticate scope keeps the limit", scope: definitions.ScopeSecurity, authorization: "Bearer valid-token", want: limitedAfterBurst(http.StatusForbidden, rateTestRequests)},
		{name: "undecided validation is not a caller failure", scope: definitions.ScopeAuthenticate, authorization: "Bearer undecided-token", want: repeatedStatus(http.StatusServiceUnavailable, rateTestRequests)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router := newRateLimitedMiddlewareRouter(cfg, testCase.scope)
			credentials := rateTestRequest{authorization: testCase.authorization}

			assert.Equal(t, testCase.want, serveRateTestRequests(router, http.MethodGet, "/api/v1/auth/probe", credentials, rateTestRequests))
		})
	}
}

func TestBackchannelBasicEndpointWithoutCallerAuthKeepsIPRateLimit(t *testing.T) {
	router := newRateLimitedMiddlewareRouter(rateTestBasicConfig(), definitions.ScopeAuthenticate)
	credentials := rateTestRequest{basicUser: "user", basicPassword: "user-password"}

	codes := serveRateTestRequests(router, http.MethodGet, "/api/v1/"+definitions.CatAuth+"/"+definitions.ServBasic, credentials, 4)

	assert.Equal(t, limitedAfterBurst(http.StatusNoContent, 4), codes)
}

// TestBackchannelExhaustedFailureBudgetBlocksValidCallerBeforeCredentialCheck pins that an address which used up
// its failure budget is answered with 429 before its credentials are evaluated, and passes again after the refill.
func TestBackchannelExhaustedFailureBudgetBlocksValidCallerBeforeCredentialCheck(t *testing.T) {
	defer mdauth.SetCallerRejectionDelayForTest(0)()

	const (
		refillPerSecond = 5
		refillWait      = 300 * time.Millisecond
		probe           = "/api/v1/auth/probe"
	)

	router, validator := newRateLimitedMiddlewareRouterWithRate(backchannelAuthConfig(false, true, false), definitions.ScopeAuthenticate, refillPerSecond)
	valid := rateTestRequest{authorization: "Bearer valid-token"}

	invalid := serveRateTestRequests(router, http.MethodGet, probe, rateTestRequest{authorization: "Bearer other-token"}, rateTestBurst)
	assert.Equal(t, repeatedStatus(http.StatusUnauthorized, rateTestBurst), invalid)
	assert.Equal(t, rateTestBurst, validator.calls)

	blocked := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, probe, nil)
	request.RemoteAddr = rateTestRemoteAddr
	request.Header.Set("Authorization", valid.authorization)
	router.ServeHTTP(blocked, request)

	assert.Equal(t, http.StatusTooManyRequests, blocked.Code)
	assert.JSONEq(t, `{"msg":"Rate limit exceeded","scope":"rate","ip":"198.51.100.7"}`, blocked.Body.String())
	assert.Equal(t, rateTestBurst, validator.calls, "the credential check must not run for an exhausted address")

	time.Sleep(refillWait)

	assert.Equal(t, []int{http.StatusNoContent}, serveRateTestRequests(router, http.MethodGet, probe, valid, 1))
	assert.Equal(t, rateTestBurst+1, validator.calls)
}
