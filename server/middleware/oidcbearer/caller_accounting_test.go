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

package oidcbearer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	servererrors "github.com/croessner/nauthilus/v4/server/errors"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	// repeatedBearerAttempts exceeds every former lockout threshold by a wide margin.
	repeatedBearerAttempts = 20
	// bearerTestProxy is a trusted proxy that aggregates many backchannel callers.
	bearerTestProxy = "203.0.113.63"
)

// bearerAccountingConfig enables the brute-force control, which must never turn into a lockout of
// backchannel callers, and trusts one proxy.
func bearerAccountingConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	var bruteForce config.RuntimeModule
	if err := bruteForce.Set(definitions.ControlBruteForce); err != nil {
		t.Fatalf("set brute-force control: %v", err)
	}

	return &config.FileSettings{Server: &config.ServerSection{
		RuntimeModules: []*config.RuntimeModule{&bruteForce},
		TrustedProxies: []string{bearerTestProxy},
	}}
}

// serveBearerRequest sends one request from ip through the authenticate-scope middleware. An empty
// authorization sends no Authorization header.
func serveBearerRequest(cfg config.File, validator TokenValidator, ip string, authorization string) *httptest.ResponseRecorder {
	router := gin.New()
	router.Use(Middleware(validator, cfg, nil))
	router.GET("/api/v1/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	request.RemoteAddr = ip + ":40000"

	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	return recorder
}

// httpCallerAuthCount reads one HTTP outcome of the backchannel caller authentication counter.
func httpCallerAuthCount(outcome string) float64 {
	return testutil.ToFloat64(stats.GetMetrics().GetBackchannelCallerAuthTotal().WithLabelValues(mdauth.CallerTransportHTTP, outcome))
}

// TestMiddlewareRepeatedRejectionsNeverBlock pins that neither invalid nor missing Bearer tokens ever block a
// caller address, including a trusted proxy that aggregates many callers: every rejection stays 401 and a
// valid token from the same address always passes.
func TestMiddlewareRepeatedRejectionsNeverBlock(t *testing.T) {
	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(time.Millisecond))

	for _, ip := range []string{"203.0.113.61", bearerTestProxy} {
		t.Run(ip, func(t *testing.T) {
			cfg := bearerAccountingConfig(t)
			invalid := &mockTokenValidator{err: errors.New("invalid token")}
			rejectedBefore := httpCallerAuthCount("rejected")

			for attempt := range repeatedBearerAttempts {
				authorization := "Bearer forged"
				if attempt%2 == 1 {
					authorization = ""
				}

				if recorder := serveBearerRequest(cfg, invalid, ip, authorization); recorder.Code != http.StatusUnauthorized {
					t.Fatalf("attempt %d status = %d, want %d", attempt+1, recorder.Code, http.StatusUnauthorized)
				}
			}

			if got := httpCallerAuthCount("rejected") - rejectedBefore; got != repeatedBearerAttempts {
				t.Fatalf("rejected outcomes = %v, want %d", got, repeatedBearerAttempts)
			}

			valid := &mockTokenValidator{claims: backchannelAccessClaims(definitions.ScopeAuthenticate)}
			if recorder := serveBearerRequest(cfg, valid, ip, "Bearer valid"); recorder.Code != http.StatusOK {
				t.Fatalf("valid token after rejections status = %d, want %d", recorder.Code, http.StatusOK)
			}
		})
	}
}

// TestMiddlewareRejectionIsDelayed pins the fixed delay of a genuine rejection, the only brake left.
func TestMiddlewareRejectionIsDelayed(t *testing.T) {
	const delay = 50 * time.Millisecond

	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(delay))

	cfg := bearerAccountingConfig(t)

	started := time.Now()

	if recorder := serveBearerRequest(cfg, &mockTokenValidator{err: errors.New("invalid token")}, "203.0.113.64", "Bearer forged"); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("rejected token status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	if elapsed := time.Since(started); elapsed < delay {
		t.Fatalf("rejection answered after %s, want at least %s", elapsed, delay)
	}
}

// TestMiddlewareAnswersUndecidedValidationWithServiceUnavailable pins that an unreachable token store is
// reported as a temporary failure, recorded as unavailable, and never delayed like a rejection.
func TestMiddlewareAnswersUndecidedValidationWithServiceUnavailable(t *testing.T) {
	const ip = "203.0.113.60"

	// A long delay makes any accidental rejection path visible as a slow test.
	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(time.Minute))

	cfg := bearerAccountingConfig(t)
	unavailable := &mockTokenValidator{err: servererrors.NewTokenValidationUnavailable(context.DeadlineExceeded)}
	unavailableBefore := httpCallerAuthCount("unavailable")
	rejectedBefore := httpCallerAuthCount("rejected")

	for range repeatedBearerAttempts {
		recorder := serveBearerRequest(cfg, unavailable, ip, "Bearer undecided")
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("undecided validation status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
		}

		if recorder.Header().Get("Retry-After") == "" {
			t.Fatal("undecided validation must carry Retry-After")
		}
	}

	if got := httpCallerAuthCount("unavailable") - unavailableBefore; got != repeatedBearerAttempts {
		t.Fatalf("unavailable outcomes = %v, want %d", got, repeatedBearerAttempts)
	}

	if got := httpCallerAuthCount("rejected") - rejectedBefore; got != 0 {
		t.Fatalf("rejected outcomes = %v, want 0", got)
	}
}
