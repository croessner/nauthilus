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
	"github.com/gin-gonic/gin"
)

const bearerLockoutThreshold = 2

// bearerLockoutConfig enables brute-force control with a small, fast lockout.
func bearerLockoutConfig(t *testing.T, exemptNetworks ...string) *config.FileSettings {
	t.Helper()

	var bruteForce config.RuntimeModule
	if err := bruteForce.Set(definitions.ControlBruteForce); err != nil {
		t.Fatalf("set brute-force control: %v", err)
	}

	return &config.FileSettings{Server: &config.ServerSection{
		RuntimeModules: []*config.RuntimeModule{&bruteForce},
		TrustedProxies: []string{"203.0.113.63"},
		BackchannelLockout: config.BackchannelLockout{
			ExemptNetworks: exemptNetworks,
			Threshold:      bearerLockoutThreshold,
			SleepOnFail:    time.Millisecond,
		},
	}}
}

// serveBearerRequest sends one Bearer request from ip through the authenticate-scope middleware.
func serveBearerRequest(cfg config.File, validator TokenValidator, ip string) *httptest.ResponseRecorder {
	router := gin.New()
	router.Use(Middleware(validator, cfg, nil))
	router.GET("/api/v1/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	request.RemoteAddr = ip + ":40000"
	request.Header.Set("Authorization", "Bearer presented-token")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	return recorder
}

// TestMiddlewareAnswersUndecidedValidationWithServiceUnavailable pins that an unreachable token store is
// reported as a temporary failure and never locks out the caller's address.
func TestMiddlewareAnswersUndecidedValidationWithServiceUnavailable(t *testing.T) {
	const ip = "203.0.113.60"

	cfg := bearerLockoutConfig(t)
	unavailable := &mockTokenValidator{err: servererrors.NewTokenValidationUnavailable(context.DeadlineExceeded)}

	for range 3 * bearerLockoutThreshold {
		recorder := serveBearerRequest(cfg, unavailable, ip)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("undecided validation status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
		}

		if recorder.Header().Get("Retry-After") == "" {
			t.Fatal("undecided validation must carry Retry-After")
		}
	}

	recorder := serveBearerRequest(cfg, &mockTokenValidator{err: errors.New("invalid token")}, ip)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("first genuine rejection status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

// TestMiddlewareLocksOutOnlyUntrustedCallers pins the lockout after genuine rejections, the exemption for
// exempt_networks, and that trusted_proxies alone never exempt a caller.
func TestMiddlewareLocksOutOnlyUntrustedCallers(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		exemptNetworks []string
		lastStatus     int
	}{
		{name: "untrusted address", ip: "203.0.113.61", lastStatus: http.StatusTooManyRequests},
		{name: "exempt network", ip: "203.0.113.62", exemptNetworks: []string{"203.0.113.62/32"}, lastStatus: http.StatusUnauthorized},
		{name: "trusted proxy is not exempt", ip: "203.0.113.63", lastStatus: http.StatusTooManyRequests},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := bearerLockoutConfig(t, test.exemptNetworks...)
			invalid := &mockTokenValidator{err: errors.New("invalid token")}

			for range bearerLockoutThreshold {
				if recorder := serveBearerRequest(cfg, invalid, test.ip); recorder.Code != http.StatusUnauthorized {
					t.Fatalf("rejection status = %d, want %d", recorder.Code, http.StatusUnauthorized)
				}
			}

			if recorder := serveBearerRequest(cfg, invalid, test.ip); recorder.Code != test.lastStatus {
				t.Fatalf("status after threshold = %d, want %d", recorder.Code, test.lastStatus)
			}
		})
	}
}

// TestMiddlewareExemptValidTokenPassesBlockedBucket pins the HTTP side: while the exempt Bearer counter is
// blocked, invalid tokens are throttled and a valid token is still accepted.
func TestMiddlewareExemptValidTokenPassesBlockedBucket(t *testing.T) {
	const ip = "203.0.113.70"

	cfg := bearerLockoutConfig(t, ip)
	cfg.Server.BackchannelLockout.ExemptThreshold = bearerLockoutThreshold
	invalid := &mockTokenValidator{err: errors.New("invalid token")}

	for range bearerLockoutThreshold {
		serveBearerRequest(cfg, invalid, ip)
	}

	if recorder := serveBearerRequest(cfg, invalid, ip); recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("invalid token after exempt threshold status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}

	valid := &mockTokenValidator{claims: backchannelAccessClaims(definitions.ScopeAuthenticate)}
	if recorder := serveBearerRequest(cfg, valid, ip); recorder.Code != http.StatusOK {
		t.Fatalf("valid token while the Bearer counter is blocked status = %d, want %d", recorder.Code, http.StatusOK)
	}
}
