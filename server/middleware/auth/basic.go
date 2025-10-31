// Copyright (C) 2024 Christian Rößner
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

package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

// secureCompare compares two strings in constant time by hashing them first.
func secureCompare(a, b string) bool {
	h1 := sha256.Sum256([]byte(a))
	h2 := sha256.Sum256([]byte(b))

	return subtle.ConstantTimeCompare(h1[:], h2[:]) == 1
}

// --- Minimal brute-force protection helpers (per-IP) ---
// These helpers implement a tiny in-memory backoff and blocking for repeated auth failures.
// They are intentionally simple and local to this process.

type failState struct {
	count         int32 // number of failures in current window
	resetAtUnix   int64 // unix nano when window resets
	blockedToUnix int64 // unix nano until which IP is blocked
}

var authFailCache = cache.New(1*time.Hour, 10*time.Minute) // key: ip(string) -> *failState, TTL-based

const (
	bfWindow      = 1 * time.Minute
	bfThreshold   = 5
	bfBlockTime   = 2 * time.Minute
	bfSleepOnFail = 300 * time.Millisecond
)

// authRateLimitExceededForIP checks if given IP is currently blocked. It also resets the window when elapsed.
// Returns (exceeded, remainingBlockDuration).
func authRateLimitExceededForIP(ip string) (bool, time.Duration) {
	now := time.Now()
	var st *failState
	if v, found := authFailCache.Get(ip); found {
		st = v.(*failState)
	} else {
		st = &failState{resetAtUnix: now.Add(bfWindow).UnixNano()}
		authFailCache.Set(ip, st, cache.DefaultExpiration)
	}

	// Fast check: is currently blocked?
	blockedTo := atomic.LoadInt64(&st.blockedToUnix)
	if blockedTo > 0 {
		if now.UnixNano() < blockedTo {
			authFailCache.Set(ip, st, cache.DefaultExpiration)

			return true, time.Until(time.Unix(0, blockedTo))
		}
	}

	// Maintain/reset the sliding window without locks
	for {
		resetAt := atomic.LoadInt64(&st.resetAtUnix)
		if resetAt == 0 {
			if atomic.CompareAndSwapInt64(&st.resetAtUnix, 0, now.Add(bfWindow).UnixNano()) {
				break
			}

			continue
		}

		if now.UnixNano() <= resetAt {
			break
		}

		// window elapsed -> set new window and reset count
		if atomic.CompareAndSwapInt64(&st.resetAtUnix, resetAt, now.Add(bfWindow).UnixNano()) {
			atomic.StoreInt32(&st.count, 0)

			break
		}
		// CAS failed due to race; retry loop
	}

	authFailCache.Set(ip, st, cache.DefaultExpiration)

	return false, 0
}

// noteAuthFailureForIP increments failure count and possibly sets a block.
func noteAuthFailureForIP(ip string) {
	now := time.Now()

	var st *failState
	if v, found := authFailCache.Get(ip); found {
		st = v.(*failState)
	} else {
		st = &failState{resetAtUnix: now.Add(bfWindow).UnixNano()}
		authFailCache.Set(ip, st, cache.DefaultExpiration)
	}

	// Maintain/reset the sliding window without locks
	for {
		resetAt := atomic.LoadInt64(&st.resetAtUnix)
		if resetAt == 0 {
			if atomic.CompareAndSwapInt64(&st.resetAtUnix, 0, now.Add(bfWindow).UnixNano()) {
				break
			}

			continue
		}

		if now.UnixNano() <= resetAt {
			break
		}

		if atomic.CompareAndSwapInt64(&st.resetAtUnix, resetAt, now.Add(bfWindow).UnixNano()) {
			atomic.StoreInt32(&st.count, 0)

			break
		}
	}

	newCount := atomic.AddInt32(&st.count, 1)
	if newCount >= bfThreshold {
		atomic.StoreInt64(&st.blockedToUnix, now.Add(bfBlockTime).UnixNano())
	}

	authFailCache.Set(ip, st, cache.DefaultExpiration)
}

// MaybeThrottleAuthByIP checks if the client IP is temporarily blocked and, if so, responds with 429 and a Retry-After header.
func MaybeThrottleAuthByIP(ctx *gin.Context) bool {
	ip := ctx.ClientIP()
	if ip == "" {
		return false
	}

	exceeded, remaining := authRateLimitExceededForIP(ip)
	if exceeded {
		ctx.Header("Retry-After", strconv.Itoa(int(remaining.Seconds())))
		ctx.AbortWithStatus(http.StatusTooManyRequests)

		return true
	}

	return false
}

// ApplyAuthBackoffOnFailure notes a failure for this IP and sleeps a short duration.
func ApplyAuthBackoffOnFailure(ctx *gin.Context) {
	ip := ctx.ClientIP()
	if ip != "" {
		noteAuthFailureForIP(ip)
	}

	time.Sleep(bfSleepOnFail)
}

// CheckAndRequireBasicAuth enforces basic authentication if it's enabled in the server configuration.
// It validates credentials provided in the request against the configured username and password.
// Returns true if authentication is successful or not required, false if the authentication fails or is throttled.
func CheckAndRequireBasicAuth(ctx *gin.Context) bool {
	if !config.GetFile().GetServer().GetBasicAuth().IsEnabled() {
		return true
	}

	// Simple per-IP throttling for repeated failures
	if MaybeThrottleAuthByIP(ctx) {
		return false
	}

	username, password, ok := ctx.Request.BasicAuth()
	if ok && secureCompare(username, config.GetFile().GetServer().GetBasicAuth().GetUsername()) && secureCompare(password, config.GetFile().GetServer().GetBasicAuth().GetPassword()) {
		return true
	}

	// Failure: count + small fixed delay, then respond uniformly
	ApplyAuthBackoffOnFailure(ctx)

	ctx.Header("WWW-Authenticate", "Basic realm=\"restricted\", charset=\"UTF-8\"")
	ctx.AbortWithStatus(http.StatusUnauthorized)

	return false
}

// BasicAuthMiddleware provides HTTP Basic Authentication for protected routes in a Gin application.
// It validates credentials against configured username and password, and challenges unauthorized requests.
// If basic auth is disabled or bypassed based on the route configuration, it allows the request to proceed.
func BasicAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ctx.GetString(definitions.CtxGUIDKey)

		cat := ctx.GetString(definitions.CtxCategoryKey)
		svc := ctx.GetString(definitions.CtxServiceKey)

		if cat == "" || svc == "" {
			full := ctx.FullPath()
			if full != "" {
				parts := strings.Split(strings.Trim(full, "/"), "/")
				if len(parts) >= 4 && parts[0] == "api" && parts[1] == "v1" {
					if cat == "" {
						cat = parts[2]
						ctx.Set(definitions.CtxCategoryKey, cat)
					}

					if svc == "" {
						svc = parts[3]
						ctx.Set(definitions.CtxServiceKey, svc)
					}
				}
			}
		}

		if cat == "" || svc == "" {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "missing routing context keys",
				definitions.LogKeyError, "missing routing context keys",
				"category", cat,
				"service", svc,
			)
			ctx.AbortWithStatus(http.StatusInternalServerError)

			return
		}

		// Note: Chicken-egg problem.
		if cat == definitions.CatAuth && svc == definitions.ServBasic {
			level.Warn(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Disabling HTTP basic Auth",
				"category", cat,
				"service", svc,
			)

			return
		}

		// Use shared helper to validate or challenge for Basic Auth
		if !CheckAndRequireBasicAuth(ctx) {
			return
		}

		ctx.Next()
	}
}
