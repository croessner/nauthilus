package limit

import (
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/util"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"
)

const limitScopeRate = "rate"

// IPRateLimiter manages rate limiters for individual IP addresses.
//
// Routes behind backchannel caller authentication are exempted from Middleware through ExemptRoute. Their
// caller-authentication middleware uses the same per-IP state as a failure budget: AbortIfExhausted rejects an
// address without budget before its credentials are checked, and ChargeFailure consumes a token only for a failed
// caller authentication. Authenticated infrastructure callers are bounded by the concurrency budget instead.
type IPRateLimiter struct {
	ips    *cache.Cache
	cfg    config.File
	exempt atomic.Pointer[map[routeKey]struct{}]
	mu     sync.RWMutex
	r      rate.Limit
	b      int
}

// routeKey identifies a registered route by method and route pattern.
type routeKey struct {
	method string
	path   string
}

// NewIPRateLimiter creates a new IPRateLimiter with the specified rate and burst.
// r: Number of tokens per second.
// b: Maximum burst size.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return NewIPRateLimiterWithConfig(r, b, nil)
}

// NewIPRateLimiterWithConfig creates an IP rate limiter using the shared
// trusted proxy configuration for client IP resolution.
func NewIPRateLimiterWithConfig(r rate.Limit, b int, cfg config.File) *IPRateLimiter {
	return &IPRateLimiter{
		ips: cache.New(5*time.Minute, 10*time.Minute),
		cfg: cfg,
		r:   r,
		b:   b,
	}
}

// NewIPRateLimiterFromConfig creates the IP rate limiter configured by runtime.servers.http.rate_limit.
func NewIPRateLimiterFromConfig(cfg config.File) *IPRateLimiter {
	return NewIPRateLimiterWithConfig(Rate(cfg.GetServer().GetRateLimitPerSecond()), cfg.GetServer().GetRateLimitBurst(), cfg)
}

// ExemptRoute removes the route with method and route pattern path from Middleware. The caller must then apply
// the limit itself through AbortIfExhausted and ChargeFailure. Routes are exempted while the router is composed; the set is replaced
// copy-on-write, so request-time lookups never take a lock.
func (i *IPRateLimiter) ExemptRoute(method string, path string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	next := make(map[routeKey]struct{})

	if current := i.exempt.Load(); current != nil {
		maps.Copy(next, *current)
	}

	next[routeKey{method: method, path: path}] = struct{}{}

	i.exempt.Store(&next)
}

// isExemptRoute reports whether the matched route of ctx was handed to its caller-authentication middleware.
func (i *IPRateLimiter) isExemptRoute(ctx *gin.Context) bool {
	exempt := i.exempt.Load()
	if exempt == nil {
		return false
	}

	_, found := (*exempt)[routeKey{method: ctx.Request.Method, path: ctx.FullPath()}]

	return found
}

// AbortIfExhausted answers with the rate-limit response and returns true when the client IP of ctx has no token
// left right now. It never consumes a token, so requests that pass it cost nothing.
func (i *IPRateLimiter) AbortIfExhausted(ctx *gin.Context) bool {
	ip := i.clientIP(ctx)
	if i.GetLimiter(ip).Tokens() >= 1 {
		return false
	}

	abortRateLimited(ctx, ip)

	return true
}

// ChargeFailure consumes one token of the client IP of ctx. Concurrent failures may drive the budget below zero,
// so every failure is charged and delays the refill instead of being forgiven.
func (i *IPRateLimiter) ChargeFailure(ctx *gin.Context) {
	i.GetLimiter(i.clientIP(ctx)).Reserve()
}

// clientIP resolves the address that owns the per-IP state of ctx through the trusted proxy configuration.
func (i *IPRateLimiter) clientIP(ctx *gin.Context) string {
	return util.RequestClientIPWithConfig(ctx, i.cfg, nil)
}

// abortRateLimited writes the rate-limit response for ip and aborts the request.
func abortRateLimited(ctx *gin.Context, ip string) {
	ctx.Set(definitions.CtxRateLimitReasonKey, limitScopeRate)

	ctx.JSON(http.StatusTooManyRequests, gin.H{
		definitions.LogKeyMsg: "Rate limit exceeded",
		limitResponseKeyScope: limitScopeRate,
		"ip":                  ip,
	})

	ctx.Abort()
}

// Rate is a helper to convert float64 to rate.Limit.
func Rate(r float64) rate.Limit {
	return rate.Limit(r)
}

// AddIP adds a new limiter for the given IP address.
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)
	i.ips.Set(ip, limiter, cache.DefaultExpiration)

	return limiter
}

// GetLimiter returns the rate limiter for the given IP address.
// If no limiter exists for the IP, it creates a new one.
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	if v, found := i.ips.Get(ip); found {
		return v.(*rate.Limiter)
	}

	return i.AddIP(ip)
}

// Middleware returns a gin middleware that performs rate limiting based on the client's IP address.
// Probe and metrics routes and routes exempted through ExemptRoute pass without counting.
func (i *IPRateLimiter) Middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if isLimitBypassPath(ctx.FullPath()) || i.isExemptRoute(ctx) {
			ctx.Next()

			return
		}

		ip := i.clientIP(ctx)
		if !i.GetLimiter(ip).Allow() {
			abortRateLimited(ctx, ip)

			return
		}

		ctx.Next()
	}
}
