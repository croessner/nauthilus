package limit

import (
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/definitions"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"
)

// IPRateLimiter manages rate limiters for individual IP addresses.
type IPRateLimiter struct {
	ips *cache.Cache
	mu  sync.RWMutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter creates a new IPRateLimiter with the specified rate and burst.
// r: Number of tokens per second.
// b: Maximum burst size.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: cache.New(5*time.Minute, 10*time.Minute),
		r:   r,
		b:   b,
	}
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
func (i *IPRateLimiter) Middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Skip rate limiting for health check and metrics
		if ctx.FullPath() == "/ping" || ctx.FullPath() == "/metrics" {
			ctx.Next()

			return
		}

		ip := ctx.ClientIP()
		limiter := i.GetLimiter(ip)

		if !limiter.Allow() {
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				definitions.LogKeyMsg: "Rate limit exceeded",
				"ip":                  ip,
			})

			ctx.Abort()

			return
		}

		ctx.Next()
	}
}
