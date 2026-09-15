package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"golang.org/x/time/rate"
)

var errCallbackAdmissionLimited = errors.New("native callback admission capacity unavailable")

var (
	errCallbackConcurrencyLimited = fmt.Errorf("%w: concurrency", errCallbackAdmissionLimited)
	errCallbackRateLimited        = fmt.Errorf("%w: rate", errCallbackAdmissionLimited)
)

type callbackAdmission struct {
	rate   *rate.Limiter
	mu     sync.Mutex
	active int
	limit  int
}

// newCallbackAdmission creates one host-owned gate from the detached registration snapshot.
func newCallbackAdmission(limits pluginapi.CallbackAdmissionLimits) *callbackAdmission {
	if limits == (pluginapi.CallbackAdmissionLimits{}) {
		return nil
	}

	return &callbackAdmission{
		rate:  rate.NewLimiter(rate.Limit(limits.RequestsPerSecond), limits.RequestsPerSecond),
		limit: limits.MaxConcurrency,
	}
}

// acquire preserves the rejection cause without consuming a rate token when concurrency is full.
func (a *callbackAdmission) acquire(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if a == nil {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active >= a.limit {
		return errCallbackConcurrencyLimited
	}

	if !a.rate.Allow() {
		return errCallbackRateLimited
	}

	a.active++

	return nil
}

// release returns callback capacity after success, failure or a recovered plugin panic.
func (a *callbackAdmission) release() {
	if a == nil {
		return
	}

	a.mu.Lock()
	a.active--
	a.mu.Unlock()
}
