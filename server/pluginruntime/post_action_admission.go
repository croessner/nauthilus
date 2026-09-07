package pluginruntime

import (
	"context"
	"errors"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"golang.org/x/time/rate"
)

var errPostActionAdmissionLimited = errors.New("native post-action admission capacity unavailable")

type postActionAdmission struct {
	rate   *rate.Limiter
	mu     sync.Mutex
	active int
	limit  int
}

// newPostActionAdmission creates one host-owned gate from the detached registration snapshot.
func newPostActionAdmission(limits pluginapi.PostActionAdmissionLimits) *postActionAdmission {
	if limits == (pluginapi.PostActionAdmissionLimits{}) {
		return nil
	}

	return &postActionAdmission{
		rate:  rate.NewLimiter(rate.Limit(limits.RequestsPerSecond), limits.RequestsPerSecond),
		limit: limits.MaxConcurrency,
	}
}

// acquire rejects excess callbacks without consuming a rate token when concurrency is full.
func (a *postActionAdmission) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}

	if a == nil {
		return true
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active >= a.limit || !a.rate.Allow() {
		return false
	}

	a.active++

	return true
}

// release returns callback capacity after success, failure or a recovered plugin panic.
func (a *postActionAdmission) release() {
	if a == nil {
		return
	}

	a.mu.Lock()
	a.active--
	a.mu.Unlock()
}
