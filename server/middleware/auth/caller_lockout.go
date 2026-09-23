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

package auth

import (
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"

	"github.com/patrickmn/go-cache"
)

// failState tracks rejected caller authentications of one source address.
// The 64-bit fields come first so atomic access stays aligned on 32-bit platforms.
type failState struct {
	resetAtUnix   int64 // unix nano when the counting window resets
	blockedToUnix int64 // unix nano until which the source is blocked
	count         int32 // rejections in the current window
}

// lockoutPolicy is the effective lockout configuration for one decision.
type lockoutPolicy struct {
	window          time.Duration
	blockTime       time.Duration
	sleepOnFail     time.Duration
	threshold       int32
	exemptThreshold int32
}

// lockoutPolicyFor reads the configured lockout limits; unset values keep the historical defaults.
func lockoutPolicyFor(cfg config.File) lockoutPolicy {
	settings := lockoutSettings(cfg)

	return lockoutPolicy{
		window:          settings.GetWindow(),
		blockTime:       settings.GetBlockTime(),
		sleepOnFail:     settings.GetSleepOnFail(),
		threshold:       int32(settings.GetThreshold()),       // validated to at most 1000
		exemptThreshold: int32(settings.GetExemptThreshold()), // validated to at most 100000
	}
}

// forExempt returns the policy that counts one presented identity of an exempt caller.
func (p lockoutPolicy) forExempt() lockoutPolicy {
	p.threshold = p.exemptThreshold

	return p
}

// retention keeps a source's state at least until an active block and a following window have passed.
func (p lockoutPolicy) retention() time.Duration {
	return p.blockTime + p.window
}

// failureLockout blocks a source address after too many rejected caller authentications within a window.
// State is process-local by design: it protects this instance's credential checks, not a shared quota.
type failureLockout struct {
	entries          *cache.Cache
	exemptIdentities *exemptIdentityRegistry
}

// newFailureLockout creates an empty lockout table.
func newFailureLockout() *failureLockout {
	return &failureLockout{entries: cache.New(time.Hour, 10*time.Minute), exemptIdentities: newExemptIdentityRegistry()}
}

// state returns the existing state of ip or registers a fresh one without losing a concurrent registration.
func (l *failureLockout) state(ip string, policy lockoutPolicy, now time.Time) *failState {
	if value, found := l.entries.Get(ip); found {
		return value.(*failState)
	}

	fresh := &failState{resetAtUnix: now.Add(policy.window).UnixNano()}
	if err := l.entries.Add(ip, fresh, policy.retention()); err == nil {
		return fresh
	}

	if value, found := l.entries.Get(ip); found {
		return value.(*failState)
	}

	return fresh
}

// tracked reports whether key has any recorded rejection state.
func (l *failureLockout) tracked(key string) bool {
	if key == "" {
		return false
	}

	_, found := l.entries.Get(key)

	return found
}

// blocked reports whether ip is currently locked out and for how much longer.
func (l *failureLockout) blocked(ip string, policy lockoutPolicy, now time.Time) (bool, time.Duration) {
	value, found := l.entries.Get(ip)
	if !found {
		return false, 0
	}

	st := value.(*failState)

	blockedTo := atomic.LoadInt64(&st.blockedToUnix)
	if now.UnixNano() < blockedTo {
		return true, time.Duration(blockedTo - now.UnixNano())
	}

	resetFailureWindowIfElapsed(st, policy, now)

	return false, 0
}

// recordFailure counts one rejection for ip and reports whether this rejection started a new block.
// Reaching the threshold starts exactly one block and restarts counting, so a block is never extended
// by rejections that raced with it.
func (l *failureLockout) recordFailure(ip string, policy lockoutPolicy, now time.Time) bool {
	st := l.state(ip, policy, now)

	resetFailureWindowIfElapsed(st, policy, now)
	l.entries.Set(ip, st, policy.retention())

	if atomic.AddInt32(&st.count, 1) < policy.threshold {
		return false
	}

	blockedTo := atomic.LoadInt64(&st.blockedToUnix)
	if now.UnixNano() < blockedTo {
		return false
	}

	if !atomic.CompareAndSwapInt64(&st.blockedToUnix, blockedTo, now.Add(policy.blockTime).UnixNano()) {
		return false
	}

	atomic.StoreInt32(&st.count, 0)
	atomic.StoreInt64(&st.resetAtUnix, now.Add(policy.window).UnixNano())

	return true
}

// reset forgets every tracked source. It exists for tests that share the process-wide lockout.
func (l *failureLockout) reset() {
	l.entries.Flush()
	l.exemptIdentities.reset()
}

// resetFailureWindowIfElapsed maintains the counting window without locks.
func resetFailureWindowIfElapsed(st *failState, policy lockoutPolicy, now time.Time) {
	for {
		resetAt := atomic.LoadInt64(&st.resetAtUnix)
		if resetAt == 0 {
			if atomic.CompareAndSwapInt64(&st.resetAtUnix, 0, now.Add(policy.window).UnixNano()) {
				break
			}

			continue
		}

		if now.UnixNano() <= resetAt {
			break
		}

		if atomic.CompareAndSwapInt64(&st.resetAtUnix, resetAt, now.Add(policy.window).UnixNano()) {
			atomic.StoreInt32(&st.count, 0)

			break
		}
	}
}

// callerLockout is the process-wide lockout shared by every backchannel transport.
var callerLockout = newFailureLockout()
