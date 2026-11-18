// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// steppedRuntimeClock is a settable runtime clock for idle-expiry tests.
type steppedRuntimeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current test time.
func (c *steppedRuntimeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// advance moves the test time forward.
func (c *steppedRuntimeClock) advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(delta)
}

// idleSessionFixture is one authenticated canonical session whose clock and Redis TTLs advance together.
type idleSessionFixture struct {
	*loginCompletionFixture
	clock  *steppedRuntimeClock
	cookie *http.Cookie
}

// newIdleSessionFixture completes one primary login with the requested remember-me TTL.
func newIdleSessionFixture(t *testing.T, rememberTTL time.Duration) *idleSessionFixture {
	t.Helper()

	clock := &steppedRuntimeClock{now: time.Date(2026, time.August, 17, 18, 0, 0, 0, time.UTC)}
	fixture := &idleSessionFixture{loginCompletionFixture: newLoginCompletionFixtureWithClock(t, clock), clock: clock}

	seedLoginCompletionProtocolFlows(t, fixture.loginCompletionFixture)
	fixture.refreshSession(t)

	writer := httptest.NewRecorder()
	if _, err := fixture.session.CompleteLogin(context.Background(), writer, fixture.input(rememberTTL)); err != nil {
		t.Fatalf("complete login: %v", err)
	}

	cookies := writer.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login completion emitted no envelope")
	}

	fixture.cookie = cookies[len(cookies)-1]

	return fixture
}

// advance moves the runtime clock and the Redis TTLs by the same amount.
func (f *idleSessionFixture) advance(delta time.Duration) {
	f.clock.advance(delta)
	f.redis.FastForward(delta)
}

// open loads the session as one browser request does.
func (f *idleSessionFixture) open() (*CanonicalSession, error) {
	request := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	request.AddCookie(f.cookie)

	return f.runtime.Open(context.Background(), request)
}

// TestCanonicalSessionIdleExpirySlidesWithActivity proves that browser activity extends the idle window up to
// the absolute lifetime, while a session without activity still ends after one idle window.
func TestCanonicalSessionIdleExpirySlidesWithActivity(t *testing.T) {
	t.Parallel()

	for _, rememberTTL := range []time.Duration{0, 24 * time.Hour} {
		t.Run(rememberTTL.String(), func(t *testing.T) {
			t.Parallel()

			fixture := newIdleSessionFixture(t, rememberTTL)

			for step := range 6 {
				fixture.advance(10 * time.Minute)

				session, err := fixture.open()
				if err != nil {
					t.Fatalf("active session rejected %d minutes after login: %v", (step+1)*10, err)
				}

				if !session.Anchor.Value.Authenticated {
					t.Fatalf("active session lost its identity: %#v", session.Anchor.Value)
				}
			}

			fixture.advance(canonicalIdleTTL + time.Second)

			if _, err := fixture.open(); !errors.Is(err, ErrEnvelopeRejected) {
				t.Fatalf("idle session error = %v, want rejection after one idle window", err)
			}
		})
	}
}
