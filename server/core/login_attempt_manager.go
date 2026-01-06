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

package core

import "strconv"

// LoginAttemptManager defines a small object that centralizes initialization and
// mutation of login attempt counters from different sources (headers, brute-force buckets).
//
// Invariant: failCount counts failed authentications (0 before first failure, 1 after first failure, ...).
// Header values are interpreted as attempt ordinals (1-based) and normalized to failCount = max(0, ordinal-1).
type LoginAttemptManager interface {
	InitFromHeader(headerVal string)
	InitFromBucket(counter uint)
	OnAuthFailure()
	OnAuthSuccess()
	FailCount() uint
	AttemptOrdinal() uint
	Remaining() uint
	ShouldBlock() bool
}

type attemptSource int

const (
	srcUnknown attemptSource = iota
	srcHeader
	srcBucket
)

// defaultLoginAttemptManager is the concrete implementation used by core.
type defaultLoginAttemptManager struct {
	failCount uint
	max       uint
	from      attemptSource
}

// newLoginAttemptManager creates and returns a new defaultLoginAttemptManager with the specified maximum login attempts.
func newLoginAttemptManager(max uint) *defaultLoginAttemptManager {
	return &defaultLoginAttemptManager{max: max}
}

// InitFromHeader initializes the login attempt manager using a header value representing the ordinal of login attempts.
func (m *defaultLoginAttemptManager) InitFromHeader(headerVal string) {
	if headerVal == "" {
		return
	}

	if n, err := strconv.Atoi(headerVal); err == nil && n > 0 {
		// Header is 1-based attempt ordinal; convert to 0-based fail count.
		fc := n - 1
		if fc < 0 {
			fc = 0
		}

		if uint(fc) > m.failCount {
			m.failCount = uint(fc)
			m.from = srcHeader
		}
	}
}

// InitFromBucket initializes the login attempt manager using a bucket value representing observed authentication failures.
// If the given counter exceeds the current fail count, the fail count and source are updated to reflect the bucket state.
func (m *defaultLoginAttemptManager) InitFromBucket(counter uint) {
	// Buckets are assumed to store number of failures already observed.
	if counter > m.failCount {
		m.failCount = counter
		m.from = srcBucket
	}
}

// OnAuthFailure increments the failure count if it is less than the maximum allowed attempts.
func (m *defaultLoginAttemptManager) OnAuthFailure() {
	if m.failCount < m.max {
		m.failCount++
	}
}

// OnAuthSuccess resets the failure count to zero after a successful authentication attempt.
func (m *defaultLoginAttemptManager) OnAuthSuccess() {
	m.failCount = 0
}

// FailCount returns the current count of failed authentication attempts.
func (m *defaultLoginAttemptManager) FailCount() uint {
	return m.failCount
}

// AttemptOrdinal returns the 1-based ordinal number of the current authentication attempt considering failures so far.
func (m *defaultLoginAttemptManager) AttemptOrdinal() uint {
	return m.failCount + 1
}

// Remaining returns the number of authentication attempts left before reaching the maximum allowed attempts.
func (m *defaultLoginAttemptManager) Remaining() uint {
	if m.failCount >= m.max {
		return 0
	}

	return m.max - m.failCount
}

func (m *defaultLoginAttemptManager) ShouldBlock() bool { return m.failCount >= m.max }

var _ LoginAttemptManager = (*defaultLoginAttemptManager)(nil)

// ensureLAM returns the lazily initialized login attempt manager bound to the AuthState.
// It also guarantees that the AuthState.LoginAttempts field reflects the internal fail count
// to keep legacy consumers working while the migration proceeds.
func (a *AuthState) ensureLAM() *defaultLoginAttemptManager {
	if a == nil {
		return nil
	}

	if a.attempts == nil {
		a.attempts = newLoginAttemptManager(uint(getDefaultEnvironment().GetMaxLoginAttempts()))
	}

	// keep legacy mirror in sync (FailCount semantics)
	a.LoginAttempts = a.attempts.FailCount()

	return a.attempts
}
