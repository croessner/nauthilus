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
	"sync"
	"time"
)

// maxExemptIdentitiesPerScope bounds the identities counted separately behind one exempt scope.
//
// Legitimate exempt callers present a handful of identities, typically one Basic account and the Bearer
// scheme, so 1024 leaves ample headroom. The bound stops a local process from growing the lockout table
// without limit and from spreading guesses over fresh usernames to stay below exempt_threshold: beyond it,
// every new identity shares the scope's overflow counter, so the scope is counted and blocked as a whole.
const maxExemptIdentitiesPerScope = 1024

// exemptOverflowIdentity names the shared counter of a full scope. It cannot collide with a hex digest.
const exemptOverflowIdentity = "overflow"

// exemptIdentityRegistry tracks which presented identities own a separate counter within each exempt scope.
// The number of scopes is bounded by the configured exempt networks and mTLS identities.
type exemptIdentityRegistry struct {
	scopes map[string]map[string]int64 // scope -> identity digest -> expiry in unix nano
	mu     sync.Mutex
}

// newExemptIdentityRegistry creates an empty registry.
func newExemptIdentityRegistry() *exemptIdentityRegistry {
	return &exemptIdentityRegistry{scopes: make(map[string]map[string]int64)}
}

// resolve returns the counter identity for identity within scope: the identity itself while it owns a
// counter or the scope has room, otherwise the shared overflow identity. With register, a new identity
// claims room and a known identity extends its lifetime by retention.
func (r *exemptIdentityRegistry) resolve(scope string, identity string, register bool, retention time.Duration, now time.Time) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	members := r.scopes[scope]
	nowNano := now.UnixNano()
	expiry := now.Add(retention).UnixNano()

	if owned, ok := members[identity]; ok && owned > nowNano {
		if register {
			members[identity] = expiry
		}

		return identity
	}

	if len(members) >= maxExemptIdentitiesPerScope {
		pruneExpiredIdentities(members, nowNano)
	}

	if len(members) >= maxExemptIdentitiesPerScope {
		return exemptOverflowIdentity
	}

	if register {
		if members == nil {
			members = make(map[string]int64)
			r.scopes[scope] = members
		}

		members[identity] = expiry
	}

	return identity
}

// reset forgets every registered identity.
func (r *exemptIdentityRegistry) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	clear(r.scopes)
}

// pruneExpiredIdentities removes identities whose counters can no longer be active.
func pruneExpiredIdentities(members map[string]int64, nowNano int64) {
	for identity, expiry := range members {
		if expiry <= nowNano {
			delete(members, identity)
		}
	}
}
