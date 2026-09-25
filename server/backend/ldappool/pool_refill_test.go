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

package ldappool

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// newRefillTestPool builds a lookup pool of closed mock slots with one configuration per slot.
func newRefillTestPool(ctx context.Context, states []definitions.LDAPState, idle int) (*ldapPoolImpl, []*mockLDAPConnection) {
	// The refill logs the slot configuration, which reads the developer mode.
	config.SetTestEnvironmentConfig(&config.EnvironmentSettings{})

	mocks := make([]*mockLDAPConnection, len(states))
	connections := make([]LDAPConnection, len(states))
	confs := make([]*config.LDAPConf, len(states))

	for index, state := range states {
		mocks[index] = &mockLDAPConnection{state: int32(state)}
		connections[index] = mocks[index]
		confs[index] = &config.LDAPConf{}
	}

	pool := newLookupTestPool(ctx, definitions.LDAPPoolLookup, connections)
	pool.conf = confs
	pool.idlePoolSize = idle
	pool.logger = slog.Default()

	return pool, mocks
}

func TestRequestIdleConnectionsNeverWaitsForALockedSlot(t *testing.T) {
	setupLDAPPoolTestConfig()

	closed := definitions.LDAPStateClosed
	pool, mocks := newRefillTestPool(t.Context(), []definitions.LDAPState{closed, closed, closed}, 2)

	// A slot whose holder never lets go, like the one stuck in a connect during the incident.
	mocks[0].mutex.Lock()
	defer mocks[0].mutex.Unlock()

	start := time.Now()

	pool.RequestIdleConnections(false)

	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("RequestIdleConnections() blocked for %s", elapsed)
	}

	deadline := time.Now().Add(2 * time.Second)
	for pool.determineOpenConnections() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("background refill opened %d connections, want 2 around the locked slot", pool.determineOpenConnections())
		}

		time.Sleep(5 * time.Millisecond)
	}

	if mocks[0].GetState() != closed {
		t.Fatal("the refill touched the locked slot")
	}
}

func TestHousekeeperLeavesBorrowedAndLockedSlotsAlone(t *testing.T) {
	setupLDAPPoolTestConfig()

	pool, mocks := newRefillTestPool(t.Context(),
		[]definitions.LDAPState{definitions.LDAPStateBusy, definitions.LDAPStateFree, definitions.LDAPStateClosed}, 1)

	mocks[1].mutex.Lock()
	defer mocks[1].mutex.Unlock()

	done := make(chan int, 1)

	go func() { done <- pool.updateConnectionsStatus() }()

	select {
	case open := <-done:
		if open != 2 {
			t.Fatalf("updateConnectionsStatus() = %d, want the borrowed and the locked slot counted as open", open)
		}
	case <-time.After(time.Second):
		t.Fatal("the housekeeper blocked behind a locked slot")
	}

	if mocks[0].GetState() != definitions.LDAPStateBusy {
		t.Fatalf("borrowed slot state = %v, want busy", mocks[0].GetState())
	}
}
