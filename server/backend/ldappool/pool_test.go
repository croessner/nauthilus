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

package ldappool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

type mockLDAPConnection struct {
	state       int32
	mutex       sync.Mutex
	connError   error
	bindError   error
	searchDelay time.Duration
}

func (m *mockLDAPConnection) SetConn(_ *ldap.Conn) {}

func (m *mockLDAPConnection) IsClosing() bool { return false }

func (m *mockLDAPConnection) Search(_ *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error) {
	if m.searchDelay > 0 {
		time.Sleep(m.searchDelay)
	}
	return nil, nil, nil
}

func (m *mockLDAPConnection) Modify(_ *bktype.LDAPRequest) error { return nil }

func (m *mockLDAPConnection) GetState() definitions.LDAPState {
	// false positive Data Race - this is thread-safe, verified by inspection
	return definitions.LDAPState(atomic.LoadInt32(&m.state))
}

func (m *mockLDAPConnection) SetState(state definitions.LDAPState) {
	// false positive Data Race - this is thread-safe, verified by inspection
	atomic.StoreInt32(&m.state, int32(state))
}

func (m *mockLDAPConnection) GetMutex() *sync.Mutex {
	return &m.mutex
}

func (m *mockLDAPConnection) Connect(_ *string, _ *config.LDAPConf) error {
	return m.connError
}

func (m *mockLDAPConnection) Bind(_ *string, _ *config.LDAPConf) error {
	return m.bindError
}

func (m *mockLDAPConnection) GetConn() *ldap.Conn {
	return nil
}

func (m *mockLDAPConnection) Unbind() error {
	return nil
}

func TestHandleLookupRequest(t *testing.T) {
	tests := []struct {
		name              string
		poolType          int
		initialConnStates []definitions.LDAPState
		expectedBusyConns int
		mockConnError     error
		mockBindError     error
	}{
		{
			name:              "single_connection_available",
			poolType:          definitions.LDAPPoolLookup,
			initialConnStates: []definitions.LDAPState{definitions.LDAPStateFree},
			expectedBusyConns: 0,
		},
		{
			name:              "all_connections_busy",
			poolType:          definitions.LDAPPoolLookup,
			initialConnStates: []definitions.LDAPState{definitions.LDAPStateBusy, definitions.LDAPStateBusy},
			expectedBusyConns: 2,
		},
		{
			name:              "connection_needs_binding",
			poolType:          definitions.LDAPPoolLookup,
			initialConnStates: []definitions.LDAPState{definitions.LDAPStateClosed},
			expectedBusyConns: 0,
		},
		{
			name:              "connection_bind_failure",
			poolType:          definitions.LDAPPoolLookup,
			initialConnStates: []definitions.LDAPState{definitions.LDAPStateClosed},
			mockBindError:     assert.AnError,
			expectedBusyConns: 0,
		},
	}

	log.SetupLogging(definitions.LogLevelNone, false, false, false, "")

	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{
			Log: config.Log{
				DbgModules: make([]*config.DbgModule, 0),
			},
		},
		LDAP: &config.LDAPSection{
			Config: &config.LDAPConf{
				ConnectAbortTimeout: 100 * time.Millisecond,
			},
		},
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockConns := make([]LDAPConnection, len(tc.initialConnStates))
			for i, state := range tc.initialConnStates {
				mockConns[i] = &mockLDAPConnection{
					state:     int32(state),
					connError: tc.mockConnError,
					bindError: tc.mockBindError,
				}
			}

			ctx, cancel := context.WithCancel(context.Background())

			defer cancel()

			dummyLDAPConf := make([]*config.LDAPConf, 0)
			dummyLDAPConf = append(dummyLDAPConf, &config.LDAPConf{})

			pool := &ldapPoolImpl{
				poolType: tc.poolType,
				name:     "test-pool",
				ctx:      ctx,
				conn:     mockConns,
				conf:     dummyLDAPConf,
				poolSize: len(mockConns),
				tokens:   make(chan struct{}, len(mockConns)),
			}

			// Prefill tokens to simulate available capacity equal to poolSize
			for i := 0; i < len(mockConns); i++ {
				pool.tokens <- struct{}{}
			}

			// Reset metrics (you may skip if not using real stats library)
			stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(pool.name).Set(0)

			// Call the method
			pool.HandleLookupRequest(&bktype.LDAPRequest{
				GUID:              &tc.name,
				HTTPClientContext: ctx,
			})

			// Give goroutines time to execute
			time.Sleep(50 * time.Millisecond)

			// Validate states of connections
			busyCount := 0
			for _, conn := range mockConns {
				if conn.(*mockLDAPConnection).GetState() == definitions.LDAPStateBusy {
					busyCount++
				}
			}

			// Assert the expected behavior
			assert.Equal(t, tc.expectedBusyConns, busyCount)
		})
	}
}

func TestSemaphoreTimeout(t *testing.T) {
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "")

	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{Log: config.Log{DbgModules: make([]*config.DbgModule, 0)}},
		LDAP:   &config.LDAPSection{Config: &config.LDAPConf{ConnectAbortTimeout: 100 * time.Millisecond}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// One connection that sleeps to hold the token
	mockConns := []LDAPConnection{
		&mockLDAPConnection{state: int32(definitions.LDAPStateFree), searchDelay: 300 * time.Millisecond},
	}

	pool := &ldapPoolImpl{
		poolType: definitions.LDAPPoolLookup,
		name:     "test-timeout",
		ctx:      ctx,
		conn:     mockConns,
		conf:     []*config.LDAPConf{{}},
		poolSize: 1,
		tokens:   make(chan struct{}, 1),
	}
	pool.tokens <- struct{}{}

	// First request consumes the single token and sleeps inside Search
	err1 := pool.HandleLookupRequest(&bktype.LDAPRequest{GUID: utilPtr("r1"), HTTPClientContext: ctx})
	assert.NoError(t, err1)

	// Second request should time out acquiring a token
	err2 := pool.HandleLookupRequest(&bktype.LDAPRequest{GUID: utilPtr("r2"), HTTPClientContext: ctx})
	assert.Error(t, err2)
}

func utilPtr(s string) *string { return &s }
