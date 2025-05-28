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
	state     int32
	mutex     sync.Mutex
	connError error
	bindError error
}

func (m *mockLDAPConnection) SetConn(_ *ldap.Conn) {
	panic("implement me")
}

func (m *mockLDAPConnection) IsClosing() bool {
	panic("implement me")
}

func (m *mockLDAPConnection) Search(_ *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error) {
	return nil, nil, nil
}

func (m *mockLDAPConnection) Modify(_ *bktype.LDAPRequest) error {
	panic("implement me")
}

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
			expectedBusyConns: 1,
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
			expectedBusyConns: 1,
		},
		{
			name:              "connection_bind_failure",
			poolType:          definitions.LDAPPoolLookup,
			initialConnStates: []definitions.LDAPState{definitions.LDAPStateClosed},
			mockBindError:     assert.AnError,
			expectedBusyConns: 0,
		},
	}

	log.SetupLogging(definitions.LogLevelNone, false, false, "")

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

			waitGroup := &sync.WaitGroup{}
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
			}

			// Reset metrics (you may skip if not using real stats library)
			stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(pool.name).Set(0)

			// Call the method
			pool.HandleLookupRequest(&bktype.LDAPRequest{
				GUID:              &tc.name,
				HTTPClientContext: ctx,
			}, waitGroup)

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
