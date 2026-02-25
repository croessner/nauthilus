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
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	srverrors "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

type mockLDAPConnection struct {
	state       int32
	mutex       sync.Mutex
	connError   error
	bindError   error
	searchDelay time.Duration
	searchCalls int32
	searchFunc  func(req *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error)
	searchError error
	modifyError error
}

func (m *mockLDAPConnection) SetConn(_ *ldap.Conn) {}

func (m *mockLDAPConnection) IsClosing() bool { return false }

func (m *mockLDAPConnection) Search(_ context.Context, _ config.File, _ *slog.Logger, req *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error) {

	// Count calls for tests that need to assert cache hits/misses.
	atomic.AddInt32(&m.searchCalls, 1)

	if m.searchDelay > 0 {
		time.Sleep(m.searchDelay)
	}

	if m.searchError != nil {
		return nil, nil, m.searchError
	}

	if m.searchFunc != nil {
		return m.searchFunc(req)
	}

	return nil, nil, nil
}

func (m *mockLDAPConnection) Modify(_ context.Context, _ config.File, _ *slog.Logger, _ *bktype.LDAPRequest) error {
	if m.modifyError != nil {
		return m.modifyError
	}

	return nil
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

func (m *mockLDAPConnection) Connect(_ string, _ config.File, _ *slog.Logger, _ *config.LDAPConf) error {
	return m.connError
}

func (m *mockLDAPConnection) Bind(_ context.Context, _ string, _ config.File, _ *slog.Logger, _ *config.LDAPConf) error {
	return m.bindError
}

func (m *mockLDAPConnection) GetConn() *ldap.Conn {
	return nil
}

func (m *mockLDAPConnection) Unbind() error {
	return nil
}

func TestHandleLookupRequest(t *testing.T) {
	// Initialize default config for LDAPConfigConnectAbortTimeout
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

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

			ctx := t.Context()

			dummyLDAPConf := make([]*config.LDAPConf, 0)
			dummyLDAPConf = append(dummyLDAPConf, &config.LDAPConf{})

			pool := &ldapPoolImpl{
				poolType: tc.poolType,
				name:     "test-pool",
				ctx:      ctx,
				conn:     mockConns,
				conf:     dummyLDAPConf,
				poolSize: len(mockConns),
				tokens:   make(chan Token, len(mockConns)),
				cfg:      config.GetFile(),
			}

			// Prefill tokens to simulate available capacity equal to poolSize
			for range mockConns {
				pool.tokens <- Token{}
			}

			// Reset metrics (you may skip if not using real stats library)
			stats.GetMetrics().GetLdapPoolStatus().WithLabelValues(pool.name).Set(0)

			// Call the method
			pool.HandleLookupRequest(&bktype.LDAPRequest{
				GUID:              tc.name,
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

	ctx := t.Context()

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
		tokens:   make(chan Token, 1),
		cfg:      config.GetFile(),
	}
	pool.tokens <- Token{}

	// First request consumes the single token and sleeps inside Search
	err1 := pool.HandleLookupRequest(&bktype.LDAPRequest{GUID: "r1", HTTPClientContext: ctx})
	assert.NoError(t, err1)

	// Second request should time out acquiring a token
	err2 := pool.HandleLookupRequest(&bktype.LDAPRequest{GUID: "r2", HTTPClientContext: ctx})
	assert.Error(t, err2)
	assert.ErrorIs(t, err2, srverrors.ErrLDAPPoolExhausted)
}

func TestNegativeCacheKeyUsesExpandedFilter(t *testing.T) {
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "")

	ctx := t.Context()

	conf := &config.LDAPConf{NegativeCacheTTL: 5 * time.Minute}

	m := &mockLDAPConnection{}
	m.SetState(definitions.LDAPStateBusy)
	m.searchFunc = func(req *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error) {
		// processLookupSearchRequest expands macros/%s before calling Search(), so
		// we expect the filter to already contain the username.
		switch {
		case strings.Contains(req.Filter, "missing@example.org"):
			return nil, nil, nil
		case strings.Contains(req.Filter, "exists@example.org"):
			return bktype.AttributeMapping{definitions.DistinguishedName: []any{"cn=exists,dc=example,dc=org"}}, nil, nil
		default:
			return nil, nil, nil
		}
	}

	pool := &ldapPoolImpl{
		poolType: definitions.LDAPPoolLookup,
		name:     "test-negcache-expanded-filter",
		ctx:      ctx,
		conn:     []LDAPConnection{m},
		conf:     []*config.LDAPConf{conf},
		poolSize: 1,
		cfg:      config.GetFile(),
	}

	// Request A: non-existing user. Should set a negative cache entry for the
	// expanded filter containing "missing@example.org".
	{
		reply := &bktype.LDAPReply{}
		pool.processLookupSearchRequest(0, &bktype.LDAPRequest{
			GUID:              "r1",
			Command:           definitions.LDAPSearch,
			BaseDN:            "dc=example,dc=org",
			Filter:            "(mail=%s)",
			SearchAttributes:  []string{definitions.DistinguishedName},
			MacroSource:       &util.MacroSource{Username: "missing@example.org"},
			HTTPClientContext: ctx,
		}, reply)
		assert.NoError(t, reply.Err)
		assert.Empty(t, reply.Result)
	}

	// Request B: existing user. Must NOT be blocked by the negative cache entry
	// from Request A; Search() must be called again.
	{
		reply := &bktype.LDAPReply{}
		pool.processLookupSearchRequest(0, &bktype.LDAPRequest{
			GUID:              "r2",
			Command:           definitions.LDAPSearch,
			BaseDN:            "dc=example,dc=org",
			Filter:            "(mail=%s)",
			SearchAttributes:  []string{definitions.DistinguishedName},
			MacroSource:       &util.MacroSource{Username: "exists@example.org"},
			HTTPClientContext: ctx,
		}, reply)
		assert.NoError(t, reply.Err)
		assert.NotEmpty(t, reply.Result)
		assert.Contains(t, reply.Result, definitions.DistinguishedName)
	}

	assert.Equal(t, int32(2), atomic.LoadInt32(&m.searchCalls))
}
