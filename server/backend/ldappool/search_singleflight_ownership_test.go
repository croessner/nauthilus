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
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/go-ldap/ldap/v3"
)

// singleflightJoinWindow gives concurrent lookups time to join the in-flight search before it completes.
const singleflightJoinWindow = 200 * time.Millisecond

// blockingSearchPool is a lookup pool whose single connection holds every search until release is closed.
type blockingSearchPool struct {
	pool    *ldapPoolImpl
	conn    *mockLDAPConnection
	release chan struct{}
}

// newBlockingSearchPool creates a lookup pool that answers each search with its requested attributes.
func newBlockingSearchPool(t *testing.T, name string) *blockingSearchPool {
	t.Helper()
	setupLDAPPoolTestConfig()

	fixture := &blockingSearchPool{release: make(chan struct{})}
	fixture.conn = &mockLDAPConnection{}
	fixture.conn.SetState(definitions.LDAPStateBusy)
	fixture.conn.searchFunc = func(req *bktype.LDAPRequest) (bktype.AttributeMapping, []*ldap.Entry, error) {
		<-fixture.release

		result := bktype.AttributeMapping{definitions.DistinguishedName: []any{"uid=alice,dc=example,dc=org"}}
		for _, attribute := range req.SearchAttributes {
			result[attribute] = []any{attribute + "-value"}
		}

		return result, nil, nil
	}

	fixture.pool = &ldapPoolImpl{
		poolType: definitions.LDAPPoolLookup,
		name:     name,
		ctx:      t.Context(),
		conn:     []LDAPConnection{fixture.conn},
		conf:     []*config.LDAPConf{{}},
		poolSize: 1,
		cfg:      config.GetFile(),
	}

	isolateNegativeCache(t, name)

	return fixture
}

// lookup runs one search for the same user through the negative-cache and singleflight path.
func (f *blockingSearchPool) lookup(ctx context.Context, guid string, scope string, attributes []string) *bktype.LDAPReply {
	request := &bktype.LDAPRequest{
		GUID:              guid,
		Command:           definitions.LDAPSearch,
		BaseDN:            "dc=example,dc=org",
		Filter:            "(uid=alice)",
		SearchAttributes:  attributes,
		HTTPClientContext: ctx,
	}

	if err := request.Scope.Set(scope); err != nil {
		panic(err)
	}

	reply := &bktype.LDAPReply{}
	f.pool.processLookupSearchRequest(0, request, reply)

	return reply
}

// runConcurrently starts every lookup, lets them join one in-flight search, and returns their replies.
func (f *blockingSearchPool) runConcurrently(lookups []func() *bktype.LDAPReply) []*bktype.LDAPReply {
	replies := make([]*bktype.LDAPReply, len(lookups))

	var wg sync.WaitGroup

	for index, lookup := range lookups {
		wg.Go(func() {
			replies[index] = lookup()
		})
	}

	time.Sleep(singleflightJoinWindow)
	close(f.release)
	wg.Wait()

	return replies
}

// TestLookupSearchSingleflightRepliesOwnTheirAttributes reproduces the production "concurrent map writes" crash:
// concurrent logins for one account share one deduplicated LDAP search, and every caller then mutated the same
// attribute map (LDAP MFA decryption, native subject attribute patches) on its own goroutine.
func TestLookupSearchSingleflightRepliesOwnTheirAttributes(t *testing.T) {
	const callers = 8

	fixture := newBlockingSearchPool(t, "test-singleflight-ownership")
	attributes := []string{"mail"}
	lookups := make([]func() *bktype.LDAPReply, callers)

	for index := range lookups {
		lookups[index] = func() *bktype.LDAPReply {
			return fixture.lookup(t.Context(), fmt.Sprintf("r%d", index), "sub", attributes)
		}
	}

	replies := fixture.runConcurrently(lookups)

	if calls := atomic.LoadInt32(&fixture.conn.searchCalls); calls != 1 {
		t.Fatalf("search calls = %d, want 1 deduplicated search", calls)
	}

	seen := make(map[uintptr]int, callers)

	for index, reply := range replies {
		if reply.Err != nil || len(reply.Result) == 0 {
			t.Fatalf("reply %d = %+v, want a found user", index, reply)
		}

		identity := reflect.ValueOf(reply.Result).Pointer()
		if previous, shared := seen[identity]; shared {
			t.Fatalf("replies %d and %d share one attribute map", previous, index)
		}

		seen[identity] = index
	}

	// Each request mutates its reply exactly like the subject attribute patch does.
	var wg sync.WaitGroup

	for index, reply := range replies {
		wg.Go(func() {
			reply.Result["rns-marker"] = []any{index}
			reply.Result["mail"][0] = fmt.Sprintf("patched-%d", index)
		})
	}

	wg.Wait()

	for index, reply := range replies {
		if marker := reply.Result["rns-marker"][0]; marker != index {
			t.Fatalf("reply %d marker = %v, want its own write", index, marker)
		}

		if mail := reply.Result["mail"][0]; mail != fmt.Sprintf("patched-%d", index) {
			t.Fatalf("reply %d mail = %v, want its own write", index, mail)
		}
	}
}

// TestLookupSearchSingleflightSeparatesSearchShapes proves that concurrent searches only share a result when the
// server would answer them identically; the same filter with another scope or attribute set must not be merged.
func TestLookupSearchSingleflightSeparatesSearchShapes(t *testing.T) {
	tests := []struct {
		name        string
		otherScope  string
		otherFields []string
	}{
		{name: "attribute_set", otherScope: "sub", otherFields: []string{"memberOf"}},
		{name: "scope", otherScope: "one", otherFields: []string{"mail"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newBlockingSearchPool(t, "test-singleflight-shape-"+tc.name)
			replies := fixture.runConcurrently([]func() *bktype.LDAPReply{
				func() *bktype.LDAPReply { return fixture.lookup(t.Context(), "base", "sub", []string{"mail"}) },
				func() *bktype.LDAPReply {
					return fixture.lookup(t.Context(), "other", tc.otherScope, tc.otherFields)
				},
			})

			if calls := atomic.LoadInt32(&fixture.conn.searchCalls); calls != 2 {
				t.Fatalf("search calls = %d, want one search per distinct search shape", calls)
			}

			for index, fields := range [][]string{{"mail"}, tc.otherFields} {
				for _, field := range fields {
					if _, found := replies[index].Result[field]; !found {
						t.Fatalf("reply %d = %v, want requested attribute %q", index, replies[index].Result, field)
					}
				}
			}
		})
	}
}
