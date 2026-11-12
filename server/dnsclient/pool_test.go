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

package dnsclient

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

const testSequentialLookups = 8

// answerAll answers every query immediately.
func answerAll(int) fakeReply {
	return fakeReply{}
}

func TestPoolSocketReuse(t *testing.T) {
	tests := []struct {
		name        string
		poolSize    int
		poolMaxUses int
		wantPorts   int
	}{
		{name: "without pool every query has its own socket", poolSize: 0, wantPorts: testSequentialLookups},
		{name: "pool reuses one socket", poolSize: 4, wantPorts: 1},
		{name: "pool replaces socket after max uses", poolSize: 4, poolMaxUses: 4, wantPorts: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFakeResolver(t, answerAll)
			client := newTestClient(t, Settings{
				Resolver:    server.address(),
				Timeout:     testLookupBudget,
				Attempts:    1,
				PoolSize:    tt.poolSize,
				PoolMaxUses: tt.poolMaxUses,
			}, nil)

			for range testSequentialLookups {
				ips, err := client.LookupIP(context.Background(), "ip4", testLookupName)

				assertListed(t, ips, err)
			}

			if _, ports := server.stats(); ports != tt.wantPorts {
				t.Fatalf("server saw %d source ports, want %d", ports, tt.wantPorts)
			}
		})
	}
}

func TestPoolRetiresSocketWithUnansweredQuery(t *testing.T) {
	// The first query is lost. Its socket must not be reused, otherwise a late
	// response could be delivered to an unrelated later query.
	server := newFakeResolver(t, dropFirst)
	observer := &recordingObserver{}
	client := newTestClient(t, Settings{
		Resolver:      server.address(),
		Timeout:       testLookupBudget,
		RetryInterval: testRetryGap,
		Attempts:      2,
		PoolSize:      4,
	}, observer)

	for range 2 {
		ips, err := client.LookupIP(context.Background(), "ip4", testLookupName)

		assertListed(t, ips, err)
	}

	// Lookup one opens two sockets (lost query, retry); lookup two reuses the retry socket.
	if observer.created != 2 || observer.reused != 1 {
		t.Fatalf("observer saw %d new and %d reused sockets, want 2 and 1", observer.created, observer.reused)
	}

	if _, ports := server.stats(); ports != 2 {
		t.Fatalf("server saw %d source ports, want 2", ports)
	}
}

func TestPoolServesConcurrentLookupsBeyondItsSize(t *testing.T) {
	const concurrent = 32

	server := newFakeResolver(t, func(int) fakeReply {
		return fakeReply{delay: testRetryGap}
	})
	client := newTestClient(t, Settings{
		Resolver: server.address(),
		Timeout:  testLookupBudget,
		Attempts: 1,
		PoolSize: 2,
	}, nil)

	var wg sync.WaitGroup

	errs := make(chan error, concurrent)

	for index := range concurrent {
		wg.Go(func() {
			// Distinct names keep the standard resolver from merging the lookups.
			name := string(rune('a'+index%26)) + string(rune('a'+index/26)) + "." + testLookupName

			_, err := client.LookupIP(context.Background(), "ip4", name)

			errs <- err
		})
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent lookup failed: %v", err)
		}
	}

	if queries, _ := server.stats(); queries != concurrent {
		t.Fatalf("server saw %d queries, want %d", queries, concurrent)
	}
}

func TestRegistrySharesClientPerSettings(t *testing.T) {
	registry := NewRegistry(nil)

	first := registry.Client(Settings{Resolver: "127.0.0.1:53"})
	second := registry.Client(Settings{Resolver: "127.0.0.1:53", Attempts: first.Settings().Attempts})
	other := registry.Client(Settings{Resolver: "127.0.0.1:53", PoolSize: 8})

	if first != second {
		t.Fatal("equal effective settings must share one client")
	}

	if first == other {
		t.Fatal("different settings must not share a client")
	}
}

func TestSettingsFromConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.File
		want Settings
	}{
		{
			name: "nil config uses defaults",
			want: Settings{
				Timeout:       definitions.DNSResolveTimeout * time.Second,
				RetryInterval: definitions.DNSResolveTimeout * time.Second / definitions.DNSLookupAttempts,
				Attempts:      definitions.DNSLookupAttempts,
				PoolMaxUses:   definitions.DNSPoolMaxUses,
			},
		},
		{
			name: "configured values are kept and the retry interval spreads over the timeout",
			cfg: &config.FileSettings{Server: &config.ServerSection{DNS: config.DNS{
				Resolver: "192.0.2.53:53",
				Timeout:  300 * time.Millisecond,
				Attempts: 3,
				PoolSize: 64,
			}}},
			want: Settings{
				Resolver:      "192.0.2.53:53",
				Timeout:       300 * time.Millisecond,
				RetryInterval: 100 * time.Millisecond,
				Attempts:      3,
				PoolSize:      64,
				PoolMaxUses:   definitions.DNSPoolMaxUses,
			},
		},
		{
			name: "explicit retry interval and socket rotation win over defaults",
			cfg: &config.FileSettings{Server: &config.ServerSection{DNS: config.DNS{
				Timeout:       time.Second,
				RetryInterval: 50 * time.Millisecond,
				Attempts:      1,
				PoolSize:      8,
				PoolMaxUses:   16,
			}}},
			want: Settings{
				Timeout:       time.Second,
				RetryInterval: 50 * time.Millisecond,
				Attempts:      1,
				PoolSize:      8,
				PoolMaxUses:   16,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SettingsFromConfig(tt.cfg); got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
