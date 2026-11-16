// Copyright (C) 2026 Christian Roessner
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

package backend

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/rediscluster"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
)

const accountMappingTestPrefix = "t:"

// newAccountMappingTestReader returns a reader backed by an isolated miniredis instance.
func newAccountMappingTestReader(t *testing.T) (AccountMappingReader, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), Protocol: 2})

	t.Cleanup(func() { _ = client.Close() })

	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: accountMappingTestPrefix}}}

	return AccountMappingReader{Cfg: cfg, Redis: rediscli.NewTestClient(client)}, server
}

// storeAccountMapping writes one synthetic mapping exactly as authentication does.
func storeAccountMapping(server *miniredis.Miniredis, username, protocol, oidcClientID, account string) {
	key := rediscli.GetUserHashKey(accountMappingTestPrefix, username)
	server.HSet(key, accountcache.GetAccountMappingField(username, protocol, oidcClientID), account)
}

// sameShardUsername finds a username built from format (one %d verb) that lands in base's user-hash shard.
func sameShardUsername(t *testing.T, base string, format string) string {
	t.Helper()

	want := rediscli.GetShardID(base)

	for index := range 100000 {
		candidate := fmt.Sprintf(format, index)
		if candidate != base && rediscli.GetShardID(candidate) == want {
			return candidate
		}
	}

	t.Fatalf("no same-shard username found for %q", base)

	return ""
}

func TestAccountMappingReaderReadsOnlyOwnedFields(t *testing.T) {
	reader, server := newAccountMappingTestReader(t)
	user := "alice"
	sibling := sameShardUsername(t, user, user+"|x%d")
	globNeighbour := sameShardUsername(t, user, "alicf%d")

	storeAccountMapping(server, user, "imap", "", "alice-account")
	storeAccountMapping(server, user, "smtp", "", "alice-account")
	storeAccountMapping(server, user, "oidc", "client-a", "")
	storeAccountMapping(server, sibling, "imap", "", "sibling-account")
	storeAccountMapping(server, globNeighbour, "imap", "", "neighbour-account")

	lookup := reader.Read(context.Background(), user)

	if lookup.Err != nil {
		t.Fatalf("unexpected error: %v", lookup.Err)
	}

	if !slices.Equal(lookup.Accounts, []string{"alice-account"}) {
		t.Fatalf("accounts = %v", lookup.Accounts)
	}

	wantFields := []string{"alice|imap|", "alice|oidc|client-a", "alice|smtp|"}
	if !slices.Equal(lookup.Fields, wantFields) {
		t.Fatalf("fields = %v, want %v", lookup.Fields, wantFields)
	}
}

func TestAccountMappingReaderEscapesGlobMetacharacters(t *testing.T) {
	reader, server := newAccountMappingTestReader(t)
	user := "a*[b]?\\c"
	// Without escaping, the pattern would also match this name ("*" -> digits, "?" -> "Y").
	other := sameShardUsername(t, user, "a%dbYc")

	storeAccountMapping(server, user, "imap", "", "literal-account")
	storeAccountMapping(server, other, "imap", "", "other-account")

	lookup := reader.Read(context.Background(), user)

	if lookup.Err != nil || !slices.Equal(lookup.Accounts, []string{"literal-account"}) {
		t.Fatalf("lookup = %+v", lookup)
	}
}

func TestAccountMappingReaderReportsDistinctAccountsAndOpaqueValues(t *testing.T) {
	reader, server := newAccountMappingTestReader(t)

	storeAccountMapping(server, "shared", "imap", "", "first")
	storeAccountMapping(server, "shared", "oidc", "client-a", "second:joined")

	lookups := reader.ReadMany(context.Background(), []string{"shared", "missing"})

	if !slices.Equal(lookups[0].Accounts, []string{"first", "second:joined"}) {
		t.Fatalf("shared accounts = %v", lookups[0].Accounts)
	}

	if lookups[1].Err != nil || len(lookups[1].Accounts) != 0 || len(lookups[1].Fields) != 0 {
		t.Fatalf("missing lookup = %+v", lookups[1])
	}
}

func TestAccountMappingReaderReportsBackendFailures(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*miniredis.Miniredis) (context.Context, context.CancelFunc)
		check   func(error) bool
	}{
		{
			name: "redis error",
			prepare: func(server *miniredis.Miniredis) (context.Context, context.CancelFunc) {
				server.SetError("synthetic failure")

				return context.WithCancel(context.Background())
			},
			check: func(err error) bool { return err != nil },
		},
		{
			name: "canceled",
			prepare: func(*miniredis.Miniredis) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				return ctx, cancel
			},
			check: func(err error) bool { return errors.Is(err, context.Canceled) },
		},
		{
			name: "deadline",
			prepare: func(*miniredis.Miniredis) (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			check: func(err error) bool { return errors.Is(err, context.DeadlineExceeded) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader, server := newAccountMappingTestReader(t)
			storeAccountMapping(server, "alice", "imap", "", "alice-account")

			ctx, cancel := tc.prepare(server)
			defer cancel()

			for _, lookup := range reader.ReadMany(ctx, []string{"alice", "bob"}) {
				if !tc.check(lookup.Err) {
					t.Fatalf("%s: unexpected error %v", lookup.Username, lookup.Err)
				}
			}
		})
	}
}

func TestAccountMappingReaderWithoutRedisFailsClosed(t *testing.T) {
	lookup := AccountMappingReader{}.Read(context.Background(), "alice")

	if !errors.Is(lookup.Err, ErrAccountMappingReaderUnavailable) {
		t.Fatalf("err = %v", lookup.Err)
	}
}

func TestAccountMappingReaderFollowsCursorsInPipelinedRounds(t *testing.T) {
	db, mock := redismock.NewClientMock()
	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: accountMappingTestPrefix}}}
	reader := AccountMappingReader{Cfg: cfg, Redis: rediscli.NewTestClient(db)}
	aliceKey := rediscli.GetUserHashKey(accountMappingTestPrefix, "alice")
	bobKey := rediscli.GetUserHashKey(accountMappingTestPrefix, "bob")

	mock.ExpectHScan(aliceKey, 0, "alice|*", accountMappingScanCount).SetVal([]string{"alice|imap|", "a1", "alice|imap|", "a1"}, 7)
	mock.ExpectHScan(bobKey, 0, "bob|*", accountMappingScanCount).SetVal([]string{"bob|imap|", "b1"}, 0)
	mock.ExpectHScan(aliceKey, 7, "alice|*", accountMappingScanCount).SetVal([]string{"alice|pop3|", "a2"}, 0)

	lookups := reader.ReadMany(context.Background(), []string{"alice", "bob"})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	if !slices.Equal(lookups[0].Accounts, []string{"a1", "a2"}) || !slices.Equal(lookups[0].Fields, []string{"alice|imap|", "alice|pop3|"}) {
		t.Fatalf("alice = %+v", lookups[0])
	}

	if !slices.Equal(lookups[1].Accounts, []string{"b1"}) {
		t.Fatalf("bob = %+v", lookups[1])
	}
}

func TestAccountMappingReaderResolvesNamesAcrossClusterSlots(t *testing.T) {
	nodes := rediscluster.NewTwoNode(t)
	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: accountMappingTestPrefix}}}
	reader := AccountMappingReader{Cfg: cfg, Redis: rediscli.NewTestClientForHandle(nodes.Cluster)}
	names := make([]string, 0, 16)
	onHigh := 0

	for index := range 16 {
		name := fmt.Sprintf("cluster%d@example.test", index)
		key := rediscli.GetUserHashKey(accountMappingTestPrefix, name)
		nodes.Node(key).HSet(key, accountcache.GetAccountMappingField(name, "imap", ""), fmt.Sprintf("account%d", index))

		if rediscluster.IsHigh(key) {
			onHigh++
		}

		names = append(names, name)
	}

	if onHigh == 0 || onHigh == len(names) {
		t.Fatalf("user hashes do not span both nodes (%d of %d on high node)", onHigh, len(names))
	}

	for index, lookup := range reader.ReadMany(context.Background(), names) {
		if lookup.Err != nil || !slices.Equal(lookup.Accounts, []string{fmt.Sprintf("account%d", index)}) {
			t.Fatalf("%s: %+v", names[index], lookup)
		}
	}
}

func TestAccountMappingReaderScansPrimaryDespiteReplicaRouting(t *testing.T) {
	primary := miniredis.RunT(t)
	replica := miniredis.RunT(t) // An empty replica: any scan routed here would report the name as unmapped.
	cluster := redis.NewClusterClient(&redis.ClusterOptions{
		ReadOnly:      true,
		RouteRandomly: true,
		ClusterSlots: func(context.Context) ([]redis.ClusterSlot, error) {
			return []redis.ClusterSlot{{Start: 0, End: 16383, Nodes: []redis.ClusterNode{{Addr: primary.Addr()}, {Addr: replica.Addr()}}}}, nil
		},
	})

	t.Cleanup(func() { _ = cluster.Close() })

	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: accountMappingTestPrefix}}}
	reader := AccountMappingReader{Cfg: cfg, Redis: rediscli.NewTestClientForHandle(cluster)}

	storeAccountMapping(primary, "alice", "imap", "", "alice-account")

	for attempt := range 32 {
		lookup := reader.Read(context.Background(), "alice")
		if lookup.Err != nil || !slices.Equal(lookup.Accounts, []string{"alice-account"}) {
			t.Fatalf("attempt %d read a replica or failed: %+v", attempt, lookup)
		}
	}
}

func TestAccountMappingReaderFailsClosedOnLaterAndPartialErrors(t *testing.T) {
	db, mock := redismock.NewClientMock()
	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: accountMappingTestPrefix}}}
	reader := AccountMappingReader{Cfg: cfg, Redis: rediscli.NewTestClient(db)}
	aliceKey := rediscli.GetUserHashKey(accountMappingTestPrefix, "alice")
	bobKey := rediscli.GetUserHashKey(accountMappingTestPrefix, "bob")
	carolKey := rediscli.GetUserHashKey(accountMappingTestPrefix, "carol")

	// Round 1: alice needs another step, carol finishes, and bob fails in the same pipeline (last, because
	// redismock stops replaying a pipeline at its first error while real Redis answers every command).
	mock.ExpectHScan(aliceKey, 0, "alice|*", accountMappingScanCount).SetVal([]string{"alice|imap|", "a1"}, 9)
	mock.ExpectHScan(carolKey, 0, "carol|*", accountMappingScanCount).SetVal([]string{"carol|imap|", "c1"}, 0)
	mock.ExpectHScan(bobKey, 0, "bob|*", accountMappingScanCount).SetErr(errors.New("synthetic node failure"))
	// Round 2: alice fails after partial data.
	mock.ExpectHScan(aliceKey, 9, "alice|*", accountMappingScanCount).SetErr(errors.New("synthetic timeout"))

	lookups := reader.ReadMany(context.Background(), []string{"alice", "carol", "bob"})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	if lookups[0].Err == nil || lookups[2].Err == nil {
		t.Fatalf("later or partial failures must fail closed: alice=%+v bob=%+v", lookups[0], lookups[2])
	}

	if lookups[1].Err != nil || !slices.Equal(lookups[1].Accounts, []string{"c1"}) {
		t.Fatalf("carol = %+v", lookups[1])
	}
}

func TestEscapeRedisGlobKeepsNamesByteExact(t *testing.T) {
	// miniredis cannot match invalid UTF-8 patterns, so the escaping itself is checked against real Redis glob
	// rules: metacharacters are prefixed with a backslash and every other byte is kept verbatim.
	cases := map[string]string{
		"inv\xffal*id":  "inv\xffal\\*id",
		"a?[b]\\c":      "a\\?\\[b\\]\\\\c",
		"plain@example": "plain@example",
	}

	for input, want := range cases {
		if got := escapeRedisGlob(input); got != want {
			t.Fatalf("escapeRedisGlob(%q) = %q, want %q", input, got, want)
		}
	}
}
