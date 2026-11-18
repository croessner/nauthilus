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

package idp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
)

// testAccountSubjectsKey returns the account binding set key exactly as the storage formats it.
func testAccountSubjectsKey(account string) string {
	return testRedisPrefix + "oidc:account:{" + oidcSlotDigest("nauthilus-oidc-token-account\x00", account) + "}:subjects"
}

func TestBindAccountSubjectSkipsSessionsWithoutDistinctAccount(t *testing.T) {
	cases := map[string]*OIDCSession{
		"no account":       {UserID: "uuid-1"},
		"subject equals":   {UserID: "alice", Username: "alice"},
		"service token":    {UserID: "cc-client", Username: "cc-client-account", ServiceToken: true},
		"no subject":       {Username: "alice"},
		"missing session":  nil,
		"distinct account": {UserID: "uuid-1", Username: "alice"},
	}

	for name, session := range cases {
		t.Run(name, func(t *testing.T) {
			server, _, storage := newSlotGuardedTokenStorage(t)

			requireNoError(t, storage.BindAccountSubject(context.Background(), session, time.Hour))

			bound := server.Exists(testAccountSubjectsKey("alice")) || server.Exists(testAccountSubjectsKey("cc-client-account"))
			if want := name == "distinct account"; bound != want {
				t.Fatalf("binding written = %t, want %t", bound, want)
			}
		})
	}
}

func TestBindAccountSubjectOnlyRaisesBindingLifetime(t *testing.T) {
	server, _, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()
	key := testAccountSubjectsKey("alice")

	requireNoError(t, storage.BindAccountSubject(ctx, &OIDCSession{UserID: "uuid-1", Username: "alice"}, 7*24*time.Hour))
	requireNoError(t, storage.BindAccountSubject(ctx, &OIDCSession{UserID: "uuid-2", Username: "alice"}, time.Hour))

	if ttl := server.TTL(key); ttl != 7*24*time.Hour {
		t.Fatalf("binding TTL = %v, want the longest bound lifetime", ttl)
	}

	members, err := server.Members(key)
	requireNoError(t, err)

	if len(members) != 2 {
		t.Fatalf("binding members = %v, want both subject slots", members)
	}

	requireNoError(t, storage.BindAccountSubject(ctx, &OIDCSession{UserID: "uuid-1", Username: "alice"}, 30*24*time.Hour))

	if ttl := server.TTL(key); ttl != 30*24*time.Hour {
		t.Fatalf("binding TTL after a longer token = %v, want 30 days", ttl)
	}
}

func TestFlushAccountTokensRevokesBoundAndAccountNamedSubjects(t *testing.T) {
	server, _, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()

	bound := &OIDCSession{ClientID: testClientID, UserID: "uuid-1", Username: "alice", DynamicUserEpoch: testSubjectEpochFloor}
	legacy := &OIDCSession{ClientID: testClientID, UserID: "alice", Username: "alice", DynamicUserEpoch: testSubjectEpochFloor}
	foreign := &OIDCSession{ClientID: testClientID, UserID: "uuid-2", Username: "bob", DynamicUserEpoch: testSubjectEpochFloor}

	for token, session := range map[string]*OIDCSession{"na_at_bound": bound, "na_at_legacy": legacy, "na_at_foreign": foreign} {
		requireNoError(t, storage.BindAccountSubject(ctx, session, time.Hour))
		requireNoError(t, storage.StoreAccessToken(ctx, token, session, time.Hour))
	}

	// A planted member that is not a subject digest must never be used to build keys.
	if _, err := server.SAdd(testAccountSubjectsKey("alice"), "not-a-slot"); err != nil {
		t.Fatalf("plant member: %v", err)
	}

	requireNoError(t, storage.FlushAccountTokens(ctx, "alice"))

	for _, token := range []string{"na_at_bound", "na_at_legacy"} {
		if _, err := storage.GetAccessTokenAuthoritative(ctx, token); err == nil {
			t.Errorf("token %q of the flushed account is still valid", token)
		}
	}

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_foreign"); err != nil {
		t.Fatalf("token of another account was revoked: %v", err)
	}

	if members, _ := server.Members(testAccountSubjectsKey("alice")); len(members) != 1 || members[0] != "not-a-slot" {
		t.Fatalf("binding after flush = %v, want only the ignored planted member", members)
	}
}

func TestFlushAccountTokensFailsWhenBindingsCannotBeRead(t *testing.T) {
	db, mock := redismock.NewClientMock()
	storage := NewRedisTokenStorage(rediscli.NewTestClient(db), testRedisPrefix)

	mock.ExpectSMembers(testAccountSubjectsKey("alice")).SetErr(errors.New("synthetic outage"))

	if err := storage.FlushAccountTokens(context.Background(), "alice"); err == nil {
		t.Fatal("FlushAccountTokens() reported success without reading the account bindings")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a failed binding read must not revoke anything: %v", err)
	}
}

func TestIssueTokensFailsClosedWhenAccountBindingFails(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	session := testOIDCSession([]string{definitions.ScopeOpenID, definitions.ScopeOfflineAccess}, time.Now().Add(-time.Minute))
	session.Username = "alice"

	expectUserTokenEpoch(fixture.mock, session.UserID)
	fixture.mock.ExpectEval(accountSubjectBindScript, []string{testAccountSubjectsKey("alice")},
		testSubjectSlot(session.UserID), (7 * 24 * time.Hour).Milliseconds()).SetErr(errors.New("synthetic outage"))

	if _, accessToken, refreshToken, _, err := fixture.idp.IssueTokens(fixture.ctx, session); err == nil || accessToken != "" || refreshToken != "" {
		t.Fatalf("IssueTokens() = access %q refresh %q err %v, want a failure without tokens", accessToken, refreshToken, err)
	}

	if err := fixture.mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no token state may be written after a failed binding: %v", err)
	}
}
