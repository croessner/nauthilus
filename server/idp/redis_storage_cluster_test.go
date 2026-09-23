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
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
	"github.com/redis/go-redis/v9"
)

// newSlotGuardedTokenStorage returns miniredis-backed token storage whose client reports every
// script, transaction, or multi-key command that would fail with CROSSSLOT in Redis Cluster.
func newSlotGuardedTokenStorage(t *testing.T) (*miniredis.Miniredis, *redis.Client, *RedisTokenStorage) {
	t.Helper()

	server, handle, _ := redisslot.NewGuardedMiniredis(t, testRedisPrefix)

	return server, handle, NewRedisTokenStorage(rediscli.NewTestClient(handle), testRedisPrefix)
}

// TestTokenStorageAtomicUnitsStayInOneHashSlot drives every multi-key token operation through the
// CROSSSLOT guard, including the keys that Lua scripts derive from ARGV prefixes.
func TestTokenStorageAtomicUnitsStayInOneHashSlot(t *testing.T) {
	_, handle, guard := redisslot.NewGuardedMiniredis(t, testRedisPrefix)
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), testRedisPrefix)
	ctx := context.Background()

	session := &OIDCSession{ClientID: "dcr_client", UserID: "slot-user", RefreshFamilyID: "slot-family", DynamicUserEpoch: testSubjectEpochFloor}
	requireNoError(t, storage.StoreAccessToken(ctx, "na_at_dcr_slot", session, time.Hour))
	requireNoError(t, storage.StoreRefreshToken(ctx, "na_rt_slot", session, time.Hour))
	requireNoError(t, storage.StoreInitialDynamicRefreshToken(ctx, "refresh-slot-1", session, time.Hour))

	_, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_dcr_slot")
	requireNoError(t, err)

	static, err := storage.GetRefreshToken(ctx, "na_rt_slot")
	requireNoError(t, err)

	_, err = storage.ConsumeRefreshToken(ctx, "na_rt_slot", static)
	requireNoError(t, err)

	loaded, err := storage.GetDynamicRefreshToken(ctx, "refresh-slot-1")
	requireNoError(t, err)
	requireNoError(t, storage.RotateDynamicRefreshToken(ctx, "refresh-slot-1", "refresh-slot-2", loaded, time.Hour))

	if _, err := storage.GetDynamicRefreshToken(ctx, "refresh-slot-1"); !errors.Is(err, ErrDynamicRefreshTokenReuse) {
		t.Fatalf("replayed GetDynamicRefreshToken() error = %v, want ErrDynamicRefreshTokenReuse", err)
	}

	requireNoError(t, storage.StoreInitialDynamicRefreshToken(ctx, "refresh-slot-3", &OIDCSession{
		ClientID: "dcr_client", UserID: "slot-user", RefreshFamilyID: "slot-family-2", DynamicUserEpoch: testSubjectEpochFloor,
	}, time.Hour))
	requireNoError(t, storage.DeleteDynamicRefreshToken(ctx, "refresh-slot-3"))

	sessions, err := storage.ListUserSessions(ctx, session.UserID)
	requireNoError(t, err)

	for managementID := range sessions {
		requireNoError(t, storage.DeleteUserSession(ctx, session.UserID, managementID))
	}

	requireNoError(t, storage.StoreAccessToken(ctx, "na_at_dcr_slot_2", session, time.Hour))
	requireNoError(t, storage.FlushUserTokens(ctx, session.UserID))

	// Store (x3), MGET (x2), consume, resolve (x3), rotate, revoke, list MGET, delete, store, and flush units.
	if units := guard.Units(); units < 14 {
		t.Fatalf("guard inspected %d multi-key units, want the complete token lifecycle", units)
	}
}

// TestTokenStateKeysShareSubjectSlotAndLocatorsSpread pins the key layout contract per subject.
func TestTokenStateKeysShareSubjectSlotAndLocatorsSpread(t *testing.T) {
	keys := oidcTokenKeys{prefix: testRedisPrefix}
	owner := keys.subject("user{with}braces")
	slot := redisslot.Slot(owner.epoch())

	for _, key := range []string{
		owner.index(oidcUserAccessTokensKeyKind),
		owner.index(oidcStaticUserRefreshTokens),
		owner.index(oidcUserRefreshTokensKeyKind),
		owner.entry(oidcAccessTokenKeyKind, "reference"),
		owner.entry(oidcStaticRefreshToken, "reference"),
		owner.entry(oidcRefreshTokenKeyKind, "reference"),
		owner.entry(oidcDynamicRefreshConsumed, "reference"),
		owner.entry(oidcDynamicRefreshFamily, "family"),
		owner.entry(oidcDynamicRefreshRevoked, "family"),
	} {
		if redisslot.Slot(key) != slot {
			t.Fatalf("key %q left the subject slot %d", key, slot)
		}
	}

	if tag := redisslot.HashTag(owner.epoch()); tag != oidcSubjectSlot("user{with}braces") || strings.ContainsAny(tag, "{}") {
		t.Fatalf("subject hash tag = %q, want the braces-free subject digest", tag)
	}

	if redisslot.HashTag(keys.locator("reference")) != "reference" {
		t.Fatalf("locator %q does not carry the bearer reference as its own hash tag", keys.locator("reference"))
	}
}

// TestSubjectSlotsDistributeAcrossClusterMasters proves that epochs of many subjects no longer share a slot.
func TestSubjectSlotsDistributeAcrossClusterMasters(t *testing.T) {
	const (
		subjects = 1000
		masters  = 3
	)

	keys := oidcTokenKeys{prefix: testRedisPrefix}
	slots := make(map[int]struct{}, subjects)
	perMaster := make([]int, masters)

	for index := range subjects {
		slot := redisslot.Slot(keys.subject(fmt.Sprintf("user-%d", index)).epoch())
		slots[slot] = struct{}{}
		perMaster[slot*masters/redisslot.SlotCount]++
	}

	if len(slots) < subjects*95/100 {
		t.Fatalf("%d subjects mapped to %d slots, want nearly one slot per subject", subjects, len(slots))
	}

	for master, count := range perMaster {
		if count < subjects/masters*80/100 || count > subjects/masters*120/100 {
			t.Fatalf("master %d owns %d of %d subject epochs, want an even share: %v", master, count, subjects, perMaster)
		}
	}
}

// TestDynamicRefreshRotationAllowsOneWinnerUnderRace keeps reuse detection atomic inside the subject slot.
func TestDynamicRefreshRotationAllowsOneWinnerUnderRace(t *testing.T) {
	_, _, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()
	session := &OIDCSession{ClientID: "dcr_client", UserID: "race-user", RefreshFamilyID: "race-family", DynamicUserEpoch: testSubjectEpochFloor}

	requireNoError(t, storage.StoreInitialDynamicRefreshToken(ctx, "race-refresh", session, time.Hour))

	loaded, err := storage.GetDynamicRefreshToken(ctx, "race-refresh")
	requireNoError(t, err)

	const contenders = 8

	var (
		wait    sync.WaitGroup
		mu      sync.Mutex
		winners []string
		reused  int
	)

	start := make(chan struct{})

	for index := range contenders {
		wait.Go(func() {
			<-start

			successor := fmt.Sprintf("race-successor-%d", index)
			rotateErr := storage.RotateDynamicRefreshToken(ctx, "race-refresh", successor, loaded, time.Hour)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case rotateErr == nil:
				winners = append(winners, successor)
			case errors.Is(rotateErr, ErrDynamicRefreshTokenReuse):
				reused++
			default:
				t.Errorf("RotateDynamicRefreshToken() error = %v", rotateErr)
			}
		})
	}

	close(start)
	wait.Wait()

	if len(winners) != 1 || reused != contenders-1 {
		t.Fatalf("rotation winners = %v, reuse detections = %d, want exactly one winner", winners, reused)
	}

	if _, err := storage.GetDynamicRefreshToken(ctx, winners[0]); !errors.Is(err, redis.Nil) {
		t.Fatalf("winning successor GetDynamicRefreshToken() error = %v, want redis.Nil after concurrent reuse revoked the family", err)
	}
}

// TestRetiredSharedTagKeysAreIgnoredAfterHardCut documents that state under the former {dynamic} tag is not read.
func TestRetiredSharedTagKeysAreIgnoredAfterHardCut(t *testing.T) {
	server, handle, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()
	token := "na_at_dcr_retired"
	session := &OIDCSession{ClientID: "dcr_client", UserID: "retired-user", DynamicUserEpoch: testSubjectEpochFloor}

	data, err := storage.encryptSession(session)
	requireNoError(t, err)

	retired := testRedisPrefix + "oidc:dcr:{dynamic}:"
	requireNoError(t, handle.Set(ctx, retired+"access_token:"+storage.accessTokenReference(token), data, time.Hour).Err())
	requireNoError(t, handle.Set(ctx, retired+"dynamic_user_epoch:"+session.UserID, "5", time.Hour).Err())

	if _, err := storage.GetAccessTokenAuthoritative(ctx, token); !errors.Is(err, redis.Nil) {
		t.Fatalf("GetAccessTokenAuthoritative() error = %v, want redis.Nil for retired shared-tag state", err)
	}

	epoch, err := storage.DynamicUserEpoch(ctx, session.UserID)
	requireNoError(t, err)

	if epoch != testSubjectEpochFloor || !server.Exists(retired+"dynamic_user_epoch:"+session.UserID) {
		t.Fatalf("DynamicUserEpoch() = %q, want the subject-slot baseline independent of retired keys", epoch)
	}
}

// requireNoError stops a storage scenario at the first unexpected error.
func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAuthorizationCodeKeysHideBearerCodes keeps single-use codes out of Redis keys and consumes them once.
func TestAuthorizationCodeKeysHideBearerCodes(t *testing.T) {
	const code = "raw-authorization-code-secret"

	server, _, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()

	requireNoError(t, storage.StoreSession(ctx, code, &OIDCSession{ClientID: "client", UserID: "code-user"}, time.Minute))

	for _, key := range server.Keys() {
		if strings.Contains(key, code) {
			t.Fatalf("Redis key %q exposes an authorization code", key)
		}
	}

	if _, err := storage.ConsumeSession(ctx, code); err != nil {
		t.Fatalf("ConsumeSession() error = %v", err)
	}

	if _, err := storage.ConsumeSession(ctx, code); !errors.Is(err, redis.Nil) {
		t.Fatalf("replayed ConsumeSession() error = %v, want redis.Nil", err)
	}
}
