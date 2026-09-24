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

package bruteforce

import (
	"reflect"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// newTriggeredFixture returns a fixture whose password-history sets accept new hashes.
func newTriggeredFixture(t *testing.T, clientIP string) *preAuthFixture {
	t.Helper()

	fixture := newPreAuthFixture(t, clientIP)
	settings := fixture.cfg.(*config.FileSettings)
	settings.Server.MaxPasswordHistoryEntries = 10
	settings.Server.Redis.NegCacheTTL = time.Hour

	return fixture
}

func TestTriggeredBruteForceMergesIndependentWrites(t *testing.T) {
	fixture := newTriggeredFixture(t, "203.0.113.80")
	fixture.seedFailures(t, 6)

	// A distinct password is not a repeat, so the blocked account is recorded as affected.
	bm := fixture.manager(passwordHistoryCommandAccount)
	bm.password = secret.New("another-wrong-password")

	outcome := fixture.check(bm, true)
	if !outcome.ruleTriggered {
		t.Fatalf("check outcome = %+v, want an over-limit rule", outcome)
	}

	rules := fixture.rules()
	checkedCounter := bm.GetBruteForceCounter()[rules[0].Name]

	fixture.recorder.Reset()

	if !bm.ProcessBruteForce(true, false, &rules[0], nil, outcome.message, func() {}) {
		t.Fatal("over-limit request was not blocked")
	}

	want := [][]string{
		{"sadd", "zadd"},                // affected account and index without a membership read
		{"set"},                         // ban key
		{"zadd"},                        // ban index
		{"publish"},                     // ban broadcast
		{"evalsha"},                     // burst gate decides whether this request records the hash
		{"evalsha", "evalsha"},          // account and IP password-history sets
		{"scard", "sismember", "scard"}, // password-history load
	}

	if trips := fixture.recorder.RoundTrips(); !reflect.DeepEqual(trips, want) {
		t.Fatalf("triggered round trips = %v, want %v", trips, want)
	}

	fresh := fixture.manager(passwordHistoryCommandAccount)
	fresh.loadBruteForceBucketCounter(&rules[0])

	if got := bm.GetBruteForceCounter()[rules[0].Name]; got != checkedCounter || got != fresh.GetBruteForceCounter()[rules[0].Name] {
		t.Fatalf("reused counter = %d, want checked %d and freshly loaded %d", got, checkedCounter, fresh.GetBruteForceCounter()[rules[0].Name])
	}
}

func TestSaveFailedPasswordCounterWritesBothSetsInOnePipeline(t *testing.T) {
	fixture := newTriggeredFixture(t, "203.0.113.81")
	bm := fixture.manager(passwordHistoryCommandAccount)
	hash := bm.currentPasswordHash()

	bm.SaveFailedPasswordCounterInRedis()

	if trips := fixture.recorder.RoundTrips(); !reflect.DeepEqual(trips, [][]string{{"evalsha", "evalsha"}}) {
		t.Fatalf("password-history save round trips = %v, want one pipeline with two scripts", trips)
	}

	for _, withAccount := range []bool{true, false} {
		key := bm.getPasswordHistoryRedisSetKey(withAccount)
		if isMember, err := fixture.storage.SIsMember(key, hash); err != nil || !isMember {
			t.Fatalf("set %s contains full hash = %t err:%v, want true", key, isMember, err)
		}
	}
}

func TestSaveFailedPasswordCounterEvaluatesEachSetOnItsOwn(t *testing.T) {
	fixture := newTriggeredFixture(t, "203.0.113.82")
	bm := fixture.manager(passwordHistoryCommandAccount)
	accountKey := bm.getPasswordHistoryRedisSetKey(true)

	if err := fixture.storage.Set(accountKey, "wrong type"); err != nil {
		t.Fatalf("seed wrong account set type: %v", err)
	}

	bm.SaveFailedPasswordCounterInRedis()

	// Both independent scripts ran in the pipeline; the account-set failure does not undo the IP-set write.
	ipKey := bm.getPasswordHistoryRedisSetKey(false)
	if isMember, err := fixture.storage.SIsMember(ipKey, bm.currentPasswordHash()); err != nil || !isMember {
		t.Fatalf("IP set contains full hash = %t err:%v, want true", isMember, err)
	}
}

func TestAffectedAccountKeepsFirstSeenIndexWithoutMembershipRead(t *testing.T) {
	fixture := newTriggeredFixture(t, "203.0.113.83")
	bm := fixture.manager(passwordHistoryCommandAccount).WithRWPDecision(true).(*bucketManagerImpl)
	prefix := fixture.cfg.GetServer().GetRedis().GetPrefix()
	indexKey := rediscli.GetAffectedAccountsIndexKey(prefix)

	bm.updateAffectedAccount()

	firstSeen, err := fixture.storage.ZScore(indexKey, passwordHistoryCommandAccount)
	if err != nil {
		t.Fatalf("read first-seen index score: %v", err)
	}

	// Model an older first-seen timestamp; ZADD NX must keep it on the next block.
	if _, err := fixture.storage.ZAdd(indexKey, firstSeen-100, passwordHistoryCommandAccount); err != nil {
		t.Fatalf("seed older first-seen score: %v", err)
	}

	bm.updateAffectedAccount()

	if score, _ := fixture.storage.ZScore(indexKey, passwordHistoryCommandAccount); score != firstSeen-100 {
		t.Fatalf("index score = %v, want the first-seen score %v", score, firstSeen-100)
	}

	if isMember, _ := fixture.storage.SIsMember(prefix+definitions.RedisAffectedAccountsKey, passwordHistoryCommandAccount); !isMember {
		t.Fatal("affected-account set does not contain the account")
	}

	want := [][]string{{"sadd", "zadd"}, {"sadd", "zadd"}}
	if trips := fixture.recorder.RoundTrips(); !reflect.DeepEqual(trips, want) {
		t.Fatalf("affected-account round trips = %v, want %v", trips, want)
	}
}
