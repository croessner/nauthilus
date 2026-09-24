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
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
)

// newBucketCounterSaveFixture returns a pre-authentication fixture with three differently scoped rules.
func newBucketCounterSaveFixture(t *testing.T, clientIP string) *preAuthFixture {
	t.Helper()

	fixture := newPreAuthFixture(t, clientIP)
	settings := fixture.cfg.(*config.FileSettings)
	settings.BruteForce.Buckets = []config.BruteForceRule{
		{Name: "hour", Period: time.Hour, CIDR: 32, IPv4: true, FailedRequests: 10},
		{Name: "two-hours", Period: 2 * time.Hour, CIDR: 24, IPv4: true, FailedRequests: 20},
		{Name: "three-hours", Period: 3 * time.Hour, CIDR: 16, IPv4: true, FailedRequests: 30},
	}

	fixture.storage.HSet(fixture.manager(passwordHistoryCommandAccount).tolerate().GetReputationKey(clientIP), reputationPositiveField, "5")
	fixture.recorder.Reset()

	return fixture
}

// storedBucketCounters returns every stored bucket counter with its value and TTL.
func storedBucketCounters(t *testing.T, fixture *preAuthFixture) map[string]string {
	t.Helper()

	counters := make(map[string]string)

	for _, key := range fixture.storage.Keys() {
		value, err := fixture.storage.Get(key)
		if err != nil {
			continue
		}

		counters[key] = value + "@" + fixture.storage.TTL(key).String()
	}

	return counters
}

func TestSaveBruteForceBucketCountersMatchSequentialWritesInTwoRoundTrips(t *testing.T) {
	sequential := newBucketCounterSaveFixture(t, "192.0.2.50")
	batched := newBucketCounterSaveFixture(t, "192.0.2.50")
	rules := sequential.rules()

	sequentialManager := sequential.manager(passwordHistoryCommandAccount)
	for i := range rules {
		sequentialManager.SaveBruteForceBucketCounterToRedis(&rules[i])
	}

	batched.manager(passwordHistoryCommandAccount).SaveBruteForceBucketCountersToRedis(batched.rules())

	if got := sequential.recorder.Count(); got != 2*len(rules) {
		t.Fatalf("per-rule writes used %d round trips, want %d", got, 2*len(rules))
	}

	want := [][]string{{"hget"}, {"evalsha", "evalsha", "evalsha"}}
	if trips := batched.recorder.RoundTrips(); !reflect.DeepEqual(trips, want) {
		t.Fatalf("batched writes round trips = %v, want %v", trips, want)
	}

	if got, want := storedBucketCounters(t, batched), storedBucketCounters(t, sequential); len(got) != len(rules) || !reflect.DeepEqual(got, want) {
		t.Fatalf("batched counters = %v, want sequential counters %v", got, want)
	}
}

func TestSaveBruteForceBucketCountersEvaluateEachRuleOnItsOwn(t *testing.T) {
	fixture := newBucketCounterSaveFixture(t, "192.0.2.60")
	manager := fixture.manager(passwordHistoryCommandAccount)
	rules := fixture.rules()

	brokenKey, _, _, ok := manager.prepareSlidingWindow(&rules[1])
	if !ok {
		t.Fatal("prepare broken rule window")
	}

	fixture.storage.HSet(brokenKey, "wrong", "type")

	manager.SaveBruteForceBucketCountersToRedis(rules)

	for i, rule := range rules {
		currentKey, _, _, _ := manager.prepareSlidingWindow(&rules[i])
		value, err := fixture.storage.Get(currentKey)

		if i == 1 {
			if err == nil {
				t.Fatalf("broken rule %s was overwritten: %q", rule.Name, value)
			}

			continue
		}

		if err != nil || value != "1" {
			t.Fatalf("rule %s counter = %q err:%v, want 1 despite the failed rule", rule.Name, value, err)
		}
	}

	if trips := fixture.recorder.RoundTrips(); len(trips) != 2 || !slices.Equal(trips[0], []string{"hget"}) {
		t.Fatalf("round trips = %v, want reputation read and one script pipeline", trips)
	}
}
