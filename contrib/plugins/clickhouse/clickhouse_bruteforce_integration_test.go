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

//go:build clickhouse_integration

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestClickHouseBruteForceEvidenceAnswersTheBanQuestions replays the host fixture of the shared-IP scenario through
// the real plugin streams into ClickHouse and answers the contract questions with the documented queries.
func TestClickHouseBruteForceEvidenceAnswersTheBanQuestions(t *testing.T) {
	db, harness := startBruteForceEvidence(t)
	defer harness.stop(t)

	events := loadBruteForceFixture(t)
	observeBruteForceEvents(t, harness, events)

	// A replayed delivery of the same counted event in a later insert must be removable by event_id.
	observeBruteForceEvents(t, harness, events[:1])

	unique := waitRows(t, db, "SELECT event_id FROM nauthilus.bruteforce_attempts LIMIT 1 BY event_id", 6)
	if len(unique) != 6 {
		t.Fatalf("unique attempt rows = %d, want 6 after replay removal", len(unique))
	}

	ban := assertBanAndHit(t, db)
	assertContributions(t, db.rows(contributionsQuery(ban)))

	if status := completenessStatus(db, ban); status != "complete" {
		t.Fatalf("completeness = %s, want 1..3 present exactly once after replay removal", status)
	}

	assertBruteForceLifecycleTail(t, db)
	assertBruteForceSummary(t, db)
}

// startBruteForceEvidence starts the plugin with both brute-force streams against a fresh real ClickHouse schema.
func startBruteForceEvidence(t *testing.T) (*clickHouseTestDB, testHarness) {
	t.Helper()

	db := newClickHouseTestDB(t)
	db.applyFile(schemaPath)

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url":                      db.insertURL("logins", true),
		"bruteforce_lifecycle_insert_url": db.insertURL("bruteforce_lifecycle", true),
		"bruteforce_attempts_insert_url":  db.insertURL("bruteforce_attempts", true),
		"batch_size":                      1000, "deployment": "it", "instance": "it-1",
	}), testRunnerOptions{roundTripper: http.DefaultTransport})

	return db, harness
}

// observeBruteForceEvents admits events through the plugin sink and flushes them into ClickHouse as one insert.
func observeBruteForceEvents(t *testing.T, harness testHarness, events []pluginapi.BruteForceEvent) {
	t.Helper()

	sink := bruteForceEventTarget{plugin: harness.plugin}

	for _, event := range events {
		if err := sink.ObserveBruteForceEvent(t.Context(), event); err != nil {
			t.Fatalf("ObserveBruteForceEvent(%s) error = %v", event.Kind, err)
		}
	}

	flushBruteForceStreams(t, harness)
}

// assertBanAndHit checks the stored activation and the only request that hit the existing ban; it returns the ban.
func assertBanAndHit(t *testing.T, db *clickHouseTestDB) map[string]any {
	t.Helper()

	ban := loadActivation(t, db)
	if ban["network"] != "198.51.100.0/24" || ban["stored_rule"] != "nat-network" ||
		fmt.Sprint(ban["window_current"]) != "3" || ban["expires_at"] == nil {
		t.Fatalf("activation = %v, want one ban of the /24 with pre-check current 3", ban)
	}

	affected := db.rows("SELECT claimed_username, hit_source, ban_active FROM nauthilus.bruteforce_attempts " +
		"WHERE kind = 'ban_hit' AND network = '198.51.100.0/24'")
	if len(affected) != 1 || affected[0]["claimed_username"] != "dave@example.test" || affected[0]["hit_source"] != "redis" {
		t.Fatalf("affected rows = %v, want dave as the only request that hit the existing ban", affected)
	}

	return ban
}

// contributionFilter is the contract 13.4 reference predicate: counted rows of the activating bucket whose window
// counter is inside the closed set the activation read (window_current of its window, window_previous of the earlier
// one), between the latest counters_reset of that bucket before the activation and the first one after it.
const contributionFilter = "deployment = 'it' AND network = '%[1]s' AND bucket_id = '%[2]s' AND kind = 'counted' " +
	"AND ((window_index = %[3]v AND window_current <= %[4]v) OR (window_index = %[3]v - 1 AND window_current <= %[5]v)) " +
	"AND ts > ifNull((SELECT maxOrNull(ts) FROM nauthilus.bruteforce_lifecycle WHERE deployment = 'it' " +
	"AND network = '%[1]s' AND bucket_id = '%[2]s' AND kind = 'counters_reset' AND ts < '%[6]s'), toDateTime64(0, 3, 'UTC')) " +
	"AND ts < ifNull((SELECT minOrNull(ts) FROM nauthilus.bruteforce_lifecycle WHERE deployment = 'it' " +
	"AND network = '%[1]s' AND bucket_id = '%[2]s' AND kind = 'counters_reset' AND ts > '%[6]s'), toDateTime64('2299-12-31 00:00:00', 3, 'UTC'))"

// loadActivation returns the single stored ban activation with the window counters it read.
func loadActivation(t *testing.T, db *clickHouseTestDB) map[string]any {
	t.Helper()

	rows := db.rows("SELECT event_id, network, stored_rule, bucket_id, window_index, window_current, " +
		"ifNull(window_previous, 0) AS window_previous, expires_at, request_id, toString(ts) AS ts " +
		"FROM nauthilus.bruteforce_lifecycle WHERE kind = 'ban_activated'")
	if len(rows) != 1 {
		t.Fatalf("activation rows = %v, want one", rows)
	}

	return rows[0]
}

// contributionWhere renders the reference predicate for one activation.
func contributionWhere(ban map[string]any) string {
	return fmt.Sprintf(contributionFilter, ban["network"], ban["bucket_id"], ban["window_index"],
		ban["window_current"], ban["window_previous"], ban["ts"])
}

// contributionsQuery lists the counted contributors of one activation in increment order.
func contributionsQuery(ban map[string]any) string {
	return "SELECT claimed_username, account, account_known, window_current, crossed FROM nauthilus.bruteforce_attempts " +
		"WHERE " + contributionWhere(ban) + " ORDER BY window_current LIMIT 1 BY event_id"
}

// completenessStatus compares the deduplicated contributions with the closed set 1..window_current of the activation.
func completenessStatus(db *clickHouseTestDB, ban map[string]any) string {
	rows := db.rows("SELECT count() AS present, uniqExact(window_current) AS distinct_current FROM (SELECT window_current " +
		"FROM nauthilus.bruteforce_attempts WHERE " + contributionWhere(ban) + " AND window_index = " +
		fmt.Sprint(ban["window_index"]) + " LIMIT 1 BY event_id)")

	want := fmt.Sprint(ban["window_current"])
	if fmt.Sprint(rows[0]["present"]) == want && fmt.Sprint(rows[0]["distinct_current"]) == want {
		return "complete"
	}

	return "loss_detected"
}

// assertContributions checks the counted contributors of the ban, including the unknown claimed name.
func assertContributions(t *testing.T, rows []map[string]any) {
	t.Helper()

	want := []struct{ name, account, known, crossed string }{
		{"alice@example.test", "alice@example.test", "true", "false"},
		{"ceo@foreign.test", "", "<nil>", "false"},
		{"bob@example.test", "bob@example.test", "true", "true"},
	}

	if len(rows) != len(want) {
		t.Fatalf("contributions = %v, want %d", rows, len(want))
	}

	for index, row := range rows {
		if row["claimed_username"] != want[index].name || row["account"] != want[index].account ||
			fmt.Sprint(row["account_known"]) != want[index].known || fmt.Sprint(row["crossed"]) != want[index].crossed {
			t.Fatalf("contribution %d = %v, want %+v", index, row, want[index])
		}
	}
}

// assertBruteForceLifecycleTail checks the release and counter reset with their operator reference.
func assertBruteForceLifecycleTail(t *testing.T, db *clickHouseTestDB) {
	t.Helper()

	rows := db.rows("SELECT kind, release_source, operator_client_id, keys_removed FROM nauthilus.bruteforce_lifecycle " +
		"WHERE kind IN ('ban_released', 'counters_reset') ORDER BY ts")
	if len(rows) != 2 || rows[0]["kind"] != "ban_released" || rows[0]["operator_client_id"] != "ops-client" ||
		rows[1]["kind"] != "counters_reset" || fmt.Sprint(rows[1]["keys_removed"]) != "1" {
		t.Fatalf("lifecycle tail = %v, want release and counter reset by ops-client", rows)
	}

	if names := db.rows("SELECT count() AS n FROM system.columns WHERE database = currentDatabase() " +
		"AND table = 'bruteforce_lifecycle' AND name = 'claimed_username'"); fmt.Sprint(names[0]["n"]) != "0" {
		t.Fatal("bruteforce_lifecycle must not store claimed login names")
	}
}

// assertBruteForceSummary checks the hourly aggregate that outlives the raw rows.
func assertBruteForceSummary(t *testing.T, db *clickHouseTestDB) {
	t.Helper()

	rows := db.rows("SELECT kind, sum(events) AS events, min(min_current) AS min_current, max(max_current) AS max_current, " +
		"uniqMerge(claimed_names) AS names FROM nauthilus.bruteforce_attempt_summary WHERE kind = 'counted' GROUP BY kind")
	if len(rows) != 1 || fmt.Sprint(rows[0]["min_current"]) != "1" || fmt.Sprint(rows[0]["max_current"]) != "5" ||
		fmt.Sprint(rows[0]["names"]) != "5" {
		t.Fatalf("summary = %v, want counted window 1..5 with five distinct claimed names", rows)
	}
}

// loadBruteForceFixture decodes the host brute-force fixture.
func loadBruteForceFixture(t *testing.T) []pluginapi.BruteForceEvent {
	t.Helper()

	content, err := os.ReadFile(bruteForceFixture)
	if err != nil {
		t.Fatalf("read brute-force fixture: %v", err)
	}

	var events []pluginapi.BruteForceEvent
	if err = json.Unmarshal(content, &events); err != nil {
		t.Fatalf("decode brute-force fixture: %v", err)
	}

	return events
}

// flushBruteForceStreams delivers every brute-force stream synchronously.
func flushBruteForceStreams(t *testing.T, harness testHarness) {
	t.Helper()

	for _, stream := range harness.plugin.bruteForceStreams() {
		harness.plugin.flushPending(t.Context(), stream, "test")
	}
}

// TestClickHouseBruteForceEvidenceDetectsLostContributions pins that a missing counted increment is provable from the
// stored rows: the activation names current 3, but only two of 1..3 are present.
func TestClickHouseBruteForceEvidenceDetectsLostContributions(t *testing.T) {
	db, harness := startBruteForceEvidence(t)
	defer harness.stop(t)

	// The export of the second counted increment was lost.
	events := loadBruteForceFixture(t)
	observeBruteForceEvents(t, harness, append(events[:1:1], events[2:]...))

	if status := completenessStatus(db, loadActivation(t, db)); status != "loss_detected" {
		t.Fatalf("completeness status = %s, want loss_detected", status)
	}
}

// TestClickHouseBruteForceContributionsStopAtCounterReset pins that increments counted after an administrative
// counter reset in the same bucket window never become contributions of the earlier ban, although their window
// counter restarts at 1.
func TestClickHouseBruteForceContributionsStopAtCounterReset(t *testing.T) {
	db, harness := startBruteForceEvidence(t)
	defer harness.stop(t)

	events := loadBruteForceFixture(t)
	observeBruteForceEvents(t, harness, append(events, countedAfterReset(t, events)))
	waitRows(t, db, "SELECT event_id FROM nauthilus.bruteforce_attempts WHERE claimed_username = 'late@example.test'", 1)

	ban := loadActivation(t, db)
	assertContributions(t, db.rows(contributionsQuery(ban)))

	if status := completenessStatus(db, ban); status != "complete" {
		t.Fatalf("completeness = %s, want complete despite the restarted counter", status)
	}
}

// countedAfterReset derives a new counted increment that restarts the bucket window after the fixture counter reset.
func countedAfterReset(t *testing.T, events []pluginapi.BruteForceEvent) pluginapi.BruteForceEvent {
	t.Helper()

	for _, event := range events {
		if event.Kind != pluginapi.BruteForceCountersReset {
			continue
		}

		late := events[0]
		current, crossed := int64(1), false
		late.EventID, late.RequestID, late.ClaimedUsername = "after-reset-1", "after-reset-request", "late@example.test"
		late.ObservedAt, late.Current, late.Crossed = event.ObservedAt.Add(time.Second), &current, &crossed

		return late
	}

	t.Fatal("fixture has no counters_reset event")

	return pluginapi.BruteForceEvent{}
}
