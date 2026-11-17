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

package main

import (
	"context"
	"net/http"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// bruteForceRejectRequest builds the login completion of a request rejected by an active ban.
func bruteForceRejectRequest(t *testing.T) pluginapi.PostActionRequest {
	t.Helper()

	return testRequest(t, requestOptions{outcome: &pluginapi.AuthOutcome{
		Decision: pluginapi.AuthOutcomeFail, Operation: "authenticate", Stage: "pre_auth",
		OutcomeMarker: bruteForceRejectOutcomeMarker, ResponseMarker: "auth.response.fail",
		PolicyRule: "standard_brute_force_deny", Known: true,
	}})
}

// TestBruteForceRejectsCannotCrowdOutLoginRows reproduces an attack during a ClickHouse outage: ban-hit completions
// may fill only their reserved share of the login buffer, so later success and failure rows are still admitted, and
// the share survives the requeue of a failed insert.
func TestBruteForceRejectsCannotCrowdOutLoginRows(t *testing.T) {
	transport := &recordingTransport{statusCode: http.StatusServiceUnavailable}

	harness := startTestRunner(t, batchingModule(map[string]any{
		"batch_size": 100, "max_buffer_rows": 4, "max_brute_force_reject_rows": 2,
	}), testRunnerOptions{transport: transport})
	defer harness.stop(t)

	for range 5 {
		if _, err := harness.enqueuePostAction(context.Background(), bruteForceRejectRequest(t)); err != nil {
			t.Fatalf("reject admission error = %v; overflow must never fail the post-action", err)
		}
	}

	// The fourth buffered row triggers an inline flush that fails and requeues every row.
	for range 2 {
		result, err := harness.enqueuePostAction(context.Background(), testRequest(t, requestOptions{}))
		if !result.Enqueued {
			t.Fatalf("login row behind a reject flood was not admitted: %+v, error = %v", result, err)
		}
	}

	if result, _ := harness.enqueuePostAction(context.Background(), bruteForceRejectRequest(t)); result.Enqueued {
		t.Fatal("reject row admitted beyond its share after the requeue")
	}

	rows := popCachedRows(t, harness.host, testCacheKey)

	rejects := 0

	for _, row := range rows {
		if isBruteForceRejectRow(row) {
			rejects++
		}
	}

	if len(rows) != 4 || rejects != 2 {
		t.Fatalf("buffered rows = %d with %d rejects, want 4 with 2", len(rows), rejects)
	}
}

// TestEncodedBruteForceRejectRowIsClassified pins the classifier to the real row encoding, so an encoding change
// cannot silently disable the reserved share.
func TestEncodedBruteForceRejectRowIsClassified(t *testing.T) {
	cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(nil))
	if err != nil {
		t.Fatal(err)
	}

	reject, _, err := encodeRequestRow(bruteForceRejectRequest(t), cfg)
	if err != nil {
		t.Fatal(err)
	}

	other, _, err := encodeRequestRow(testRequest(t, requestOptions{}), cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !isBruteForceRejectRow(string(reject)) || isBruteForceRejectRow(string(other)) {
		t.Fatalf("classification = reject:%t other:%t, want true/false",
			isBruteForceRejectRow(string(reject)), isBruteForceRejectRow(string(other)))
	}
}

// TestMaxBruteForceRejectRowsValidation defaults the share to half of the buffer and rejects shares that would leave
// no row for other login rows.
func TestMaxBruteForceRejectRowsValidation(t *testing.T) {
	for _, testCase := range []struct {
		settings map[string]any
		want     int
		invalid  bool
	}{
		{settings: map[string]any{}, want: defaultMaxBufferRows / rejectBufferShareDivisor},
		{settings: map[string]any{"max_buffer_rows": 1}, want: 1},
		{settings: map[string]any{"max_buffer_rows": 10, "max_brute_force_reject_rows": 9}, want: 9},
		{settings: map[string]any{"max_buffer_rows": 10, "max_brute_force_reject_rows": 10}, invalid: true},
		{settings: map[string]any{"max_buffer_rows": 1, "max_brute_force_reject_rows": 2}, invalid: true},
		{settings: map[string]any{"max_brute_force_reject_rows": -1}, invalid: true},
	} {
		cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(testCase.settings))
		if testCase.invalid {
			if err == nil {
				t.Fatalf("settings %v accepted, want rejection", testCase.settings)
			}

			continue
		}

		if err != nil || cfg.MaxBruteForceRejectRows != testCase.want {
			t.Fatalf("settings %v = %d (error %v), want %d", testCase.settings, cfg.MaxBruteForceRejectRows, err, testCase.want)
		}
	}
}
