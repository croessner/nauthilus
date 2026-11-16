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
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const testFlowRef = "0123456789abcdef0123456789abcdef"

// legacyLoginRow is one row as the v4.0.9 writer produced it.
const legacyLoginRow = `{"ts":"2026-11-16 08:28:09.000","session":"legacy-session","service":"json","deployment":"prod",` +
	`"instance":"legacy","decision_sources":"","rbl_lists":[],"client_ip":"192.0.2.10","username":"legacy@example.test",` +
	`"geoip_privacy_classes":[],"geoip_privacy_source_authorities":[],"authenticated":false,"latency":3,` +
	`"http_status":403,"status_msg":"Invalid login or password"}`

// TestClickHouseContractMigrationKeepsLegacyRowsAndMatchesFreshSchema proves the additive migration on a
// production-shaped table: it is repeatable, keeps legacy rows as contract_version 0 without invented causes, and
// yields exactly the column set of a fresh installation from schema.sql.
func TestClickHouseContractMigrationKeepsLegacyRowsAndMatchesFreshSchema(t *testing.T) {
	migrated := newClickHouseTestDB(t)
	migrated.applyFile(legacySchemaPath)
	migrated.exec(fmt.Sprintf("INSERT INTO %s.logins FORMAT JSONEachRow %s", migrated.name, legacyLoginRow))
	migrated.applyFile(migrationPath)
	migrated.applyFile(migrationPath)
	migrated.applyFile(bruteForceMigPath)
	migrated.applyFile(bruteForceMigPath)
	// A writer of the previous contract keeps working against the migrated table.
	migrated.exec(fmt.Sprintf("INSERT INTO %s.logins FORMAT JSONEachRow %s", migrated.name,
		strings.Replace(legacyLoginRow, "legacy-session", "legacy-after-migration", 1)))

	legacy := migrated.rows("SELECT contract_version, event_id, outcome, transport_status, flow_ref, " +
		"reputation_assessments, reputation_truncated, brute_force_tolerated, http_status, status_msg " +
		"FROM nauthilus.logins WHERE session IN ('legacy-session', 'legacy-after-migration')")
	if len(legacy) != 2 {
		t.Fatalf("legacy rows = %d, want 2", len(legacy))
	}

	for _, row := range legacy {
		assertRowValues(t, row, map[string]any{
			"contract_version": "0", "event_id": "", "outcome": "", "transport_status": nil, "flow_ref": "",
			"reputation_truncated": false, "brute_force_tolerated": nil, "http_status": "403",
			"status_msg": "Invalid login or password",
		})
	}

	fresh := newClickHouseTestDB(t)
	fresh.applyFile(schemaPath)

	for _, table := range []string{
		"logins", "auth_events", "bruteforce_lifecycle", "bruteforce_attempts", "bruteforce_attempt_summary",
	} {
		if got, want := migrated.columns(table), fresh.columns(table); !maps.Equal(got, want) {
			t.Fatalf("%s columns differ between migrated and fresh schema:\nmigrated=%v\nfresh=%v", table, got, want)
		}
	}
}

// TestClickHouseContractRowsMatchHostOutcomes writes the shared host outcome fixture and the other contract cases
// through the real plugin streams into ClickHouse and reads the stored rows back.
//
//nolint:funlen // One end-to-end scenario keeps the stored-row acceptance matrix readable in one place.
func TestClickHouseContractRowsMatchHostOutcomes(t *testing.T) {
	db := newClickHouseTestDB(t)
	db.applyFile(legacySchemaPath)
	db.applyFile(migrationPath)

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": db.insertURL("logins", true), "events_insert_url": db.insertURL("auth_events", true),
		"batch_size": 1000, "dedup_success": false, "deployment": "it", "instance": "it-1",
	}), testRunnerOptions{roundTripper: http.DefaultTransport})
	defer harness.stop(t)

	requests := contractRequests(t)
	for name, request := range requests {
		if _, err := harness.enqueuePostAction(t.Context(), request); err != nil {
			t.Fatalf("Enqueue(%s) error = %v", name, err)
		}
	}

	events := contractEvents()
	sink := authEventTarget{plugin: harness.plugin}

	for _, event := range events {
		if err := sink.ObserveAuthEvent(t.Context(), event); err != nil {
			t.Fatalf("ObserveAuthEvent() error = %v", err)
		}
	}

	flushStreams(t, harness)

	rows := waitRows(t, db, "SELECT session, contract_version, event_id, operation, outcome, outcome_stage, "+
		"outcome_marker, response_marker, policy_rule, tempfail_reason, tempfail_checkpoint, policy_status, fsm_state, "+
		"transport, transport_status, http_status, status_msg, authenticated, flow_ref, brute_force_tolerated, "+
		"reputation_assessments, reputation_truncated, decision_sources, deployment, instance "+
		"FROM nauthilus.logins WHERE session LIKE 'it-%' ORDER BY session", len(requests))
	if len(rows) != len(requests) {
		t.Fatalf("stored login rows = %d, want %d", len(rows), len(requests))
	}

	byName := map[string]map[string]any{}
	for _, row := range rows {
		byName[strings.TrimPrefix(fmt.Sprint(row["session"]), "it-")] = row
	}

	assertFixtureOutcomeRows(t, byName)
	assertSpecialContractRows(t, byName)

	stored := waitRows(t, db, "SELECT event_id, event_type, event_version, result, reason, flow_effect, fail_latched, "+
		"method, flow_ref, protocol, account, deployment FROM nauthilus.auth_events ORDER BY ts", len(events))
	if len(stored) != len(events) {
		t.Fatalf("stored events = %d, want %d", len(stored), len(events))
	}

	for index, event := range events {
		assertRowValues(t, stored[index], map[string]any{
			"event_id": event.EventID, "event_type": "mfa.verification", "event_version": "1",
			"result": string(event.Result), "reason": event.Reason, "flow_effect": string(event.FlowEffect),
			"fail_latched": event.FailLatched, "method": event.Method, "flow_ref": testFlowRef, "protocol": "oidc",
			"account": "alice", "deployment": "it",
		})
	}

	joined := db.rows("SELECT l.session AS session, e.result AS result FROM nauthilus.logins AS l " +
		"INNER JOIN nauthilus.auth_events AS e ON l.flow_ref = e.flow_ref WHERE l.flow_ref != '' ORDER BY e.ts")
	if len(joined) != len(events) || fmt.Sprint(joined[0]["session"]) != "it-flow" {
		t.Fatalf("flow join = %v, want every event joined to the password row", joined)
	}
}

// assertFixtureOutcomeRows compares the stored rows of the shared host outcome fixture.
func assertFixtureOutcomeRows(t *testing.T, rows map[string]map[string]any) {
	t.Helper()

	for name, outcome := range loadOutcomeFixture(t) {
		row, found := rows[strings.ReplaceAll(name, " ", "-")]
		if !found {
			t.Fatalf("missing stored row for fixture %q", name)
		}

		assertRowValues(t, row, map[string]any{
			"contract_version": "1", "operation": outcome.Operation, "outcome": string(outcome.Decision),
			"outcome_stage": outcome.Stage, "outcome_marker": outcome.OutcomeMarker,
			"response_marker": outcome.ResponseMarker, "policy_rule": outcome.PolicyRule,
			"tempfail_reason": outcome.TempFailReason, "tempfail_checkpoint": outcome.TempFailCheckpoint,
			"policy_status": outcome.PolicyStatus, "fsm_state": outcome.FSMState, "transport": "grpc",
			"transport_status": nil, "http_status": fmt.Sprint(outcome.HTTPStatus), "status_msg": outcome.StatusMessage,
			"deployment": "it", "instance": "it-1",
		})

		if len(fmt.Sprint(row["event_id"])) != 32 {
			t.Fatalf("%s event_id = %v, want 128-bit hex", name, row["event_id"])
		}
	}

	if tls := rows["tls-required-tempfail"]; fmt.Sprint(tls["status_msg"]) == "Invalid login or password" ||
		fmt.Sprint(tls["http_status"]) == "403" {
		t.Fatalf("TLS tempfail row = %v, must not read as a credential failure", tls)
	}
}

// assertSpecialContractRows checks unknown outcomes, HTTP transport, toleration, flow, and reputation projections.
func assertSpecialContractRows(t *testing.T, rows map[string]map[string]any) {
	t.Helper()

	assertRowValues(t, rows["unknown"], map[string]any{
		"outcome": "unknown", "operation": "", "http_status": "0", "status_msg": "", "transport_status": nil,
		"tempfail_reason": "",
	})
	assertRowValues(t, rows["http-header-fail"], map[string]any{
		"outcome": "fail", "transport": "http", "transport_status": "200", "http_status": "200",
	})
	assertRowValues(t, rows["tolerated"], map[string]any{"brute_force_tolerated": true, "decision_sources": ""})
	assertRowValues(t, rows["flow"], map[string]any{"flow_ref": testFlowRef, "brute_force_tolerated": false})

	assessments, ok := rows["reputation"]["reputation_assessments"].([]any)
	if !ok || len(assessments) != 2 || rows["reputation"]["reputation_truncated"] != false {
		t.Fatalf("reputation row = %v, want two projected assessments", rows["reputation"])
	}

	fresh, _ := assessments[0].(map[string]any)
	missing, _ := assessments[1].(map[string]any)

	if fresh["band"] != "neutral" || fmt.Sprint(fresh["risk_score"]) != "0.12" || fmt.Sprint(fresh["age_seconds"]) != "3600" ||
		fresh["fact"] != "plugin.reputation.auth_subjects" || missing["state"] != "not_found" || missing["risk_score"] != nil {
		t.Fatalf("assessments = %v, want measured fresh and NULL-measured not_found tuples", assessments)
	}

	if rows["trimmed"]["reputation_truncated"] != true {
		t.Fatalf("trimmed row = %v, want reputation_truncated", rows["trimmed"])
	}
}

// TestClickHouseContractReplayIsIdentifiable pins replay semantics after an ambiguous insert failure: the login row
// duplicates with the same event_id, and auth_events collapses the replay under FINAL.
func TestClickHouseContractReplayIsIdentifiable(t *testing.T) {
	db := newClickHouseTestDB(t)
	db.applyFile(schemaPath)

	transport := &acceptThenFailTransport{}

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": db.insertURL("logins", true), "events_insert_url": db.insertURL("auth_events", true),
		"batch_size": 1000, "dedup_success": false,
	}), testRunnerOptions{roundTripper: transport})
	defer harness.stop(t)

	request := testRequest(t, requestOptions{authenticated: true})
	request.Snapshot.Session = "replay"

	if _, err := harness.enqueuePostAction(t.Context(), request); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	if err := (authEventTarget{plugin: harness.plugin}).ObserveAuthEvent(t.Context(), contractEvents()[0]); err != nil {
		t.Fatalf("ObserveAuthEvent() error = %v", err)
	}

	for range 2 {
		transport.failNext.Store(true)
		flushStreams(t, harness)
		harness.plugin.logins.retryAfter = time.Time{}
		harness.plugin.events.retryAfter = time.Time{}
	}

	flushStreams(t, harness)

	logins := waitRows(t, db, "SELECT event_id FROM nauthilus.logins WHERE session = 'replay'", 2)
	if len(logins) < 2 || logins[0]["event_id"] != logins[1]["event_id"] {
		t.Fatalf("replayed login rows = %v, want duplicates sharing one event_id", logins)
	}

	db.exec(db.scoped("OPTIMIZE TABLE nauthilus.auth_events FINAL"))

	if events := db.rows("SELECT event_id FROM nauthilus.auth_events FINAL"); len(events) != 1 {
		t.Fatalf("auth_events FINAL rows = %v, want one collapsed replay", events)
	}
}

// TestClickHouseContractSchemaDriftVisibility documents how a new writer behaves against an unmigrated table: the
// ClickHouse default silently drops unknown fields, while a strict insert URL makes the drift a visible failure.
func TestClickHouseContractSchemaDriftVisibility(t *testing.T) {
	db := newClickHouseTestDB(t)
	db.applyFile(legacySchemaPath)

	for _, strict := range []bool{false, true} {
		harness := startTestRunner(t, testModule(map[string]any{
			"insert_url": db.insertURL("logins", strict), "batch_size": 1000, "dedup_success": false,
		}), testRunnerOptions{roundTripper: http.DefaultTransport})

		request := testRequest(t, requestOptions{authenticated: true})
		request.Snapshot.Session = fmt.Sprintf("drift-%v", strict)

		if _, err := harness.enqueuePostAction(t.Context(), request); err != nil {
			t.Fatalf("Enqueue() error = %v", err)
		}

		err := flushBatch(t.Context(), harness.plugin.snapshot())
		stored := db.rows(fmt.Sprintf("SELECT session FROM nauthilus.logins WHERE session = '%s'", request.Snapshot.Session))

		if strict && (err == nil || len(stored) != 0) {
			t.Fatalf("strict insert against old schema: err=%v rows=%d, want visible failure", err, len(stored))
		}

		if !strict && (err != nil || len(stored) != 1) {
			t.Fatalf("default insert against old schema: err=%v rows=%d, want silently accepted row", err, len(stored))
		}

		harness.stop(t)
	}

	if _, found := db.columns("logins")["contract_version"]; found {
		t.Fatal("unmigrated table unexpectedly has contract_version")
	}
}

// acceptThenFailTransport forwards inserts to ClickHouse but can report a failure afterwards, modelling a response
// lost after ClickHouse accepted the batch.
type acceptThenFailTransport struct {
	failNext atomic.Bool
}

// RoundTrip forwards the request and optionally replaces the successful response with an error.
func (a *acceptThenFailTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return nil, err
	}

	if a.failNext.CompareAndSwap(true, false) {
		_ = response.Body.Close()

		return nil, errors.New("response lost after insert")
	}

	return response, nil
}

// contractRequests builds the post-action requests of the acceptance matrix, keyed by session suffix.
func contractRequests(t *testing.T) map[string]pluginapi.PostActionRequest {
	t.Helper()

	requests := map[string]pluginapi.PostActionRequest{}

	for name, outcome := range loadOutcomeFixture(t) {
		requests[strings.ReplaceAll(name, " ", "-")] = boundRequest(t, outcome)
	}

	requests["unknown"] = boundRequest(t, pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeUnknown})
	requests["http-header-fail"] = boundRequest(t, pluginapi.AuthOutcome{
		Decision: pluginapi.AuthOutcomeFail, Operation: "authenticate", HTTPStatus: 200,
		StatusMessage: "Invalid login or password", Transport: pluginapi.AuthTransportHTTP, TransportStatus: 200, Known: true,
	})

	tolerated := boundRequest(t, okOutcome())
	tolerated.Snapshot.Diagnostics.BruteForceTolerated = true
	requests["tolerated"] = tolerated

	flow := boundRequest(t, okOutcome())
	flow.Snapshot.IDP.FlowRef = testFlowRef
	requests["flow"] = flow

	reputation := boundRequest(t, okOutcome())
	reputation.Facts = []pluginapi.PolicyFact{
		{Attribute: "plugin.reputation.auth_subjects", Value: assessmentRecords(t)},
		{Attribute: "plugin.geoip.country_iso", Value: "DE"},
	}
	requests["reputation"] = reputation

	trimmed := boundRequest(t, okOutcome())
	trimmed.FactsTrimmed = true
	requests["trimmed"] = trimmed

	for name, request := range requests {
		request.Snapshot.Session = "it-" + name
		requests[name] = request
	}

	return requests
}

// boundRequest returns a request whose diagnostics were refreshed from the outcome, as the host binding does.
func boundRequest(t *testing.T, outcome pluginapi.AuthOutcome) pluginapi.PostActionRequest {
	t.Helper()

	request := testRequest(t, requestOptions{outcome: &outcome})
	request.Snapshot.Diagnostics.HTTPStatus = outcome.HTTPStatus
	request.Snapshot.Diagnostics.StatusMessage = outcome.StatusMessage

	return request
}

// okOutcome returns a sealed HTTP success outcome.
func okOutcome() pluginapi.AuthOutcome {
	return pluginapi.AuthOutcome{
		Decision: pluginapi.AuthOutcomeOK, Operation: "authenticate", HTTPStatus: 200, StatusMessage: "OK",
		Transport: pluginapi.AuthTransportHTTP, TransportStatus: 200, Known: true,
	}
}

// contractEvents returns the second-factor events of one fail-latched flow.
func contractEvents() []pluginapi.AuthEvent {
	base := pluginapi.AuthEvent{
		ObservedAt: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC), RequestID: "mfa-request", FlowRef: testFlowRef,
		Protocol: "oidc", ClientID: "client-a", Account: "alice", ClientIP: "192.0.2.1",
		FactorRole: pluginapi.AuthEventFactorRoleSecond, Method: "recovery_codes", Type: pluginapi.AuthEventMFAVerification,
		Version: pluginapi.AuthEventVersion, FailLatched: true,
	}

	invalid, limited, verified := base, base, base
	invalid.EventID, invalid.Result, invalid.Reason, invalid.FlowEffect =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", pluginapi.AuthEventInvalid, "invalid_code", pluginapi.AuthEventFlowNone
	limited.EventID, limited.Result, limited.Reason, limited.FlowEffect =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2", pluginapi.AuthEventRateLimited, "attempt_limit", pluginapi.AuthEventFlowNone
	verified.EventID, verified.Result, verified.Reason, verified.FlowEffect =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3", pluginapi.AuthEventSuccess, "verified", pluginapi.AuthEventFlowPrimaryFailureKept
	limited.ObservedAt = base.ObservedAt.Add(time.Second)
	verified.ObservedAt = base.ObservedAt.Add(2 * time.Second)

	return []pluginapi.AuthEvent{invalid, limited, verified}
}

// assessmentRecords builds one fresh and one not-found published assessment plus a correlation field.
func assessmentRecords(t *testing.T) pluginapi.DecisionRecordList {
	t.Helper()

	fresh := view.Tuple{State: "fresh", Profile: "operational", Band: "neutral", Override: "none", Details: &view.Details{
		Risk: 0.12, Confidence: 0.4, Samples: 7, Diversity: 1, AgeSeconds: 3600,
	}}
	missing := view.Tuple{State: "not_found", Profile: "operational", Band: "unknown", Override: "none"}

	records := []pluginapi.DecisionRecord{
		publishedAssessment(t, "auth_client", "ip", fresh, true),
		publishedAssessment(t, "auth_client", "asn", missing, false),
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		t.Fatalf("NewDecisionRecordList() error = %v", err)
	}

	return list
}

// publishedAssessment encodes one subject record like the reputation plugin publishes it.
func publishedAssessment(t *testing.T, role, kind string, tuple view.Tuple, correlated bool) pluginapi.DecisionRecord {
	t.Helper()

	fields, err := view.Encode(tuple)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	fields[view.FieldRole] = stringRecordValue(t, role)
	fields[view.FieldKind] = stringRecordValue(t, kind)

	if correlated {
		fields["correlation_id"] = stringRecordValue(t, "catalog-1")
	}

	output := make([]pluginapi.DecisionRecordField, 0, len(fields))

	for _, name := range slices.Sorted(maps.Keys(fields)) {
		field, fieldErr := pluginapi.NewDecisionRecordField(name, fields[name])
		if fieldErr != nil {
			t.Fatalf("NewDecisionRecordField() error = %v", fieldErr)
		}

		output = append(output, field)
	}

	record, err := pluginapi.NewDecisionRecord(output)
	if err != nil {
		t.Fatalf("NewDecisionRecord() error = %v", err)
	}

	return record
}

// stringRecordValue builds one string record field value.
func stringRecordValue(t *testing.T, text string) pluginapi.DecisionRecordFieldValue {
	t.Helper()

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewDecisionValue() error = %v", err)
	}

	fieldValue, err := pluginapi.NewDecisionRecordFieldValue(value)
	if err != nil {
		t.Fatalf("NewDecisionRecordFieldValue() error = %v", err)
	}

	return fieldValue
}

// loadOutcomeFixture decodes the shared host terminal outcome fixture.
func loadOutcomeFixture(t *testing.T) map[string]pluginapi.AuthOutcome {
	t.Helper()

	content, err := os.ReadFile(outcomeFixture)
	if err != nil {
		t.Fatalf("read outcome fixture: %v", err)
	}

	var fixture struct {
		Cases []struct {
			Name    string                `json:"name"`
			Outcome pluginapi.AuthOutcome `json:"outcome"`
		} `json:"cases"`
	}

	if err = json.Unmarshal(content, &fixture); err != nil {
		t.Fatalf("decode outcome fixture: %v", err)
	}

	result := map[string]pluginapi.AuthOutcome{}
	for _, fixtureCase := range fixture.Cases {
		result[fixtureCase.Name] = fixtureCase.Outcome
	}

	return result
}

// assertRowValues compares selected stored columns; numbers arrive as JSON strings or json.Number.
func assertRowValues(t *testing.T, row map[string]any, want map[string]any) {
	t.Helper()

	for column, expected := range want {
		got, present := row[column]
		if !present {
			t.Fatalf("row lacks column %s: %v", column, row)
		}

		if fmt.Sprint(got) != fmt.Sprint(expected) || (expected == nil) != (got == nil) {
			t.Fatalf("column %s = %#v, want %#v (row %v)", column, got, expected, row)
		}
	}
}

// TestClickHouseDashboardQueriesRunOnMigratedSchema executes every panel query of the shipped Grafana dashboard
// against a migrated production-shaped table, with Grafana macros replaced by neutral SQL.
func TestClickHouseDashboardQueriesRunOnMigratedSchema(t *testing.T) {
	db := newClickHouseTestDB(t)
	db.applyFile(legacySchemaPath)
	db.applyFile(migrationPath)
	db.exec(fmt.Sprintf("INSERT INTO %s.logins FORMAT JSONEachRow %s", db.name, legacyLoginRow))

	queries := dashboardQueries(t)
	if len(queries) == 0 {
		t.Fatal("dashboard contains no SQL panel queries")
	}

	for index, query := range queries {
		statement := expandDashboardMacros(query, db.name+".logins")
		if err := db.tryExec(statement + " FORMAT Null"); err != nil {
			t.Errorf("dashboard query %d failed on migrated schema: %v\n%s", index, err, statement)
		}
	}
}

// dashboardQueries collects the raw SQL of every dashboard target.
func dashboardQueries(t *testing.T) []string {
	t.Helper()

	content, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}

	var document any
	if err = json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}

	var queries []string

	var walk func(any)

	walk = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			for key, value := range typed {
				if text, ok := value.(string); ok && (key == "rawSql" || key == "query") &&
					strings.Contains(strings.ToUpper(text), "SELECT") {
					queries = append(queries, text)

					continue
				}

				walk(value)
			}
		case []any:
			for _, value := range typed {
				walk(value)
			}
		}
	}

	walk(document)

	return queries
}

// expandDashboardMacros replaces the Grafana ClickHouse macros used by the dashboard with neutral SQL.
func expandDashboardMacros(query string, table string) string {
	replacer := strings.NewReplacer(
		"${log_table:raw}", table, "${table_page:raw}", "1", "${table_page_size:raw}", "10",
		"${exclude_identities:singlequote}", "''",
	)
	query = replacer.Replace(query)
	query = replaceMacroCalls(query, "$__conditionalAll", func(string) string { return "1" })
	query = replaceMacroCalls(query, "$__timeFilter_ms", func(argument string) string {
		return "(" + argument + " >= now() - INTERVAL 1 DAY)"
	})

	return replaceMacroCalls(query, "$__timeInterval_ms", func(argument string) string {
		return "toStartOfMinute(" + argument + ")"
	})
}

// replaceMacroCalls replaces every balanced-parenthesis call of one macro.
func replaceMacroCalls(query string, macro string, expand func(string) string) string {
	for {
		start := strings.Index(query, macro+"(")
		if start < 0 {
			return query
		}

		depth, end := 0, -1

		for position := start + len(macro); position < len(query); position++ {
			switch query[position] {
			case '(':
				depth++
			case ')':
				depth--
			}

			if depth == 0 {
				end = position

				break
			}
		}

		if end < 0 {
			return query
		}

		query = query[:start] + expand(query[start+len(macro)+1:end]) + query[end+1:]
	}
}
