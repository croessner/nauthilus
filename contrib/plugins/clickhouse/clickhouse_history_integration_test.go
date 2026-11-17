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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/clickhousestore"
)

const (
	historyReaderSQL   = "../../clickhouse-kubernetes/history-reader.sql"
	historySubject     = "anna@example.test"
	historyAccount     = "account-4711"
	historyOtherLogin  = "mallory@example.test"
	historyFlowOK      = "1111111111111111aaaaaaaaaaaaaaaa"
	historyFlowLatched = "2222222222222222bbbbbbbbbbbbbbbb"
)

// historyEnv is one isolated database with the plugin writer, a provisioned reader account, and the service.
type historyEnv struct {
	db      *clickHouseTestDB
	harness testHarness
	now     time.Time
}

// startHistoryEnv writes the history scenario through the real plugin streams into a fresh schema.
func startHistoryEnv(t *testing.T) historyEnv {
	t.Helper()

	db := newClickHouseTestDB(t)
	db.applyFile(schemaPath)

	harness := startTestRunner(t, testModule(map[string]any{
		"insert_url": db.insertURL("logins", true), "events_insert_url": db.insertURL("auth_events", true),
		"bruteforce_lifecycle_insert_url": db.insertURL("bruteforce_lifecycle", true),
		"bruteforce_attempts_insert_url":  db.insertURL("bruteforce_attempts", true),
		"batch_size":                      1000, "dedup_success": false, "deployment": "it", "instance": "it-1",
	}), testRunnerOptions{roundTripper: http.DefaultTransport})
	t.Cleanup(func() { harness.stop(t) })

	env := historyEnv{db: db, harness: harness, now: time.Now().UTC()}
	env.writeScenario(t)

	return env
}

// historyRequest builds one sealed post-action request of the synthetic subject.
func historyRequest(t *testing.T, session string, outcome pluginapi.AuthOutcome, flowRef, username string) pluginapi.PostActionRequest {
	t.Helper()

	request := boundRequest(t, outcome)
	request.Snapshot.Session, request.Snapshot.Username = session, username
	request.Snapshot.Account = historyAccount

	if username != historySubject {
		request.Snapshot.Account = ""
	}

	if flowRef != "" {
		request.Snapshot.IDP.FlowRef, request.Snapshot.Protocol, request.Snapshot.Service = flowRef, "oidc", "idp"
	}

	return request
}

// writeScenario writes request attempts, an IdP flow with a TOTP retry, a fail-latched flow, a replay, a legacy row,
// and the shared-IP ban fixture.
func (env historyEnv) writeScenario(t *testing.T) {
	t.Helper()

	outcomes := loadOutcomeFixture(t)
	brute := pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeFail, Operation: "authenticate", Stage: "pre_auth",
		OutcomeMarker: "auth.outcome.brute_force_reject", ResponseMarker: "auth.response.fail",
		PolicyRule: "standard_brute_force_deny", FSMState: "auth_fail", StatusMessage: "Invalid login or password",
		Transport: pluginapi.AuthTransportHTTP, HTTPStatus: 403, TransportStatus: 403, Known: true}

	for _, request := range []pluginapi.PostActionRequest{
		historyRequest(t, "req-credential", outcomes["credential failure"], "", historySubject),
		historyRequest(t, "req-backend", outcomes["backend tempfail"], "", historySubject),
		historyRequest(t, "req-tls", outcomes["tls required tempfail"], "", historySubject),
		historyRequest(t, "req-brute", brute, "", historySubject),
		historyRequest(t, "req-success", outcomes["success"], "", historySubject),
		historyRequest(t, "flow-ok-password", outcomes["success"], historyFlowOK, historySubject),
		historyRequest(t, "flow-ok-other", outcomes["credential failure"], historyFlowOK, historyOtherLogin),
		historyRequest(t, "flow-latched-password", outcomes["credential failure"], historyFlowLatched, historySubject),
	} {
		if _, err := env.harness.enqueuePostAction(t.Context(), request); err != nil {
			t.Fatalf("Enqueue(%s) error = %v", request.Snapshot.Session, err)
		}
	}

	sink := authEventTarget{plugin: env.harness.plugin}
	for _, event := range env.historyEvents() {
		if err := sink.ObserveAuthEvent(t.Context(), event); err != nil {
			t.Fatalf("ObserveAuthEvent() error = %v", err)
		}
	}

	flushStreams(t, env.harness)
	waitRows(t, env.db, "SELECT event_id FROM nauthilus.logins", 8)
	waitRows(t, env.db, "SELECT event_id FROM nauthilus.auth_events", 5)

	// A replayed delivery of the credential failure row and one legacy row of the same subject.
	env.db.exec(env.db.scoped("INSERT INTO nauthilus.logins SELECT * FROM nauthilus.logins WHERE session = 'req-credential'"))
	env.db.exec(env.db.scoped("INSERT INTO nauthilus.logins (ts, session, service, deployment, username, account, " +
		"client_ip, proto, http_status, status_msg, latency) VALUES (now64(3) - INTERVAL 10 MINUTE, 'req-legacy', 'nginx', " +
		"'it', 'anna@example.test', 'account-4711', '192.0.2.10', 'imap', 403, 'Invalid login or password', 1)"))

	observeBruteForceEvents(t, env.harness, shiftedBruteForceFixture(t, env.now))
}

// historyEvents returns a TOTP retry that completes one flow and three latched events of another.
func (env historyEnv) historyEvents() []pluginapi.AuthEvent {
	base := pluginapi.AuthEvent{RequestID: "mfa-request", Protocol: "oidc", ClientID: "client-a", Account: historyAccount,
		ClientIP: "192.0.2.1", FactorRole: pluginapi.AuthEventFactorRoleSecond, Type: pluginapi.AuthEventMFAVerification,
		Version: pluginapi.AuthEventVersion}
	event := func(id, flow, method string, result pluginapi.AuthEventResult, reason string,
		effect pluginapi.AuthEventFlowEffect, latched bool, offset time.Duration) pluginapi.AuthEvent {
		value := base
		value.EventID, value.FlowRef, value.Method, value.Result, value.Reason = id, flow, method, result, reason
		value.FlowEffect, value.FailLatched, value.ObservedAt = effect, latched, env.now.Add(offset)

		return value
	}

	return []pluginapi.AuthEvent{
		event("e0000000000000000000000000000001", historyFlowOK, "totp", pluginapi.AuthEventInvalid, "invalid_code",
			pluginapi.AuthEventFlowNone, false, time.Second),
		event("e0000000000000000000000000000002", historyFlowOK, "totp", pluginapi.AuthEventSuccess, "verified",
			pluginapi.AuthEventFlowStepUpCompleted, false, 2*time.Second),
		event("e0000000000000000000000000000003", historyFlowLatched, "recovery_codes", pluginapi.AuthEventInvalid,
			"invalid_code", pluginapi.AuthEventFlowNone, true, 3*time.Second),
		event("e0000000000000000000000000000004", historyFlowLatched, "recovery_codes", pluginapi.AuthEventRateLimited,
			"attempt_limit", pluginapi.AuthEventFlowNone, true, 4*time.Second),
		event("e0000000000000000000000000000005", historyFlowLatched, "recovery_codes", pluginapi.AuthEventSuccess,
			"verified", pluginapi.AuthEventFlowPrimaryFailureKept, true, 5*time.Second),
	}
}

// shiftedBruteForceFixture moves the shared-IP fixture two hours before now, keeping its relative order, so raw
// retention never depends on the date the tests run.
func shiftedBruteForceFixture(t *testing.T, now time.Time) []pluginapi.BruteForceEvent {
	t.Helper()

	events := loadBruteForceFixture(t)
	shift := now.Add(-2 * time.Hour).Sub(events[0].ObservedAt)

	for index := range events {
		events[index].ObservedAt = events[index].ObservedAt.Add(shift)
		if events[index].ExpiresAt != nil {
			expires := events[index].ExpiresAt.Add(shift)
			events[index].ExpiresAt = &expires
		}
	}

	return events
}

// provisionReader applies the documented reader provisioning with unique names and returns the store config.
func provisionReader(t *testing.T, db *clickHouseTestDB, readonly string, mode clickhousestore.BudgetMode) clickhousestore.Config {
	t.Helper()

	content, err := os.ReadFile(historyReaderSQL)
	if err != nil {
		t.Fatalf("read reader provisioning: %v", err)
	}

	var suffix [4]byte

	_, _ = rand.Read(suffix[:])
	user, profile, password := "it_history_"+hex.EncodeToString(suffix[:]), "it_history_profile_"+hex.EncodeToString(suffix[:]),
		"it-"+hex.EncodeToString(suffix[:])
	replacer := strings.NewReplacer("nauthilus_history_profile", profile, "nauthilus_history", user,
		"CHANGE_ME_PASSWORD", password, "readonly = 2 CONST", "readonly = "+readonly+" CONST")

	for _, sql := range sqlStatements(replacer.Replace(string(content))) {
		db.exec(db.scoped(sql))
	}

	t.Cleanup(func() {
		_ = db.tryExec("DROP USER IF EXISTS " + user)
		_ = db.tryExec("DROP SETTINGS PROFILE IF EXISTS " + profile)
	})

	return clickhousestore.Config{URL: db.baseURL, Database: db.name, Username: user, Password: secret.New(password),
		Deployment: "it", Mode: mode, Budget: clickhousestore.Budget{MaxExecutionTime: 8 * time.Second,
			MaxRowsToRead: 5_000_000, MaxBytesToRead: 2 << 30, MaxResponseBytes: 8 << 20}}
}

// historyService builds the service over a provisioned reader.
func historyService(t *testing.T, env historyEnv, config clickhousestore.Config) *supporthistory.Service {
	t.Helper()

	store, err := clickhousestore.New(config)
	if err != nil {
		t.Fatalf("clickhousestore.New() error = %v", err)
	}

	service, err := supporthistory.NewService(supporthistory.Options{Attempts: store, Bans: store,
		Now:      func() time.Time { return env.now.Add(time.Minute) },
		Prefixes: func() []supporthistory.Prefix { return []supporthistory.Prefix{{Family: 4, Bits: 24}} }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// historyCaller returns a verified bearer caller with the given scopes.
func historyCaller(scopes ...string) supporthistory.Caller {
	return supporthistory.NewCaller(supporthistory.VerifiedCredential{Method: supporthistory.CredentialOIDCBearer,
		ClientID: "support-console", Scopes: scopes})
}

// searchAll pages through the subject's attempts and fails on a repeated attempt id.
func searchAll(t *testing.T, env historyEnv, service *supporthistory.Service, caller supporthistory.Caller) map[string]supporthistory.Attempt {
	t.Helper()

	attempts := map[string]supporthistory.Attempt{}
	request := supporthistory.AttemptSearchRequest{SchemaVersion: "1",
		Subject: supporthistory.Subject{Login: historySubject},
		Filter:  supporthistory.AttemptSearchFilter{From: env.now.Add(-time.Hour), Until: env.now.Add(time.Hour)},
		Page:    supporthistory.PageRequest{Limit: 2}}

	for page := 0; page < 10; page++ {
		result, err := service.SearchAttempts(t.Context(), caller, request)
		if err != nil {
			t.Fatalf("SearchAttempts() error = %v", err)
		}

		if result.History.Availability != "available" || result.ResultBasis == "" {
			t.Fatalf("history = %+v basis = %s, want available evidence", result.History, result.ResultBasis)
		}

		for _, attempt := range result.Attempts {
			if _, seen := attempts[attempt.AttemptID]; seen {
				t.Fatalf("attempt %s repeated across pages", attempt.AttemptID)
			}

			attempts[attempt.AttemptID] = attempt
		}

		if result.Page.NextCursor == nil {
			return attempts
		}

		request.Page.Cursor = *result.Page.NextCursor
	}

	t.Fatal("paging did not terminate")

	return nil
}

// TestClickHouseHistoryAnswersWhatTheWriterRecorded reads the plugin-written scenario through the provisioned
// read-only account and checks the support projection of every path.
func TestClickHouseHistoryAnswersWhatTheWriterRecorded(t *testing.T) {
	env := startHistoryEnv(t)
	service := historyService(t, env, provisionReader(t, env.db, "2", clickhousestore.BudgetQuerySettings))
	attempts := searchAll(t, env, service, historyCaller(definitions.ScopeHistoryRead))

	if len(attempts) != 8 {
		t.Fatalf("attempts = %d, want 6 requests and 2 flows", len(attempts))
	}

	for id, want := range map[string]struct{ outcome, code string }{
		"rq1.req-credential": {"rejected", supporthistory.CodeCredentialsRejected},
		"rq1.req-backend":    {"technical_error", supporthistory.CodeTechnicalBackend},
		"rq1.req-tls":        {"rejected", supporthistory.CodeTLSRequired},
		"rq1.req-brute":      {"rejected", supporthistory.CodeBruteForceRejected},
		"rq1.req-success":    {"succeeded", supporthistory.CodeAuthenticationAccepted},
		"rq1.req-legacy":     {"unknown", supporthistory.CodeLegacyUninterpreted},
	} {
		attempt := attempts[id]
		if attempt.Outcome != want.outcome || len(attempt.Events) == 0 || attempt.Events[0].Code != want.code {
			t.Fatalf("%s = %+v, want %s/%s", id, attempt, want.outcome, want.code)
		}
	}

	if replays := attempts["rq1.req-credential"].Recording.ReplayedRowsMerged; replays != 1 {
		t.Fatalf("replayed rows merged = %d, want 1", replays)
	}

	assertSupportFlows(t, attempts)
}

// assertSupportFlows checks the TOTP retry flow and the withheld fail-latched flow of the support projection.
func assertSupportFlows(t *testing.T, attempts map[string]supporthistory.Attempt) {
	t.Helper()

	assertRetryFlow(t, attempts["fl1."+historyFlowOK])
	assertLatchedFlow(t, attempts["fl1."+historyFlowLatched])
}

// assertRetryFlow checks that a completed step-up never claims a completed login and keeps the earlier rejection.
func assertRetryFlow(t *testing.T, retry supporthistory.Attempt) {
	t.Helper()

	if retry.Outcome != "not_observed" || retry.Progress != "second_factor_completed" || retry.FinalOutcomeObserved {
		t.Fatalf("retry flow = %+v, want completion never claimed", retry)
	}

	rejected := slices.ContainsFunc(retry.Events, func(event supporthistory.Event) bool {
		return event.Code == supporthistory.CodeFactorRejected
	})
	redacted := slices.ContainsFunc(retry.Events, func(event supporthistory.Event) bool {
		return event.Identity.Redacted && event.Identity.SuppliedLogin == nil
	})

	if !rejected || !redacted {
		t.Fatalf("retry flow events = %+v, want the earlier TOTP rejection kept and the other login redacted", retry.Events)
	}
}

// assertLatchedFlow checks that the support projection reports the latched rejection without factor results.
func assertLatchedFlow(t *testing.T, latched supporthistory.Attempt) {
	t.Helper()

	if latched.Outcome != "rejected" || latched.OutcomeBasis != "primary_failure_latched" ||
		latched.Steps.SecondFactor != "withheld" || !latched.Recording.EventsWithheld {
		t.Fatalf("latched flow = %+v, want rejection without factor results", latched)
	}

	if slices.ContainsFunc(latched.Events, func(event supporthistory.Event) bool { return event.Source == "auth_events" }) {
		t.Fatalf("support projection leaked latched factor events: %+v", latched.Events)
	}
}

// TestClickHouseHistoryDetailRoleSeesKeptPrimaryFailure checks the detail projection of the latched flow.
func TestClickHouseHistoryDetailRoleSeesKeptPrimaryFailure(t *testing.T) {
	env := startHistoryEnv(t)
	service := historyService(t, env, provisionReader(t, env.db, "1", clickhousestore.BudgetProfile))

	result, err := service.GetAttempt(t.Context(), historyCaller(definitions.ScopeHistoryDetail),
		supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: "fl1." + historyFlowLatched, Around: env.now})
	if err != nil {
		t.Fatalf("GetAttempt() error = %v", err)
	}

	if result.Attempt == nil || result.Attempt.OutcomeBasis != "primary_failure_kept" || len(result.Attempt.Events) != 4 {
		t.Fatalf("detail attempt = %+v, want the password row and three latched factor events", result.Attempt)
	}

	foreign, err := service.GetAttempt(t.Context(), historyCaller(definitions.ScopeHistoryRead),
		supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: "fl1." + historyFlowLatched, Around: env.now,
			Subject: &supporthistory.Subject{Login: "someone-else@example.test"}})
	if err != nil || foreign.Attempt != nil {
		t.Fatalf("foreign subject detail = %+v, %v, want null", foreign, err)
	}
}

// TestClickHouseHistoryRefusesUnsafeReaders pins that a writable account is refused before any read.
func TestClickHouseHistoryRefusesUnsafeReaders(t *testing.T) {
	env := startHistoryEnv(t)
	config := provisionReader(t, env.db, "2", clickhousestore.BudgetQuerySettings)
	config.Username, config.Password = "default", secret.Value{}

	_, err := historyService(t, env, config).SearchAttempts(t.Context(), historyCaller(definitions.ScopeHistoryRead),
		supporthistory.AttemptSearchRequest{SchemaVersion: "1", Subject: supporthistory.Subject{Login: historySubject},
			Filter: supporthistory.AttemptSearchFilter{From: env.now.Add(-time.Hour), Until: env.now.Add(time.Hour)}})

	var serviceErr *supporthistory.Error
	if !errors.As(err, &serviceErr) || serviceErr.Code != supporthistory.CodeReaderUnsafe {
		t.Fatalf("SearchAttempts(writable reader) error = %v, want HISTORY_READER_UNSAFE", err)
	}
}

// assertSupportBan checks the support projection of the shared-IP ban.
func assertSupportBan(t *testing.T, support *supporthistory.BanSearchResult) {
	t.Helper()

	ban := support.Bans[0]
	if ban.Network != "198.51.100.0/24" || ban.Contributions.Status != "complete" || len(ban.Contributions.Items) != 3 ||
		ban.End.Reason != "released" || ban.Hits.Count != 1 || ban.Contributions.CrossingCandidate == nil {
		t.Fatalf("ban = %+v, want complete contributions, one hit, and the release", ban)
	}

	if slices.ContainsFunc(ban.Contributions.Items, func(item supporthistory.Contribution) bool {
		return !item.Redacted || item.ClaimedUsername != nil
	}) {
		t.Fatalf("support contributions %+v expose a claimed name", ban.Contributions.Items)
	}

	if len(support.Releases) != 1 || len(support.CounterResets) != 1 || support.Releases[0].OperatorClientID != nil {
		t.Fatalf("lifecycle lists = %+v / %+v, want release and reset without operator id", support.Releases, support.CounterResets)
	}
}

// TestClickHouseHistoryExplainsTheSharedIPBan answers the ban questions through the service.
func TestClickHouseHistoryExplainsTheSharedIPBan(t *testing.T) {
	env := startHistoryEnv(t)
	service := historyService(t, env, provisionReader(t, env.db, "2", clickhousestore.BudgetQuerySettings))
	request := supporthistory.BanSearchRequest{SchemaVersion: "1", Target: supporthistory.BanTarget{IP: "198.51.100.17"},
		Filter: supporthistory.BanSearchFilter{From: env.now.Add(-3 * time.Hour), Until: env.now}}

	support, err := service.SearchBans(t.Context(), historyCaller(definitions.ScopeHistoryRead), request)
	if err != nil {
		t.Fatalf("SearchBans() error = %v", err)
	}

	if len(support.Bans) != 1 {
		t.Fatalf("bans = %+v, want the one /24 ban", support.Bans)
	}

	assertSupportBan(t, support)

	request.Subject = &supporthistory.Subject{Login: "bob@example.test"}
	if _, err = service.SearchBans(t.Context(), historyCaller(definitions.ScopeHistoryRead), request); err == nil {
		t.Fatal("support ban search with subject succeeded, want FORBIDDEN")
	}

	detail, err := service.SearchBans(t.Context(), historyCaller(definitions.ScopeHistoryDetail), request)
	if err != nil || detail.Bans[0].Contributions.Items[2].ClaimedUsername == nil ||
		*detail.Bans[0].Contributions.Items[2].ClaimedUsername != "bob@example.test" {
		t.Fatalf("detail ban search = %+v, %v, want named contributions", detail, err)
	}
}
