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

package supporthistory_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
)

// subjectLogin returns one contract login row of the fixture subject.
func subjectLogin(at time.Time, session, flow, outcome, marker, tempfail string) supporthistory.LoginRecord {
	return supporthistory.LoginRecord{At: at, EventID: "x-" + session + at.Format("150405.000"), Session: session,
		Username: "anna@example.test", Account: "acc-anna", FlowRef: flow, Operation: "authenticate",
		Outcome: outcome, OutcomeMarker: marker, TempFailReason: tempfail, ContractVersion: 1, OutcomeStage: "pre_auth"}
}

// TestLaterPagesKeepAttemptsWithActivityAfterTheWindow pins that rows after `until` never mark an attempt as served.
func TestLaterPagesKeepAttemptsWithActivityAfterTheWindow(t *testing.T) {
	store := fixtureStore(t)
	until := searchRequest().Filter.Until
	straddle := strings.Repeat("9", 32)
	store.Logins = append(store.Logins,
		subjectLogin(until.Add(-110*time.Minute), "straddle-a", straddle, "fail", "auth.outcome.auth_failure", ""),
		subjectLogin(until.Add(5*time.Minute), "straddle-b", straddle, "fail", "auth.outcome.auth_failure", ""))

	service := newService(t, store)
	request := searchRequest()
	request.Page.Limit = 1
	found := false

	for page := 0; page < 30 && !found; page++ {
		result, err := service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), request)
		if err != nil {
			t.Fatalf("page %d error = %v", page, err)
		}

		found = slices.ContainsFunc(result.Attempts, func(a supporthistory.Attempt) bool { return a.AttemptID == "fl1."+straddle })

		if result.Page.NextCursor == nil {
			break
		}

		request.Page.Cursor = *result.Page.NextCursor
	}

	if !found {
		t.Fatal("a flow with a row after the window end was dropped from a later page")
	}
}

// TestDisagreeingRowsOfOneRequestStayUnknown pins that two rows of one request with different readings never pick one.
func TestDisagreeingRowsOfOneRequestStayUnknown(t *testing.T) {
	store := fixtureStore(t)
	at := scenarioBase.Add(-5 * time.Minute)
	store.Logins = append(store.Logins,
		subjectLogin(at, "req-mixed", "", "tempfail", "auth.outcome.tls_required", "policy_indeterminate"),
		subjectLogin(at.Add(time.Millisecond), "req-mixed", "", "tempfail", "auth.outcome.backend_tempfail", "backend_tempfail"))

	attempts, _ := attemptsByID(t, newService(t, store), caller(definitions.ScopeHistoryRead))
	mixed := attempts["rq1.req-mixed"]

	if mixed.Outcome != "unknown" || !slices.Contains(mixed.Recording.KnownGaps, "CONFLICTING_TERMINAL_RECORDS") {
		t.Fatalf("attempt = %+v, want unknown with the conflict gap", mixed)
	}
}

// TestLatchedFlowOverTheEventCapLeaksNothing pins that withheld factor events never show up as truncation.
func TestLatchedFlowOverTheEventCapLeaksNothing(t *testing.T) {
	store := fixtureStore(t)
	latched := strings.Repeat("2", 32)

	for index := range supporthistory.MaxEventsPerAttempt + 5 {
		store.Events = append(store.Events, supporthistory.AuthEventRecord{At: scenarioBase.Add(-time.Duration(index) * time.Second),
			EventID: fmt.Sprintf("cap-%03d", index), EventType: "mfa.verification", FlowRef: latched, Account: "acc-anna",
			FactorRole: "second_factor", Method: "totp", Result: "invalid", Reason: "invalid_code", FlowEffect: "none",
			EventVersion: 1, FailLatched: true})
	}

	attempts, _ := attemptsByID(t, newService(t, store), caller(definitions.ScopeHistoryRead))
	if attempt := attempts["fl1."+latched]; attempt.Recording.EventsTruncated || attempt.Recording.ReplayedRowsMerged != 0 {
		t.Fatalf("support recording = %+v, want no trace of withheld events", attempt.Recording)
	}
}

// TestBanSubjectNeedsTheDetailRoleBeforeAnyRead pins that a support caller naming a subject never reaches a store.
func TestBanSubjectNeedsTheDetailRoleBeforeAnyRead(t *testing.T) {
	store := sharedIPStore(banNow.Add(-2 * time.Hour))

	_, err := banService(t, store).SearchBans(context.Background(), caller(definitions.ScopeHistoryRead),
		supporthistory.BanSearchRequest{SchemaVersion: "1", Target: supporthistory.BanTarget{IP: "198.51.100.17"},
			Subject: &supporthistory.Subject{Login: "bob@example.test"},
			Filter:  supporthistory.BanSearchFilter{From: banNow.Add(-3 * time.Hour), Until: banNow}})
	if !hasCode(err, supporthistory.CodeForbidden) || store.TotalCalls() != 0 {
		t.Fatalf("error = %v, store calls = %v, want FORBIDDEN before any read", err, store.Calls)
	}
}

// TestTruncatedLifecycleNeverReadsAsNoBan pins that a network with more lifecycle rows than the bound keeps its newest
// bans and never yields a plain miss.
func TestTruncatedLifecycleNeverReadsAsNoBan(t *testing.T) {
	at := banNow.Add(-2 * time.Hour)
	store := sharedIPStore(at)

	for index := range 600 {
		store.Store.Lifecycle = append(store.Store.Lifecycle, supporthistory.LifecycleRecord{
			At: at.Add(-time.Duration(index+10) * time.Hour), EventID: fmt.Sprintf("old-%03d", index), Kind: "counters_reset",
			Network: banNetwork, BucketID: "bucket-old", Rule: "nat-network"})
	}

	result := searchBans(t, store, definitions.ScopeHistoryRead)
	if len(result.Bans) != 1 || !slices.Contains(result.Bans[0].Unknowns, "LIFECYCLE_ROWS_TRUNCATED") ||
		!slices.Contains(result.History.Conditions, "LIFECYCLE_ROWS_TRUNCATED") {
		t.Fatalf("bans = %+v conditions = %v, want the recent ban with a truncation mark", result.Bans, result.History.Conditions)
	}

	store.Store.Lifecycle = slices.DeleteFunc(store.Store.Lifecycle, func(row supporthistory.LifecycleRecord) bool {
		return row.Kind == "ban_activated"
	})
	if basis := searchBans(t, store, definitions.ScopeHistoryRead).ResultBasis; basis != "evidence_truncated" {
		t.Fatalf("result basis = %s, want evidence_truncated instead of no_matches", basis)
	}
}

// TestLongPeriodResetInPreviousWindowMakesSummaryUnreliable pins the previous-window bounds for long rule periods.
func TestLongPeriodResetInPreviousWindowMakesSummaryUnreliable(t *testing.T) {
	old := banNow.Add(-20 * 24 * time.Hour)
	store := &historytest.BanStore{Store: &historytest.Store{DeployName: "it"}}
	ban := activation("ban-day", old, 3, 2)
	ban.PeriodSeconds = 86400
	store.Store.Lifecycle = []supporthistory.LifecycleRecord{ban,
		{At: old.Add(-12 * time.Hour), EventID: "reset-day", Kind: "counters_reset", Network: banNetwork, BucketID: banBucket}}
	store.Summaries = []supporthistory.WindowSummary{
		{WindowIndex: banWindow, Events: 3, MinCurrent: int64p(1), MaxCurrent: int64p(3)},
		{WindowIndex: banWindow - 1, Events: 1, MinCurrent: int64p(1), MaxCurrent: int64p(2)}}

	result, err := banService(t, store).SearchBans(context.Background(), caller(definitions.ScopeHistoryRead),
		supporthistory.BanSearchRequest{SchemaVersion: "1", Target: supporthistory.BanTarget{Network: banNetwork},
			Filter: supporthistory.BanSearchFilter{From: old.Add(-time.Hour), Until: old.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("SearchBans() error = %v", err)
	}

	previous := result.Bans[0].Contributions.Windows[1]
	if !previous.SummaryCheckUnreliable || previous.Status != "aggregate_only" {
		t.Fatalf("previous window = %+v, want an unreliable aggregate instead of a loss claim", previous)
	}
}

// TestUnconfirmedActivationDuringABanIsNotANewBan pins that an unconfirmed activation never records an end.
func TestUnconfirmedActivationDuringABanIsNotANewBan(t *testing.T) {
	at := banNow.Add(-2 * time.Hour)
	store := sharedIPStore(at)
	store.Store.Lifecycle = append(store.Store.Lifecycle[:1], supporthistory.LifecycleRecord{At: at.Add(time.Minute),
		EventID: "unconfirmed-1", Kind: "ban_activation_unconfirmed", Network: banNetwork, Rule: "nat-network"})

	result := searchBans(t, store, definitions.ScopeHistoryRead)
	if len(result.Bans) != 1 || result.Bans[0].End.Reason == "superseded_by_new_activation" ||
		!slices.Contains(result.Bans[0].Unknowns, "UNCONFIRMED_ACTIVATION_DURING_BAN") || len(result.UnconfirmedActivations) != 1 {
		t.Fatalf("bans = %+v, want one ban with an unconfirmed activation as unknown", result.Bans)
	}
}
