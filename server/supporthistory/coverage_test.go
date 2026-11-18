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
)

// TestUnreadableStepEventsMakeTheAnswerPartial pins that unread step events mean "not recorded", never "not required".
func TestUnreadableStepEventsMakeTheAnswerPartial(t *testing.T) {
	store := fixtureStore(t)
	store.Errors = map[string]error{"AuthEvents": fmt.Errorf("%w: test", supporthistory.ErrSourceUnavailable)}

	attempts, result := attemptsByID(t, newService(t, store), caller(definitions.ScopeHistoryRead))
	if result.History.Availability != "partial" || !slices.Contains(result.History.Conditions, "SOURCE_READ_FAILED") {
		t.Fatalf("history = %+v, want partial with a failed source", result.History)
	}

	flow := attempts["fl1."+strings.Repeat("1", 32)]
	if flow.Steps.SecondFactor != "not_recorded" || !slices.Contains(flow.Recording.KnownGaps, "AUTH_EVENTS_NOT_READ") {
		t.Fatalf("flow = %+v, want not_recorded second factor and the gap", flow)
	}
}

// TestPrimarySourceFailuresAreErrorsNotEmptyHistory pins that a failed logins read never yields an empty answer.
func TestPrimarySourceFailuresAreErrorsNotEmptyHistory(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code supporthistory.ErrorCode
	}{
		{fmt.Errorf("%w: test", supporthistory.ErrSourceUnavailable), supporthistory.CodeSourceUnavailable},
		{fmt.Errorf("%w: test", supporthistory.ErrSourceNotInstalled), supporthistory.CodeSourceUnavailable},
		{fmt.Errorf("%w: test", supporthistory.ErrBudgetExceeded), supporthistory.CodeQueryTooBroad},
		{fmt.Errorf("%w: test", supporthistory.ErrReaderUnsafe), supporthistory.CodeReaderUnsafe},
	} {
		for _, method := range []string{"LoginRows", "RecordedAccounts", "SelfCheck"} {
			t.Run(method+"/"+string(tc.code), func(t *testing.T) {
				store := fixtureStore(t)
				store.Errors = map[string]error{method: tc.err}

				result, err := newService(t, store).SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), searchRequest())
				if result != nil || !hasCode(err, tc.code) {
					t.Fatalf("result = %v, error = %v, want %s", result, err, tc.code)
				}
			})
		}
	}
}

// TestAnchorSlicesShrinkBeforeGivingUp pins that a busy slice is narrowed down to one hour before the query fails.
func TestAnchorSlicesShrinkBeforeGivingUp(t *testing.T) {
	store := fixtureStore(t)
	store.BudgetSpans = []time.Duration{90 * time.Minute}

	attempts, result := attemptsByID(t, newService(t, store), caller(definitions.ScopeHistoryRead))
	if len(attempts) != 12 || store.Calls["Anchors"] < 3 {
		t.Fatalf("attempts = %d after %d anchor calls, want all through narrowed slices", len(attempts), store.Calls["Anchors"])
	}

	if !result.Page.ScannedUntil.Equal(searchRequest().Filter.From) {
		t.Fatalf("scanned until = %s, want the window start", result.Page.ScannedUntil)
	}

	store.BudgetSpans = []time.Duration{30 * time.Minute}
	if _, err := newService(t, store).SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), searchRequest()); !hasCode(err, supporthistory.CodeQueryTooBroad) {
		t.Fatalf("error = %v, want QUERY_TOO_BROAD below the minimum slice", err)
	}
}

// TestEmptyAnswersStayDistinguishable pins that missing sources, expiry, and unresolved identities never read as
// "the user did not log in".
func TestEmptyAnswersStayDistinguishable(t *testing.T) {
	cases := []struct {
		name       string
		presence   map[supporthistory.Source]supporthistory.SourcePresence
		login      string
		shift      time.Duration
		basis      string
		conditions []string
	}{
		{"unknown login", nil, "nobody@example.test", 0, "identity_unresolved", nil},
		{"expired window", nil, "anna@example.test", -10 * 24 * time.Hour, "window_expired", []string{"WINDOW_EXPIRED"}},
		{"login stream without rows", map[supporthistory.Source]supporthistory.SourcePresence{supporthistory.SourceLogins: supporthistory.PresenceNoRows},
			"nobody@example.test", 0, "source_without_rows", []string{"SOURCE_WITHOUT_ROWS_STREAM_DISABLED_OR_NO_TRAFFIC"}},
		{"login table missing", map[supporthistory.Source]supporthistory.SourcePresence{supporthistory.SourceLogins: supporthistory.PresenceNotInstalled},
			"nobody@example.test", 0, "source_not_installed", []string{"SOURCE_NOT_INSTALLED"}},
		{"mail-only deployment without step events", map[supporthistory.Source]supporthistory.SourcePresence{supporthistory.SourceAuthEvents: supporthistory.PresenceNoRows},
			"nobody@example.test", 0, "identity_unresolved", []string{"SOURCE_WITHOUT_ROWS_STREAM_DISABLED_OR_NO_TRAFFIC"}},
		{"account miss with healthy logins", map[supporthistory.Source]supporthistory.SourcePresence{supporthistory.SourceAuthEvents: supporthistory.PresenceNotInstalled},
			"", 0, "no_matches", []string{"SOURCE_NOT_INSTALLED"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := fixtureStore(t)
			store.Presences = tc.presence
			request := searchRequest()
			request.Subject.Login = tc.login

			if tc.login == "" {
				request.Subject.Account = "acc-nobody"
			}

			request.Filter.From, request.Filter.Until = request.Filter.From.Add(tc.shift), request.Filter.Until.Add(tc.shift)

			result, err := newService(t, store).SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), request)
			if err != nil {
				t.Fatalf("SearchAttempts() error = %v", err)
			}

			if len(result.Attempts) != 0 || result.ResultBasis != tc.basis {
				t.Fatalf("result = %d attempts, basis %s, want empty %s", len(result.Attempts), result.ResultBasis, tc.basis)
			}

			for _, condition := range tc.conditions {
				if !slices.Contains(result.History.Conditions, condition) {
					t.Fatalf("conditions = %v, want %s", result.History.Conditions, condition)
				}
			}

			if result.History.DeliveryCompleteness != "not_guaranteed" || len(result.History.KnownLimits) == 0 {
				t.Fatalf("history = %+v, want explicit delivery limits", result.History)
			}
		})
	}
}

// TestRequestValidationUsesSharedLimits pins the shared window and page bounds.
func TestRequestValidationUsesSharedLimits(t *testing.T) {
	service := newService(t, fixtureStore(t))
	mutate := map[string]func(*supporthistory.AttemptSearchRequest){
		"window above 31 days": func(r *supporthistory.AttemptSearchRequest) { r.Filter.From = r.Filter.Until.Add(-32 * 24 * time.Hour) },
		"reversed window":      func(r *supporthistory.AttemptSearchRequest) { r.Filter.From = r.Filter.Until.Add(time.Hour) },
		"page above maximum":   func(r *supporthistory.AttemptSearchRequest) { r.Page.Limit = 51 },
		"missing subject":      func(r *supporthistory.AttemptSearchRequest) { r.Subject = supporthistory.Subject{} },
		"bad client ip":        func(r *supporthistory.AttemptSearchRequest) { r.Filter.ClientIP = "not-an-ip" },
		"bad schema":           func(r *supporthistory.AttemptSearchRequest) { r.SchemaVersion = "2" },
		"bad cursor":           func(r *supporthistory.AttemptSearchRequest) { r.Page.Cursor = "%%%" },
	}

	for name, apply := range mutate {
		t.Run(name, func(t *testing.T) {
			request := searchRequest()
			apply(&request)

			if _, err := service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

// TestUnconfiguredServiceAnswersNotConfigured pins that a host without history source never invents an answer.
func TestUnconfiguredServiceAnswersNotConfigured(t *testing.T) {
	var service *supporthistory.Service

	_, err := service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), searchRequest())
	if !hasCode(err, supporthistory.CodeNotConfigured) {
		t.Fatalf("error = %v, want HISTORY_NOT_CONFIGURED", err)
	}
}

// blockingStore holds SelfCheck until released, to fill the gate.
type blockingStore struct {
	supporthistory.AttemptStore

	release chan struct{}
	entered chan struct{}
}

// SelfCheck blocks until the test releases it.
func (s blockingStore) SelfCheck(ctx context.Context) error {
	s.entered <- struct{}{}

	<-s.release

	return s.AttemptStore.SelfCheck(ctx)
}

// TestGateBoundsConcurrentCallsPerCaller pins the shared per-caller concurrency bound.
func TestGateBoundsConcurrentCallsPerCaller(t *testing.T) {
	store := blockingStore{AttemptStore: fixtureStore(t), release: make(chan struct{}), entered: make(chan struct{}, 4)}
	service := newService(t, store)
	who := caller(definitions.ScopeHistoryRead)
	done := make(chan error, 2)

	for range 2 {
		go func() {
			_, err := service.SearchAttempts(context.Background(), who, searchRequest())
			done <- err
		}()

		<-store.entered
	}

	if _, err := service.SearchAttempts(context.Background(), who, searchRequest()); !hasCode(err, supporthistory.CodeBusy) {
		t.Fatalf("third concurrent call error = %v, want HISTORY_BUSY", err)
	}

	close(store.release)

	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("blocked call error = %v", err)
		}
	}
}

// auditLog captures audit entries.
type auditLog struct {
	entries []supporthistory.AuditEntry
}

// RecordSupportAudit stores one entry.
func (a *auditLog) RecordSupportAudit(_ context.Context, entry supporthistory.AuditEntry) {
	a.entries = append(a.entries, entry)
}

// TestEveryCallIsAuditedWithoutClearSubject pins audit records for denied, invalid, and allowed calls.
func TestEveryCallIsAuditedWithoutClearSubject(t *testing.T) {
	log := &auditLog{}

	service, err := supporthistory.NewService(supporthistory.Options{Attempts: fixtureStore(t), Audit: log,
		Now: func() time.Time { return scenarioBase.Add(time.Hour) }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	invalid := searchRequest()
	invalid.Filter.From = invalid.Filter.Until.Add(-40 * 24 * time.Hour)
	invalid.AuditReference = "TICKET-1\nforged"

	_, _ = service.SearchAttempts(context.Background(), caller(), searchRequest())
	_, _ = service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), invalid)
	_, _ = service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), searchRequest())

	want := []struct {
		code    string
		allowed bool
	}{{"FORBIDDEN", false}, {"WINDOW_TOO_LARGE", true}, {"OK", true}}

	if len(log.entries) != len(want) {
		t.Fatalf("audit entries = %+v, want %d", log.entries, len(want))
	}

	for index, entry := range log.entries {
		if entry.ResultCode != want[index].code || entry.Allowed != want[index].allowed || entry.CallerIdentity == "" ||
			entry.SubjectDigest == "" || strings.Contains(fmt.Sprint(entry), "anna") || strings.Contains(entry.AuditReference, "\n") {
			t.Fatalf("audit entry %d = %+v, want %+v without clear-text subject", index, entry, want[index])
		}
	}
}
