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

package supportops

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// fakeLogSource is a Loki-named source that answers a fixed log overview and records its queries.
type fakeLogSource struct {
	fakeSource

	overview LogOverviewSourceResult
	asked    []LogOverviewQuery
}

// LogOverview records the query and answers the fixed result.
func (f *fakeLogSource) LogOverview(_ context.Context, query LogOverviewQuery) LogOverviewSourceResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.asked = append(f.asked, query)

	return f.overview
}

// testGrid returns three ten-minute buckets that end at testNow.
func testGrid() []Window {
	grid := make([]Window, 0, 3)

	for index := range 3 {
		from := testNow.Add(time.Duration(index-3) * 10 * time.Minute)
		grid = append(grid, Window{From: from, Until: from.Add(10 * time.Minute)})
	}

	return grid
}

// newLogSource returns a Loki source with full coverage of the test grid.
func newLogSource(series ...LogSeries) *fakeLogSource {
	grid := testGrid()

	return &fakeLogSource{fakeSource: fakeSource{name: SourceLoki, kind: SourceKindHistorical},
		overview: LogOverviewSourceResult{Buckets: grid, Series: series, Report: SourceReport{Status: SourceStatusOK,
			Coverage: Coverage{Instances: []string{"mx-1", "mx-2"}, View: CoverageLogLabels, From: TimePointer(grid[0].From),
				Until: TimePointer(testNow)}}}}
}

// overviewRequest asks for the last 30 minutes.
func overviewRequest(levels ...string) LogOverviewRequest {
	return LogOverviewRequest{SchemaVersion: SchemaVersion, Levels: levels,
		Window: &Window{From: testNow.Add(-30 * time.Minute), Until: testNow}}
}

// TestNormalizeLogMessage pins which parts of an observed message leave the host: fixed words stay, and values such as
// IPs, quoted names, mail addresses, error payloads, and values after sensitive keywords are replaced.
func TestNormalizeLogMessage(t *testing.T) {
	for raw, want := range map[string][2]string{
		"WebAuthn sign count anomaly":                                      {"WebAuthn sign count anomaly", MessageFormLiteral},
		"RBL check failed":                                                 {"RBL check failed", MessageFormLiteral},
		"LDAP free/busy state is free":                                     {"LDAP free/busy state is free", MessageFormLiteral},
		"Client IP '203.0.113.7' not matching [10.0.0.0/8]":                {"Client IP <quoted> not matching [<value>]", MessageFormNormalized},
		"lookup 7.113.0.203.zen.spamhaus.org on 10.0.0.53:53: i/o timeout": {"lookup <value> on <value>: i/o timeout", MessageFormNormalized},
		`Authentication failed for "alice"`:                                {"Authentication failed for <quoted>", MessageFormNormalized},
		"Mail for bob@example.org rejected":                                {"Mail for <value> rejected", MessageFormNormalized},
		"Lookup failed for user alice":                                     {"Lookup failed for user <value>", MessageFormNormalized},
		"login: carol locked":                                              {"login: <value> locked", MessageFormNormalized},
		"Fetch https://idp.example.org/x failed":                           {"Fetch <value> failed", MessageFormNormalized},
		"Connection #12 closed":                                            {"Connection <value> closed", MessageFormNormalized},
		"Session aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa expired":             {"Session <value> expired", MessageFormNormalized},
		"Error \u202ehidden\n text":                                        {"Error hidden text", MessageFormNormalized},
		"  ":                                                               {placeholderEmpty, MessageFormNormalized},
	} {
		text, form := normalizeLogMessage(raw)
		if text != want[0] || form != want[1] {
			t.Errorf("normalizeLogMessage(%q) = %q, %q; want %q, %q", raw, text, form, want[0], want[1])
		}
	}

	if text, _ := normalizeLogMessage(strings.Repeat("word ", 100)); len([]rune(text)) > maxMessageRunes+1 {
		t.Errorf("normalized message exceeds the bound: %d runes", len([]rune(text)))
	}
}

// TestLogOverviewGroupsAndBounds pins grouping by level and normalized message across instances, the bucket timeline,
// the profiled symptom of a literal message, the observed status, the order, and the notes.
func TestLogOverviewGroupsAndBounds(t *testing.T) {
	source := newLogSource(
		LogSeries{Instance: "mx-1", Level: LogLevelError, Message: "lookup 1.2.3.4.zen.example on 10.0.0.1:53: i/o timeout", Counts: []int64{0, 2, 0}},
		LogSeries{Instance: "mx-2", Level: LogLevelError, Message: "lookup 5.6.7.8.zen.example on 10.0.0.1:53: i/o timeout", Counts: []int64{0, 0, 3}},
		LogSeries{Instance: "mx-1", Level: LogLevelWarn, Message: "WebAuthn sign count anomaly", Counts: []int64{1, 0, 0}},
		LogSeries{Instance: "mx-2", Level: LogLevelError, Message: "LDAP connection error", Counts: []int64{0, 0, 1},
			Component: ComponentLDAP, Symptom: SymptomLDAPConnectionError},
		LogSeries{Instance: "mx-2", Level: LogLevelWarn, Message: "never counted", Counts: []int64{0, 0, 0}},
	)

	result, err := newTestService(t, &auditLog{}, source).LogOverview(context.Background(), operator(), overviewRequest())
	if err != nil {
		t.Fatalf("LogOverview() = %v", err)
	}

	if len(result.Messages) != 3 || result.BucketSeconds != 600 || len(result.Buckets) != 3 || result.Source.Name != SourceLoki {
		t.Fatalf("result = %+v", result)
	}

	assertMergedResolverGroup(t, result.Messages[0])

	if ldap := result.Messages[1]; ldap.Symptom != SymptomLDAPConnectionError || ldap.Level != LogLevelError {
		t.Fatalf("errors sort before warnings at equal counts and keep their symptom: %+v", ldap)
	}

	if !slices.Equal(result.Notes, []string{NoteValuesAreUntrusted, NoteLogMessagesAreNotIncidents, NoteLogMessagesNormalized}) {
		t.Fatalf("notes = %v", result.Notes)
	}

	if levels := source.asked[0].Levels; !slices.Equal(levels, LogLevels) {
		t.Fatalf("levels = %v", levels)
	}
}

// assertMergedResolverGroup checks the group that merges the resolver timeouts of two instances.
func assertMergedResolverGroup(t *testing.T, dns LogMessageGroup) {
	t.Helper()

	if dns.ID != "L1" || dns.Message != "lookup <value> on <value>: i/o timeout" || dns.Count != 5 ||
		dns.Status != StatusObserved || dns.MessageForm != MessageFormNormalized || !slices.Equal(dns.Counts, []int64{0, 2, 3}) {
		t.Fatalf("dns group = %+v", dns)
	}

	if !slices.Equal(dns.Instances, []LogInstanceCount{{"mx-2", 3}, {"mx-1", 2}}) ||
		!dns.FirstBucket.Equal(testGrid()[1].From) || !dns.LastBucket.Equal(testNow) {
		t.Fatalf("dns group instances and buckets = %+v", dns)
	}
}

// TestLogOverviewOmitsGroupsBeyondTheBound pins the group cap and its omission statement.
func TestLogOverviewOmitsGroupsBeyondTheBound(t *testing.T) {
	series := make([]LogSeries, 0, maxLogGroups+2)

	for index := range maxLogGroups + 2 {
		series = append(series, LogSeries{Instance: "mx-1", Level: LogLevelWarn, Message: fmt.Sprintf("warning %c", 'a'+rune(index%26)) +
			strings.Repeat("x", index/26), Counts: []int64{0, 0, 1}})
	}

	result, err := newTestService(t, &auditLog{}, newLogSource(series...)).LogOverview(context.Background(), operator(), overviewRequest(LogLevelWarn))
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Messages) != maxLogGroups || result.Omitted != (LogOmission{Groups: 2, Lines: 2}) ||
		!slices.Contains(result.Notes, NoteLogGroupsOmitted) {
		t.Fatalf("omission = %+v, notes = %v", result.Omitted, result.Notes)
	}
}

// TestLogOverviewSourceStates pins the not-configured, incomplete, and grid-extension notes.
func TestLogOverviewSourceStates(t *testing.T) {
	runtime := &fakeSource{name: SourceRuntime, kind: SourceKindLocalCurrent}

	result, err := newTestService(t, &auditLog{}, runtime).LogOverview(context.Background(), operator(), overviewRequest())
	if err != nil || result.Source.Status != SourceStatusNotConfigured || len(result.Messages) != 0 ||
		!slices.Contains(result.Notes, NoteNoHistoricalSource) {
		t.Fatalf("not configured = %+v, %v", result, err)
	}

	partial := newLogSource()
	partial.overview.Report.Status, partial.overview.Report.Truncated = SourceStatusPartial, true
	partial.overview.Report.Coverage.From = TimePointer(testNow.Add(-31 * time.Minute))

	result, err = newTestService(t, &auditLog{}, partial).LogOverview(context.Background(), operator(), overviewRequest())
	if err != nil || !slices.Contains(result.Notes, NoteHistoricalSourceIncomplete) || !slices.Contains(result.Notes, NoteLogBucketsExceedWindow) {
		t.Fatalf("partial notes = %v, %v", result.Notes, err)
	}
}

// TestLogOverviewAuthorizationAndAudit pins the operations scope, the level vocabulary, and one audit entry per call.
func TestLogOverviewAuthorizationAndAudit(t *testing.T) {
	audit := &auditLog{}
	service := newTestService(t, audit, newLogSource())
	historyOnly := NewCaller(supportaccess.VerifiedCredential{Method: supportaccess.CredentialOIDCBearer, ClientID: "console",
		Scopes: []string{definitions.ScopeHistoryRead}})

	for name, tc := range map[string]struct {
		caller  Caller
		request LogOverviewRequest
		code    ErrorCode
	}{
		"missing scope":  {historyOnly, overviewRequest(), CodeForbidden},
		"bad schema":     {operator(), LogOverviewRequest{SchemaVersion: "2"}, CodeInvalidRequest},
		"unknown level":  {operator(), overviewRequest("debug"), CodeInvalidRequest},
		"repeated level": {operator(), overviewRequest(LogLevelWarn, LogLevelWarn), CodeInvalidRequest},
		"too large":      {operator(), LogOverviewRequest{SchemaVersion: SchemaVersion, Window: &Window{From: testNow.Add(-25 * time.Hour), Until: testNow}}, CodeWindowTooLarge},
	} {
		_, err := service.LogOverview(context.Background(), tc.caller, tc.request)

		var supportErr *Error
		if !errors.As(err, &supportErr) || supportErr.Code != tc.code {
			t.Errorf("%s: err = %v, want %s", name, err, tc.code)
		}
	}

	if _, err := service.LogOverview(context.Background(), operator(), overviewRequest()); err != nil {
		t.Fatal(err)
	}

	last := audit.entries[len(audit.entries)-1]
	if len(audit.entries) != 6 || last.Operation != operationLogOverview || !last.Allowed || last.ResultCode != "OK" ||
		!slices.ContainsFunc(audit.entries, func(entry supportaccess.AuditEntry) bool {
			return !entry.Allowed && entry.ResultCode == string(CodeForbidden)
		}) {
		t.Fatalf("audit = %+v", audit.entries)
	}

	var nilService *Service
	if _, err := nilService.LogOverview(context.Background(), operator(), overviewRequest()); AsError(err).Code != CodeNotConfigured {
		t.Fatalf("nil service = %v", err)
	}
}

// TestLogOverviewCoverageAndMergedForms pins the note for a window without any covered instance and that a group is
// normalized, without the profiled symptom, as soon as one merged series was normalized, whatever the series order.
func TestLogOverviewCoverageAndMergedForms(t *testing.T) {
	empty := newLogSource()
	empty.overview.Report.Coverage.Instances = nil

	result, err := newTestService(t, &auditLog{}, empty).LogOverview(context.Background(), operator(), overviewRequest())
	if err != nil || !slices.Contains(result.Notes, NoteLogNoCoverage) {
		t.Fatalf("no coverage notes = %v, %v", result.Notes, err)
	}

	literal := LogSeries{Instance: "mx-1", Level: LogLevelError, Message: "LDAP connection error", Counts: []int64{0, 0, 1},
		Component: ComponentLDAP, Symptom: SymptomLDAPConnectionError}
	spaced := LogSeries{Instance: "mx-2", Level: LogLevelError, Message: "LDAP  connection error", Counts: []int64{0, 1, 0}}

	for _, order := range [][]LogSeries{{literal, spaced}, {spaced, literal}} {
		result, err = newTestService(t, &auditLog{}, newLogSource(order...)).LogOverview(context.Background(), operator(), overviewRequest())
		if err != nil || len(result.Messages) != 1 {
			t.Fatalf("merge = %+v, %v", result, err)
		}

		if group := result.Messages[0]; group.MessageForm != MessageFormNormalized || group.Symptom != "" || group.Count != 2 {
			t.Fatalf("merged group = %+v", group)
		}
	}
}
