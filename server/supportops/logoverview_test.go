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

// TestLogOverviewKeepsEveryMessageComplete reproduces the masking gap: two resolver timeouts with different hosts used
// to merge into one placeholder group. Every exact message must stay its own group with its complete text, identical
// messages of different instances share a group, and errors sort before warnings at equal counts.
func TestLogOverviewKeepsEveryMessageComplete(t *testing.T) {
	first := "lookup 1.2.3.4.zen.example on 10.0.0.1:53: i/o timeout"
	second := "lookup 5.6.7.8.zen.example on 10.0.0.1:53: i/o timeout"
	source := newLogSource(
		LogSeries{Instance: "mx-1", Level: LogLevelError, Message: first, Counts: []int64{0, 2, 0}},
		LogSeries{Instance: "mx-2", Level: LogLevelError, Message: first, Counts: []int64{0, 0, 1}},
		LogSeries{Instance: "mx-2", Level: LogLevelError, Message: second, Counts: []int64{0, 0, 3}},
		LogSeries{Instance: "mx-1", Level: LogLevelWarn, Message: "Client IP '198.51.100.1' not matching [10.0.0.0/8]", Counts: []int64{1, 0, 0}},
		LogSeries{Instance: "mx-2", Level: LogLevelError, Message: "LDAP connection error", Counts: []int64{0, 0, 1},
			Component: ComponentLDAP, Symptom: SymptomLDAPConnectionError},
		LogSeries{Instance: "mx-2", Level: LogLevelWarn, Message: "never counted", Counts: []int64{0, 0, 0}},
	)

	result, err := newTestService(t, &auditLog{}, source).LogOverview(context.Background(), operator(), overviewRequest())
	if err != nil {
		t.Fatalf("LogOverview() = %v", err)
	}

	if len(result.Messages) != 4 || result.BucketSeconds != 600 || len(result.Buckets) != 3 || result.Source.Name != SourceLoki ||
		result.Page != (LogPageResult{Limit: DefaultLogGroupPageLimit, Total: 4}) {
		t.Fatalf("result = %+v", result)
	}

	assertExactGroups(t, result.Messages, first, second)

	if !slices.Equal(result.Notes, []string{NoteValuesAreUntrusted, NoteLogMessagesAreNotIncidents}) {
		t.Fatalf("notes = %v", result.Notes)
	}

	if levels := source.asked[0].Levels; !slices.Equal(levels, DefaultLogLevels) {
		t.Fatalf("levels = %v", levels)
	}
}

// assertExactGroups checks that every exact message is its own group in count order, that identical messages of two
// instances share one group, and that a profiled message keeps its symptom.
func assertExactGroups(t *testing.T, groups []LogMessageGroup, first string, second string) {
	t.Helper()

	want := []struct {
		message string
		count   int64
	}{{first, 3}, {second, 3}, {"LDAP connection error", 1}, {"Client IP '198.51.100.1' not matching [10.0.0.0/8]", 1}}

	for index, group := range groups {
		if group.Message != want[index].message || group.Count != want[index].count || group.ID != fmt.Sprintf("L%d", index+1) {
			t.Errorf("group %d = %+v, want %+v", index, group, want[index])
		}
	}

	if dns := groups[0]; !slices.Equal(dns.Instances, []LogInstanceCount{{"mx-1", 2}, {"mx-2", 1}}) ||
		!dns.FirstBucket.Equal(testGrid()[1].From) || !dns.LastBucket.Equal(testNow) || !slices.Equal(dns.Counts, []int64{0, 2, 1}) {
		t.Fatalf("dns group = %+v", dns)
	}

	if slices.ContainsFunc(groups, func(group LogMessageGroup) bool { return !group.MessageExact }) {
		t.Fatalf("every message of the fixture is stored as shown: %+v", groups)
	}

	if ldap := groups[2]; ldap.Symptom != SymptomLDAPConnectionError || !ldap.MessageExact {
		t.Fatalf("a profiled message keeps its symptom: %+v", ldap)
	}
}

// TestLogOverviewRedactsOnlySecrets pins that a message keeps users, addresses, and error text, and that only an
// authentication secret is replaced and flagged.
func TestLogOverviewRedactsOnlySecrets(t *testing.T) {
	source := newLogSource(LogSeries{Instance: "mx-1", Level: LogLevelWarn, Counts: []int64{0, 0, 1},
		Message: "token rejected for alice@example.org from 203.0.113.9: Bearer abcdefghijklmnop1234"})

	result, err := newTestService(t, &auditLog{}, source).LogOverview(context.Background(), operator(), overviewRequest())
	if err != nil || len(result.Messages) != 1 {
		t.Fatalf("result = %+v, %v", result, err)
	}

	if group := result.Messages[0]; group.Message != "token rejected for alice@example.org from 203.0.113.9: Bearer <redacted>" ||
		!group.SecretsRedacted || group.MessageExact || !slices.Contains(result.Notes, NoteLogSecretsRedacted) {
		t.Fatalf("group = %+v, notes = %v", group, result.Notes)
	}
}

// TestLogOverviewPagesThroughEveryGroup pins that no group is omitted: pages continue with next_cursor until every
// group was returned once, numbered by its position, and a cursor of another query is refused.
func TestLogOverviewPagesThroughEveryGroup(t *testing.T) {
	series := make([]LogSeries, 0, 7)

	for index := range 7 {
		series = append(series, LogSeries{Instance: "mx-1", Level: LogLevelWarn, Message: fmt.Sprintf("warning %d", index),
			Counts: []int64{0, 0, int64(10 - index)}})
	}

	service := newTestService(t, &auditLog{}, newLogSource(series...))
	request := overviewRequest(LogLevelWarn)
	request.Page = &LogPage{Limit: 3}

	var seen []string

	for page := 0; ; page++ {
		result, err := service.LogOverview(context.Background(), operator(), request)
		if err != nil || page > 3 {
			t.Fatalf("page %d: %v", page, err)
		}

		for _, group := range result.Messages {
			seen = append(seen, group.ID+"="+group.Message)
		}

		if result.Page.NextCursor == nil {
			break
		}

		if !slices.Contains(result.Notes, NoteLogMorePages) {
			t.Fatalf("notes = %v", result.Notes)
		}

		request.Page.Cursor = *result.Page.NextCursor
	}

	if len(seen) != 7 || seen[0] != "L1=warning 0" || seen[6] != "L7=warning 6" {
		t.Fatalf("pages = %v", seen)
	}

	other := overviewRequest(LogLevelError)
	other.Page = &LogPage{Cursor: request.Page.Cursor}

	if _, err := service.LogOverview(context.Background(), operator(), other); AsError(err).Code != CodeInvalidCursor {
		t.Fatalf("foreign cursor = %v", err)
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
		"unknown level":  {operator(), overviewRequest("trace"), CodeInvalidRequest},
		"page too large": {operator(), LogOverviewRequest{SchemaVersion: SchemaVersion, Page: &LogPage{Limit: MaxLogGroupPageLimit + 1}}, CodeInvalidRequest},
		"bad cursor":     {operator(), LogOverviewRequest{SchemaVersion: SchemaVersion, Page: &LogPage{Cursor: "not-a-cursor"}}, CodeInvalidCursor},
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
	if len(audit.entries) != 8 || last.Operation != operationLogOverview || !last.Allowed || last.ResultCode != "OK" ||
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

// TestLogOverviewWithoutCoverage pins the note for a window without any covered instance.
func TestLogOverviewWithoutCoverage(t *testing.T) {
	empty := newLogSource()
	empty.overview.Report.Coverage.Instances = nil

	result, err := newTestService(t, &auditLog{}, empty).LogOverview(context.Background(), operator(), overviewRequest())
	if err != nil || !slices.Contains(result.Notes, NoteLogNoCoverage) {
		t.Fatalf("no coverage notes = %v, %v", result.Notes, err)
	}
}
