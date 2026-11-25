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

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportapi"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
	"github.com/croessner/nauthilus/v4/server/supportops"
)

// retrievalBound is the MCP response bound of the full-retrieval tests.
const retrievalBound = 32 << 10

// retrievalLines is the number of stored log lines of the full-retrieval tests; hugeLine is the index of the line
// larger than the MCP bound.
const (
	retrievalLines = 40
	hugeLine       = 17
)

// retrievalBase is the time of the newest stored line of the full-retrieval tests.
var retrievalBase = time.Date(2026, time.November, 18, 7, 59, 0, 0, time.UTC)

// pagingEventSource is a Loki-named source that pages a fixed list of stored lines by position, one of them larger
// than the MCP response bound and full of characters JSON escapes twice.
type pagingEventSource struct{ fixedSource }

// Name returns the Loki source name.
func (pagingEventSource) Name() string { return supportops.SourceLoki }

// Kind returns the historical kind.
func (pagingEventSource) Kind() supportops.SourceKind { return supportops.SourceKindHistorical }

// retrievalLine returns stored line index.
func retrievalLine(index int) string {
	message := fmt.Sprintf("line-%02d", index)
	if index == hugeLine {
		message += strings.Repeat(`"\<&>`, 20000)
	}

	encoded, _ := json.Marshal(map[string]string{"level": "WARN", "msg": message, "password": "s3cr3t"})

	return string(encoded)
}

// LogEvents pages the stored lines; the position's skip counts the lines already returned.
func (pagingEventSource) LogEvents(_ context.Context, query supportops.LogEventsQuery) supportops.LogEventsSourceResult {
	start := 0
	if !query.Position.Before.IsZero() {
		start = query.Position.Skip
	}

	end := min(start+query.Limit, retrievalLines)
	result := supportops.LogEventsSourceResult{LimitApplied: query.Limit, Lines: []supportops.LogLine{},
		Report: supportops.SourceReport{Status: supportops.SourceStatusOK, Coverage: supportops.Coverage{Instances: []string{"mx-1"}}}}

	for index := start; index < end; index++ {
		result.Lines = append(result.Lines, supportops.LogLine{At: retrievalBase.Add(-time.Duration(index) * time.Second),
			Instance: "mx-1", Labels: map[string]string{"pod": "mx-1"}, Line: retrievalLine(index)})
	}

	if end < retrievalLines {
		result.More, result.Next = true, &supportops.LogPosition{Before: retrievalBase, Skip: end}
	}

	return result
}

// retrievalServer builds the MCP endpoint over the paging source and a history store with a grown flow.
func retrievalServer(t *testing.T) (*Server, supportapi.Services) {
	t.Helper()

	operations, err := supportops.NewService(supportops.Options{Sources: []supportops.Source{pagingEventSource{}}, Instance: "mx-1",
		Now: func() time.Time { return retrievalBase.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}

	services := parityServices(t)
	services.Operations, services.Segments = operations, supportapi.NewSegmentStore(nil)
	services.History = grownHistory(t)

	settings := &config.RuntimeMCPServerSection{Enabled: true, HostedResource: "support-mcp", TrustedProxies: []string{testProxy + "/32"},
		Limits: config.MCPLimits{FailedAuthPerMinute: 3, MaxResponseBytes: retrievalBound}}

	server, err := New(Deps{Settings: settings, Tokens: newAuthority(), Services: services, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}

	return server, services
}

// grownFlow is the fixture flow the retrieval test grows beyond the events page.
var grownFlow = strings.Repeat("1", 32)

// grownHistory returns the fixture history with 450 extra events of one flow, one of them stored 300 times.
func grownHistory(t *testing.T) *supporthistory.Service {
	t.Helper()

	store, err := historytest.LoadFixture("../supporthistory/testdata/attempt_scenarios.json", parityBase)
	if err != nil {
		t.Fatal(err)
	}

	at := parityBase.Add(-10 * time.Minute)
	event := func(id string, offset int) supporthistory.AuthEventRecord {
		return supporthistory.AuthEventRecord{At: at.Add(time.Duration(offset) * time.Millisecond), EventID: id,
			EventType: "mfa.verification", FlowRef: grownFlow, Account: "acc-anna", FactorRole: "second_factor", Method: "totp",
			Result: "invalid", Reason: "invalid_code", FlowEffect: "none", EventVersion: 1}
	}

	for range 300 {
		store.Events = append(store.Events, event("grown-replayed", 0))
	}

	for index := 1; index < 450; index++ {
		store.Events = append(store.Events, event(fmt.Sprintf("grown-%04d", index), index))
	}

	history, err := supporthistory.NewService(supporthistory.Options{Attempts: store, Bans: historytest.WithRecordedBan(store, "req-brute"),
		Now: func() time.Time { return parityBase.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}

	return history
}

// mcpAnswer calls a tool over raw HTTP, follows its segments, checks that every raw response stays within the bound,
// and returns the reassembled answer.
func mcpAnswer(t *testing.T, server *Server, tool string, arguments string) string {
	t.Helper()

	var data strings.Builder

	for calls := 0; calls < 500; calls++ {
		raw, text := rawToolCall(t, server, "1", tool, arguments)
		if len(raw) > retrievalBound {
			t.Fatalf("%s: raw MCP response of %d bytes, bound %d", tool, len(raw), retrievalBound)
		}

		var segment struct {
			Segment *struct {
				NextCursor *string `json:"next_cursor"`
			} `json:"segment"`
			Data string `json:"data"`
		}

		if err := json.Unmarshal([]byte(text), &segment); err != nil {
			t.Fatal(err)
		}

		if segment.Segment == nil {
			return text
		}

		data.WriteString(segment.Data)

		if segment.Segment.NextCursor == nil {
			return data.String()
		}

		tool, arguments = supportapi.OperationSegment, `{"schema_version":"1","cursor":"`+*segment.Segment.NextCursor+`"}`
	}

	t.Fatal("segments never ended")

	return ""
}

// eventPages pages the log events through call and returns every stored line in order.
func eventPages(t *testing.T, call func(arguments string) string) []supportops.LogEvent {
	t.Helper()

	var events []supportops.LogEvent

	arguments := `{"schema_version":"1","page":{"limit":7}}`

	for page := 0; page < 50; page++ {
		var answer supportops.LogEventsResult
		if err := json.Unmarshal([]byte(call(arguments)), &answer); err != nil {
			t.Fatal(err)
		}

		events = append(events, answer.Events...)

		if answer.Page.NextCursor == nil {
			return events
		}

		arguments = `{"schema_version":"1","page":{"limit":7,"cursor":"` + *answer.Page.NextCursor + `"}}`
	}

	t.Fatal("pages never ended")

	return nil
}

// assertEveryLine checks that every stored line arrived once, complete, and without its password.
func assertEveryLine(t *testing.T, transport string, events []supportops.LogEvent) {
	t.Helper()

	if len(events) != retrievalLines {
		t.Fatalf("%s: %d events, want %d", transport, len(events), retrievalLines)
	}

	for index, event := range events {
		want := strings.Replace(retrievalLine(index), `"s3cr3t"`, `"<redacted>"`, 1)
		if event.Line != want || strings.Contains(event.Line, "s3cr3t") || event.Fields["password"] != "<redacted>" {
			t.Fatalf("%s: event %d line of %d bytes differs from the stored line of %d bytes", transport, index, len(event.Line), len(want))
		}
	}
}

// TestLogEventsArriveCompleteOverHTTPAndMCP pins the full retrieval path: every stored line, including one larger
// than the MCP bound, arrives once and complete over MCP (pages and segments, every raw response within the bound)
// and over HTTP.
func TestLogEventsArriveCompleteOverHTTPAndMCP(t *testing.T) {
	server, services := retrievalServer(t)
	operation, _ := supportapi.Lookup(supportapi.OperationLogEvents)

	assertEveryLine(t, "MCP", eventPages(t, func(arguments string) string {
		return mcpAnswer(t, server, supportapi.OperationLogEvents, arguments)
	}))

	assertEveryLine(t, "HTTP", eventPages(t, func(arguments string) string {
		status, body := httpBody(t, services, operation, arguments, definitions.ScopeOperationsRead)
		if status != http.StatusOK {
			t.Fatalf("HTTP status = %d %s", status, body)
		}

		return body
	}))
}

// TestAttemptEventsArriveCompleteOverHTTPAndMCP pins the full history retrieval path: every distinct event of a flow
// that exceeds the events page, one of them stored 300 times, arrives once over MCP and over HTTP.
func TestAttemptEventsArriveCompleteOverHTTPAndMCP(t *testing.T) {
	server, services := retrievalServer(t)
	operation, _ := supportapi.Lookup(supportapi.OperationAttemptDetail)
	around := parityBase.Add(-10 * time.Minute).Format(time.RFC3339Nano)

	for transport, call := range map[string]func(arguments string) string{
		"MCP": func(arguments string) string {
			return mcpAnswer(t, server, supportapi.OperationAttemptDetail, arguments)
		},
		"HTTP": func(arguments string) string {
			_, body := httpBody(t, services, operation, arguments, definitions.ScopeHistoryRead)

			return body
		},
	} {
		seen := attemptEventPages(t, transport, call, `{"schema_version":"1","attempt_id":"fl1.`+grownFlow+`","around":"`+around+
			`","events_page":{"limit":50}}`)

		if len(seen) != 450 {
			t.Fatalf("%s: %d distinct grown events, want 450", transport, len(seen))
		}

		for id, count := range seen {
			if count != 1 {
				t.Fatalf("%s: event %s arrived %d times", transport, id, count)
			}
		}
	}
}

// attemptEventPages follows the events pages of one attempt through call and counts every grown event it lists.
func attemptEventPages(t *testing.T, transport string, call func(arguments string) string, arguments string) map[string]int {
	t.Helper()

	seen := map[string]int{}

	for page := 0; page < 100; page++ {
		var answer supporthistory.AttemptDetailResult
		if err := json.Unmarshal([]byte(call(arguments)), &answer); err != nil || answer.Attempt == nil {
			t.Fatalf("%s: answer = %+v, %v", transport, answer, err)
		}

		for _, event := range answer.Attempt.Events {
			if event.EventID != nil && strings.HasPrefix(*event.EventID, "grown-") {
				seen[*event.EventID]++
			}
		}

		next := answer.Attempt.EventsPage
		if next == nil || next.NextCursor == nil {
			return seen
		}

		arguments = `{"schema_version":"1","attempt_id":"` + next.Detail.AttemptID + `","around":"` +
			next.Detail.Around.Format(time.RFC3339Nano) + `","events_page":{"limit":50,"cursor":"` + *next.NextCursor + `"}}`
	}

	t.Fatalf("%s: pages never ended", transport)

	return nil
}
