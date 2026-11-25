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

// Package historytest provides a hermetic in-memory store for support history tests. It mirrors the documented
// query semantics of the ClickHouse reader (deployment binding, half-open ranges, subject predicates, newest-first
// anchors) so service and transport tests run without a database; the SQL itself is covered by the
// clickhouse_integration tests.
package historytest

import (
	"cmp"
	"context"
	"encoding/json"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// Store is an in-memory AttemptStore and BanStore.
type Store struct {
	Errors      map[string]error
	Presences   map[supporthistory.Source]supporthistory.SourcePresence
	Calls       map[string]int
	Logins      []supporthistory.LoginRecord
	Events      []supporthistory.AuthEventRecord
	Lifecycle   []supporthistory.LifecycleRecord
	DeployName  string
	mu          sync.Mutex
	BudgetSpans []time.Duration
}

// Fixture is the JSON shape of a scenario file in testdata.
type Fixture struct {
	Logins []supporthistory.LoginRecord     `json:"logins"`
	Events []supporthistory.AuthEventRecord `json:"events"`
}

// LoadFixture reads a scenario and shifts every timestamp so the newest row lies at base.
func LoadFixture(path string, base time.Time) (*Store, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fixture Fixture
	if err = json.Unmarshal(content, &fixture); err != nil {
		return nil, err
	}

	var newest time.Time

	for _, row := range fixture.Logins {
		newest = maxTime(newest, row.At)
	}

	for _, row := range fixture.Events {
		newest = maxTime(newest, row.At)
	}

	shift := base.Sub(newest)
	for index := range fixture.Logins {
		fixture.Logins[index].At = fixture.Logins[index].At.Add(shift)
	}

	for index := range fixture.Events {
		fixture.Events[index].At = fixture.Events[index].At.Add(shift)
	}

	return &Store{Logins: fixture.Logins, Events: fixture.Events, DeployName: "it"}, nil
}

// maxTime returns the later instant.
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}

	return b
}

// record counts a call and returns a configured error.
func (s *Store) record(method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Calls == nil {
		s.Calls = map[string]int{}
	}

	s.Calls[method]++

	return s.Errors[method]
}

// TotalCalls returns the number of data calls of any kind.
func (s *Store) TotalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := 0
	for _, count := range s.Calls {
		total += count
	}

	return total
}

// Deployment returns the bound deployment.
func (s *Store) Deployment() string {
	return s.DeployName
}

// SelfCheck succeeds unless an error is configured.
func (s *Store) SelfCheck(context.Context) error {
	return s.record("SelfCheck")
}

// Presence returns the configured presence, defaulting to rows.
func (s *Store) Presence(_ context.Context, source supporthistory.Source) supporthistory.SourcePresence {
	_ = s.record("Presence")

	if presence, ok := s.Presences[source]; ok {
		return presence
	}

	return supporthistory.PresenceRows
}

// ContractRowsSince returns the first contract row in the range.
func (s *Store) ContractRowsSince(_ context.Context, from, until time.Time) (*time.Time, bool) {
	if err := s.record("ContractRowsSince"); err != nil {
		return nil, false
	}

	var since *time.Time

	for _, row := range s.Logins {
		if row.ContractVersion >= 1 && inRange(row.At, from, until) && (since == nil || row.At.Before(*since)) {
			at := row.At
			since = &at
		}
	}

	return since, true
}

// OIDC completion event types of the reader contract.
const (
	codeIssuanceEvent   = "oidc.code_issuance"
	codeRedemptionEvent = "oidc.code_redemption"
)

// stepEventTypes mirrors the event types the reader selects.
var stepEventTypes = []string{"mfa.verification", codeIssuanceEvent, codeRedemptionEvent}

// completionEventTypes are the OIDC completion event types.
var completionEventTypes = []string{codeIssuanceEvent, codeRedemptionEvent}

// eventRetention mirrors the auth_events TTL that bounds the completion cutover probe.
const eventRetention = 7 * 24 * time.Hour

// CompletionEventsSince returns the first completion event before until within retention of the newest row.
func (s *Store) CompletionEventsSince(_ context.Context, until time.Time) (*time.Time, bool) {
	if err := s.record("CompletionEventsSince"); err != nil {
		return nil, false
	}

	var since *time.Time

	for _, row := range s.Events {
		if slices.Contains(completionEventTypes, row.EventType) && row.At.Before(until) &&
			until.Sub(row.At) <= eventRetention && (since == nil || row.At.Before(*since)) {
			at := row.At
			since = &at
		}
	}

	return since, true
}

// inRange reports whether at lies in [from, until).
func inRange(at, from, until time.Time) bool {
	return !at.Before(from) && at.Before(until)
}

// subjectLogin mirrors the SQL identity predicate of login rows.
func subjectLogin(match supporthistory.SubjectMatch, row supporthistory.LoginRecord) bool {
	return slices.Contains(match.Logins, row.Username) || (row.Account != "" && slices.Contains(match.Accounts, row.Account))
}

// authenticateRow mirrors the operation filter.
func authenticateRow(row supporthistory.LoginRecord) bool {
	return row.Operation == "authenticate" || row.Operation == ""
}

// filterMatch mirrors the anchor filters on login rows.
func filterMatch(filter supporthistory.AttemptFilter, row supporthistory.LoginRecord) bool {
	return (filter.ClientIP == "" || row.ClientIP == filter.ClientIP) &&
		(filter.Protocol == "" || row.Protocol == filter.Protocol) &&
		(filter.OIDCClientID == "" || row.OIDCClientID == filter.OIDCClientID) &&
		(filter.SAMLEntityID == "" || row.SAMLEntityID == filter.SAMLEntityID)
}

// loginKey returns the attempt key of a login row.
func loginKey(row supporthistory.LoginRecord) supporthistory.AttemptKey {
	if row.FlowRef != "" {
		return supporthistory.AttemptKey{Kind: supporthistory.AttemptFlow, Value: row.FlowRef}
	}

	return supporthistory.AttemptKey{Kind: supporthistory.AttemptRequest, Value: row.Session}
}

// eventKey returns the attempt key of a step event.
func eventKey(row supporthistory.AuthEventRecord) supporthistory.AttemptKey {
	if row.FlowRef != "" {
		return supporthistory.AttemptKey{Kind: supporthistory.AttemptFlow, Value: row.FlowRef}
	}

	return supporthistory.AttemptKey{Kind: supporthistory.AttemptRequest, Value: row.RequestID}
}

// Anchors mirrors the anchor query: latest subject-matching row per key, newest first, below the position.
func (s *Store) Anchors(_ context.Context, query supporthistory.AnchorQuery) ([]supporthistory.AttemptAnchor, error) {
	if err := s.record("Anchors"); err != nil {
		return nil, err
	}

	if limit := s.budgetSpan(); limit > 0 && query.Until.Sub(query.From) > limit {
		return nil, supporthistory.ErrBudgetExceeded
	}

	latest := map[supporthistory.AttemptKey]time.Time{}
	note := func(key supporthistory.AttemptKey, at time.Time) {
		if current, ok := latest[key]; !ok || at.After(current) {
			latest[key] = at
		}
	}

	for _, row := range s.Logins {
		if anchorsLogin(query, row) {
			note(loginKey(row), row.At)
		}
	}

	for _, row := range s.Events {
		if anchorsEvent(query, row) {
			note(eventKey(row), row.At)
		}
	}

	return orderedAnchors(latest, query), nil
}

// anchorsLogin mirrors the login half of the anchor predicate.
func anchorsLogin(query supporthistory.AnchorQuery, row supporthistory.LoginRecord) bool {
	return inRange(row.At, query.From, query.Until) && authenticateRow(row) && subjectLogin(query.Subject, row) &&
		filterMatch(query.Filter, row)
}

// anchorsEvent mirrors the step-event half of the anchor predicate, with the filters mapped onto event columns.
func anchorsEvent(query supporthistory.AnchorQuery, row supporthistory.AuthEventRecord) bool {
	filter := query.Filter

	return slices.Contains(stepEventTypes, row.EventType) && inRange(row.At, query.From, query.Until) &&
		row.Account != "" && slices.Contains(query.Subject.Accounts, row.Account) &&
		(filter.ClientIP == "" || row.ClientIP == filter.ClientIP) &&
		(filter.Protocol == "" || row.Protocol == filter.Protocol) &&
		(filter.OIDCClientID == "" || row.ClientID == filter.OIDCClientID) &&
		(filter.SAMLEntityID == "" || row.SAMLEntityID == filter.SAMLEntityID)
}

// budgetSpan returns the configured largest accepted slice, if any.
func (s *Store) budgetSpan() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.BudgetSpans) == 0 {
		return 0
	}

	return s.BudgetSpans[0]
}

// orderedAnchors sorts newest first, applies the exclusive position and the limit.
func orderedAnchors(latest map[supporthistory.AttemptKey]time.Time, query supporthistory.AnchorQuery) []supporthistory.AttemptAnchor {
	anchors := make([]supporthistory.AttemptAnchor, 0, len(latest))

	for key, at := range latest {
		at = at.Truncate(time.Millisecond)
		if query.Before != nil && !beforePosition(at, key.Value, *query.Before) {
			continue
		}

		anchors = append(anchors, supporthistory.AttemptAnchor{At: at, Key: key})
	}

	slices.SortFunc(anchors, func(a, b supporthistory.AttemptAnchor) int {
		if order := b.At.Compare(a.At); order != 0 {
			return order
		}

		return cmp.Compare(b.Key.Value, a.Key.Value)
	})

	if len(anchors) > query.Limit {
		anchors = anchors[:query.Limit]
	}

	return anchors
}

// beforePosition mirrors the SQL tuple comparison (anchor, key) < (position).
func beforePosition(at time.Time, key string, position supporthistory.AnchorPosition) bool {
	if order := at.Compare(position.At); order != 0 {
		return order < 0
	}

	return key < position.Key
}

// RecordedAccounts mirrors the recorded-account query.
func (s *Store) RecordedAccounts(_ context.Context, query supporthistory.AccountQuery) ([]string, error) {
	if err := s.record("RecordedAccounts"); err != nil {
		return nil, err
	}

	var accounts []string

	for _, row := range s.Logins {
		if inRange(row.At, query.From, query.Until) && authenticateRow(row) && row.Account != "" &&
			slices.Contains(query.Logins, row.Username) && !slices.Contains(accounts, row.Account) {
			accounts = append(accounts, row.Account)
		}
	}

	slices.Sort(accounts)

	return accounts, nil
}

// LoginRows mirrors the row query of login rows.
func (s *Store) LoginRows(_ context.Context, query supporthistory.RowQuery) ([]supporthistory.LoginRecord, error) {
	if err := s.record("LoginRows"); err != nil {
		return nil, err
	}

	var rows []supporthistory.LoginRecord

	for _, row := range s.Logins {
		if !inRange(row.At, query.From, query.Until) || !authenticateRow(row) {
			continue
		}

		flow := row.FlowRef != "" && slices.Contains(query.Flows, row.FlowRef)
		request := row.FlowRef == "" && slices.Contains(query.Requests, row.Session) &&
			(query.Subject == nil || subjectLogin(*query.Subject, row))

		if (flow || request) && afterPosition(row.At, row.EventID, query.LoginsAfter) {
			rows = append(rows, row)
		}
	}

	sortRows(rows, func(row supporthistory.LoginRecord) (time.Time, string) { return row.At, row.EventID })

	return limitGroups(rows, query.LimitPerGroup, loginKey), nil
}

// AuthEvents mirrors the row query of step events.
func (s *Store) AuthEvents(_ context.Context, query supporthistory.RowQuery) ([]supporthistory.AuthEventRecord, error) {
	if err := s.record("AuthEvents"); err != nil {
		return nil, err
	}

	var rows []supporthistory.AuthEventRecord

	for _, row := range s.Events {
		if !inRange(row.At, query.From, query.Until) || !slices.Contains(stepEventTypes, row.EventType) {
			continue
		}

		flow := row.FlowRef != "" && slices.Contains(query.Flows, row.FlowRef)
		request := row.FlowRef == "" && slices.Contains(query.Requests, row.RequestID) &&
			(query.Subject == nil || len(query.Subject.Accounts) == 0 || slices.Contains(query.Subject.Accounts, row.Account))

		if (flow || request) && afterPosition(row.At, row.EventID, query.EventsAfter) {
			rows = append(rows, row)
		}
	}

	sortRows(rows, func(row supporthistory.AuthEventRecord) (time.Time, string) { return row.At, row.EventID })

	return limitGroups(rows, query.LimitPerGroup, eventKey), nil
}

// afterPosition mirrors the keyset condition of a continuation read in (ts, event_id) order; the own source
// continues from its position inclusively.
func afterPosition(at time.Time, eventID string, position *supporthistory.RowPosition) bool {
	if position == nil {
		return true
	}

	switch order := at.Compare(position.At); {
	case order != 0:
		return order > 0
	case position.Bound == supporthistory.RowAfterInstant:
		return false
	case position.Bound == supporthistory.RowFromInstant:
		return true
	case position.Bound == supporthistory.RowAfterEventID:
		return eventID > position.EventID
	default:
		return eventID >= position.EventID
	}
}

// sortRows mirrors ORDER BY ts, event_id of the row reads.
func sortRows[T any](rows []T, key func(T) (time.Time, string)) {
	slices.SortStableFunc(rows, func(a, b T) int {
		atA, idA := key(a)
		atB, idB := key(b)

		return cmp.Or(atA.Compare(atB), cmp.Compare(idA, idB))
	})
}

// limitGroups orders by time and keeps at most limit rows per attempt key.
func limitGroups[T any](rows []T, limit int, key func(T) supporthistory.AttemptKey) []T {
	counts := map[supporthistory.AttemptKey]int{}
	result := make([]T, 0, len(rows))

	for _, row := range rows {
		if counts[key(row)]++; limit <= 0 || counts[key(row)] <= limit {
			result = append(result, row)
		}
	}

	return result
}
