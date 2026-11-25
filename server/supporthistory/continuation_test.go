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
	"cmp"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
)

// continuedFlow is the latched fixture flow that the continuation tests grow beyond the event bound.
var continuedFlow = strings.Repeat("2", 32)

// continuedFlowEvents is the number of events the fixture records for continuedFlow before it is grown.
const continuedFlowEvents = 4

// continuedBanRef is the activation id of the continuation ban tests.
var continuedBanRef = strings.Repeat("a", 32)

// growFlow appends count second-factor events to a fixture flow, one millisecond apart and older than the fixture.
func growFlow(store *historytest.Store, flow string, count int) {
	for index := range count {
		store.Events = append(store.Events, supporthistory.AuthEventRecord{
			At:      scenarioBase.Add(-30*time.Minute + time.Duration(index)*time.Millisecond),
			EventID: fmt.Sprintf("grown-%04d", index), EventType: "mfa.verification", FlowRef: flow, Account: "acc-anna",
			FactorRole: "second_factor", Method: "totp", Result: "invalid", Reason: "invalid_code", FlowEffect: "none",
			EventVersion: 1, FailLatched: true})
	}
}

// eventCollector gathers listed events across pages and fails on repeats or sequence gaps. key identifies an
// event; nil identifies it by its event id.
type eventCollector struct {
	t    *testing.T
	seen map[string]struct{}
	key  func(supporthistory.Event) string
	next int
}

// add records one page of events.
func (c *eventCollector) add(events []supporthistory.Event) {
	c.t.Helper()

	for _, event := range events {
		id := stringValue(event.EventID)
		if c.key != nil {
			id = c.key(event)
		}

		if id == "" {
			c.t.Fatalf("event %+v carries no id", event)
		}

		if _, repeated := c.seen[id]; repeated {
			c.t.Fatalf("event %s listed twice", id)
		}

		c.next++
		if event.Sequence != c.next {
			c.t.Fatalf("event %s has sequence %d, want %d", id, event.Sequence, c.next)
		}

		c.seen[id] = struct{}{}
	}
}

// walkEvents follows an events page through the detail lookup and returns how many pages it read.
func walkEvents(t *testing.T, service *supporthistory.Service, collector *eventCollector, page *supporthistory.EventsPage, outcome string, limit int) int {
	t.Helper()

	pages := 0

	for page != nil && page.NextCursor != nil {
		result, err := service.GetAttempt(context.Background(), caller(definitions.ScopeHistoryRead),
			supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: page.Detail.AttemptID,
				Around: page.Detail.Around, EventsPage: &supporthistory.PageRequest{Cursor: *page.NextCursor, Limit: limit}})
		if err != nil || result.Attempt == nil {
			t.Fatalf("GetAttempt(continuation) = %+v, %v", result, err)
		}

		if result.Attempt.Outcome != outcome {
			t.Fatalf("continuation outcome = %s, want the outcome of the complete attempt %s", result.Attempt.Outcome, outcome)
		}

		collector.add(result.Attempt.Events)
		page, pages = result.Attempt.EventsPage, pages+1

		if pages > 100 {
			t.Fatal("events paging does not terminate")
		}
	}

	return pages
}

// TestAttemptEventsBeyondTheBoundAreReachable reproduces the silent event cut: an attempt with more events than
// MaxEventsPerAttempt listed the first ones only and offered no way to read the rest.
func TestAttemptEventsBeyondTheBoundAreReachable(t *testing.T) {
	store := fixtureStore(t)
	grown := supporthistory.MaxEventsPerAttempt + 37
	growFlow(store, continuedFlow, grown)

	service := newService(t, store)
	attempts, _ := attemptsByID(t, service, caller(definitions.ScopeHistoryRead))
	attempt := attempts["fl1."+continuedFlow]

	if !attempt.Recording.EventsTruncated || attempt.EventsPage == nil || attempt.EventsPage.NextCursor == nil {
		t.Fatalf("search attempt recording = %+v page = %+v, want a continuation", attempt.Recording, attempt.EventsPage)
	}

	collector := &eventCollector{t: t, seen: map[string]struct{}{}}
	collector.add(attempt.Events)
	walkEvents(t, service, collector, attempt.EventsPage, attempt.Outcome, 0)

	if want := continuedFlowEvents + grown; len(collector.seen) != want {
		t.Fatalf("reachable events = %d, want every recorded event %d", len(collector.seen), want)
	}

	small := &eventCollector{t: t, seen: map[string]struct{}{}}

	first, err := service.GetAttempt(context.Background(), caller(definitions.ScopeHistoryRead),
		supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: attempt.AttemptID, Around: attempt.StartedAt,
			EventsPage: &supporthistory.PageRequest{Limit: 7}})
	if err != nil || first.Attempt == nil || len(first.Attempt.Events) != 7 {
		t.Fatalf("GetAttempt(limit 7) = %+v, %v, want seven events", first, err)
	}

	small.add(first.Attempt.Events)

	if pages := walkEvents(t, service, small, first.Attempt.EventsPage, attempt.Outcome, 7); len(small.seen) != len(collector.seen) || pages < 30 {
		t.Fatalf("small pages reached %d events in %d pages, want %d", len(small.seen), pages, len(collector.seen))
	}
}

// growLegacyFlow appends count second-factor events without event id to a fixture flow, all at one millisecond, so
// their whole merged position is equal; the instance tells them apart.
func growLegacyFlow(store *historytest.Store, flow string, count int) {
	at := scenarioBase.Add(-30 * time.Minute)

	for index := range count {
		store.Events = append(store.Events, supporthistory.AuthEventRecord{
			At: at, Instance: fmt.Sprintf("legacy-%04d", index), EventType: "mfa.verification", FlowRef: flow,
			Account: "acc-anna", FactorRole: "second_factor", Method: "totp", Result: "invalid", Reason: "invalid_code",
			FlowEffect: "none", EventVersion: 1, FailLatched: true})
	}
}

// eventKey identifies a fixture event by its id, or a legacy event by its instance.
func eventKey(event supporthistory.Event) string {
	return cmp.Or(stringValue(event.EventID), event.Instance)
}

// TestLegacyEventGroupsBeyondTheReadBoundAreReachable reproduces the lost-item defect of the events continuation:
// more rows without event id at one instant than one read holds cut the group, and a continuation after the
// shared position skipped the unread rest.
func TestLegacyEventGroupsBeyondTheReadBoundAreReachable(t *testing.T) {
	for _, grown := range []int{205, 420} {
		for _, limit := range []int{0, 7} {
			store := fixtureStore(t)
			growLegacyFlow(store, continuedFlow, grown)

			service := newService(t, store)
			attempts, _ := attemptsByID(t, service, caller(definitions.ScopeHistoryRead))
			attempt := attempts["fl1."+continuedFlow]
			collector := &eventCollector{t: t, seen: map[string]struct{}{}, key: eventKey}

			first, err := service.GetAttempt(context.Background(), caller(definitions.ScopeHistoryRead),
				supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: attempt.AttemptID,
					Around: attempt.StartedAt, EventsPage: &supporthistory.PageRequest{Limit: limit}})
			if err != nil || first.Attempt == nil {
				t.Fatalf("GetAttempt(limit %d) = %+v, %v", limit, first, err)
			}

			collector.add(first.Attempt.Events)
			walkEvents(t, service, collector, first.Attempt.EventsPage, attempt.Outcome, limit)

			if want := continuedFlowEvents + grown; len(collector.seen) != want {
				t.Fatalf("%d legacy rows, limit %d: reachable events = %d, want every recorded event %d", grown, limit,
					len(collector.seen), want)
			}
		}
	}
}

// TestShortAttemptsOfferNoEventContinuation pins that a complete attempt carries neither flag nor cursor.
func TestShortAttemptsOfferNoEventContinuation(t *testing.T) {
	attempts, _ := attemptsByID(t, newService(t, fixtureStore(t)), caller(definitions.ScopeHistoryRead))

	for id, attempt := range attempts {
		if attempt.Recording.EventsTruncated || attempt.EventsPage != nil {
			t.Fatalf("attempt %s recording = %+v page = %+v, want no continuation", id, attempt.Recording, attempt.EventsPage)
		}
	}
}

// TestEventCursorsAreBoundAndLimitsValidated pins that an events cursor only continues its own attempt lookup and
// that the events page limit is bounded.
func TestEventCursorsAreBoundAndLimitsValidated(t *testing.T) {
	store := fixtureStore(t)
	growFlow(store, continuedFlow, supporthistory.MaxEventsPerAttempt+1)

	service := newService(t, store)
	attempts, _ := attemptsByID(t, service, caller(definitions.ScopeHistoryRead))
	page := attempts["fl1."+continuedFlow].EventsPage

	if page == nil || page.NextCursor == nil {
		t.Fatalf("events page = %+v, want a continuation", page)
	}

	detail := func(id string, around time.Time, events supporthistory.PageRequest) error {
		_, err := service.GetAttempt(context.Background(), caller(definitions.ScopeHistoryRead),
			supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: id, Around: around, EventsPage: &events})

		return err
	}

	cases := map[string]struct {
		err    error
		code   supporthistory.ErrorCode
		wanted bool
	}{
		"other attempt":  {err: detail("fl1."+strings.Repeat("1", 32), page.Detail.Around, supporthistory.PageRequest{Cursor: *page.NextCursor}), code: supporthistory.CodeInvalidCursor},
		"other around":   {err: detail(page.Detail.AttemptID, page.Detail.Around.Add(time.Second), supporthistory.PageRequest{Cursor: *page.NextCursor}), code: supporthistory.CodeInvalidCursor},
		"garbage cursor": {err: detail(page.Detail.AttemptID, page.Detail.Around, supporthistory.PageRequest{Cursor: "bm90LWEtY3Vyc29y"}), code: supporthistory.CodeInvalidCursor},
		"limit too high": {err: detail(page.Detail.AttemptID, page.Detail.Around, supporthistory.PageRequest{Limit: supporthistory.MaxEventsPerAttempt + 1}), code: supporthistory.CodeInvalidRequest},
		"negative limit": {err: detail(page.Detail.AttemptID, page.Detail.Around, supporthistory.PageRequest{Limit: -1}), code: supporthistory.CodeInvalidRequest},
		"own cursor":     {err: detail(page.Detail.AttemptID, page.Detail.Around, supporthistory.PageRequest{Cursor: *page.NextCursor}), wanted: true},
	}

	for name, check := range cases {
		if check.wanted {
			if check.err != nil {
				t.Fatalf("%s: error = %v, want none", name, check.err)
			}

			continue
		}

		if !hasCode(check.err, check.code) {
			t.Fatalf("%s: error = %v, want %s", name, check.err, check.code)
		}
	}
}

// continuedBanStore returns the shared-IP scenario with one activation over many contributions and many hit claimants.
func continuedBanStore(contributions, claimants int) *historytest.BanStore {
	activatedAt := banNow.Add(-2 * time.Hour)
	store := sharedIPStore(activatedAt)
	store.Store.Lifecycle[0] = activation(continuedBanRef, activatedAt, int64(contributions), 0)
	store.Contribs[banBucket] = nil

	for index := range contributions {
		store.Contribs[banBucket] = append(store.Contribs[banBucket], counted(fmt.Sprintf("cc-%04d", index),
			activatedAt.Add(-time.Duration(contributions-index)*time.Second), banWindow, int64(index+1),
			fmt.Sprintf("user%04d@example.test", index), index == contributions-1))
	}

	for index := range claimants {
		for range 1 + index%3 {
			store.Volume = append(store.Volume, historytest.VolumeRow{CountedRecord: supporthistory.CountedRecord{
				At: activatedAt.Add(2 * time.Second), ClaimedUsername: fmt.Sprintf("claimant%03d@example.test", index)},
				Network: banNetwork, Kind: "ban_hit", HitSource: "redis"})
		}
	}

	return store
}

// banInnerPage runs one ban search by IP over the last three hours with an inner page.
func banInnerPage(service *supporthistory.Service, inner *supporthistory.BanInnerPageRequest) (*supporthistory.BanSearchResult, error) {
	return service.SearchBans(context.Background(), caller(definitions.ScopeHistoryRead), supporthistory.BanSearchRequest{
		SchemaVersion: "1", Target: supporthistory.BanTarget{IP: "198.51.100.17"},
		Filter: supporthistory.BanSearchFilter{From: banNow.Add(-3 * time.Hour), Until: banNow}, InnerPage: inner})
}

// innerList reads the listed keys and the continuation of one inner list of the only ban of a result.
type innerList func(t *testing.T, result *supporthistory.BanSearchResult) ([]string, *string)

// contributionList lists the contribution event ids of the only ban.
var contributionList = contributionListBy(func(item supporthistory.Contribution) string { return item.EventID })

// contributionListBy lists the contributions of the only ban by a key that identifies each item.
func contributionListBy(key func(supporthistory.Contribution) string) innerList {
	return func(t *testing.T, result *supporthistory.BanSearchResult) ([]string, *string) {
		t.Helper()

		return contributionKeys(t, result, key)
	}
}

// contributionKeys lists the keys of the contributions of the only ban and checks that the flag means a continuation.
func contributionKeys(t *testing.T, result *supporthistory.BanSearchResult, key func(supporthistory.Contribution) string) ([]string, *string) {
	t.Helper()

	if len(result.Bans) != 1 {
		t.Fatalf("bans = %+v, want the one ban", result.Bans)
	}

	contributions := result.Bans[0].Contributions
	if contributions.Truncated != (contributions.NextCursor != nil) {
		t.Fatalf("truncated = %v with cursor %v, want the flag to mean a continuation", contributions.Truncated, contributions.NextCursor)
	}

	keys := make([]string, 0, len(contributions.Items))
	for _, item := range contributions.Items {
		keys = append(keys, key(item))
	}

	return keys, contributions.NextCursor
}

// hitClaimantKeys lists the claimants of a hit summary and checks that the flag means a continuation.
func hitClaimantKeys(t *testing.T, hits supporthistory.HitSummary) ([]string, *string) {
	t.Helper()

	if hits.ClaimantsTruncated != (hits.ClaimantsNextCursor != nil) {
		t.Fatalf("claimants truncated = %v with cursor %v, want the flag to mean a continuation",
			hits.ClaimantsTruncated, hits.ClaimantsNextCursor)
	}

	keys := make([]string, 0, len(hits.Claimants))
	for _, claimant := range hits.Claimants {
		keys = append(keys, fmt.Sprintf("%d|%s|%s", claimant.Hits, stringValue(claimant.ClaimedUsername), stringValue(claimant.Account)))
	}

	return keys, hits.ClaimantsNextCursor
}

// claimantList lists the hit claimants of the only ban.
func claimantList(t *testing.T, result *supporthistory.BanSearchResult) ([]string, *string) {
	t.Helper()

	if len(result.Bans) != 1 {
		t.Fatalf("bans = %+v, want the one ban", result.Bans)
	}

	return hitClaimantKeys(t, result.Bans[0].Hits)
}

// orphanClaimantList lists the orphan hit claimants.
func orphanClaimantList(t *testing.T, result *supporthistory.BanSearchResult) ([]string, *string) {
	t.Helper()

	return hitClaimantKeys(t, result.OrphanHits)
}

// walkInner follows one inner list from the first search answer and returns every listed key in order.
func walkInner(t *testing.T, service *supporthistory.Service, list, banRef string, limit int, read innerList) []string {
	t.Helper()

	var inner *supporthistory.BanInnerPageRequest
	if limit > 0 {
		inner = &supporthistory.BanInnerPageRequest{BanRef: banRef, List: list, Limit: limit}
	}

	result, err := banInnerPage(service, inner)
	if err != nil {
		t.Fatalf("SearchBans() error = %v", err)
	}

	keys, next := read(t, result)
	seen := map[string]struct{}{}
	all := []string{}

	for pages := 0; ; pages++ {
		for _, key := range keys {
			if _, repeated := seen[key]; repeated {
				t.Fatalf("%s item %s listed twice", list, key)
			}

			seen[key] = struct{}{}
			all = append(all, key)
		}

		if next == nil {
			return all
		}

		if pages > 200 {
			t.Fatalf("%s paging does not terminate", list)
		}

		if result, err = banInnerPage(service, &supporthistory.BanInnerPageRequest{BanRef: banRef, List: list,
			Cursor: *next, Limit: limit}); err != nil {
			t.Fatalf("SearchBans(%s continuation) error = %v", list, err)
		}

		keys, next = read(t, result)
	}
}

// TestBanContributionsBeyondTheBoundAreReachable reproduces the silent contribution cut: a ban with more counted
// contributions than MaxContributions listed the first ones only.
func TestBanContributionsBeyondTheBoundAreReachable(t *testing.T) {
	total := supporthistory.MaxContributions + 23
	service := banService(t, continuedBanStore(total, 0))

	for _, limit := range []int{0, 61} {
		keys := walkInner(t, service, supporthistory.InnerListContributions, continuedBanRef, limit, contributionList)
		if len(keys) != total || keys[0] != "cc-0000" || keys[len(keys)-1] != fmt.Sprintf("cc-%04d", total-1) {
			t.Fatalf("limit %d reached %d contributions (%v ... %v), want all %d in order", limit, len(keys),
				keys[:min(1, len(keys))], keys[max(0, len(keys)-1):], total)
		}
	}
}

// TestLegacyContributionGroupsAcrossPagesAreReachable reproduces the lost-item defect of the contribution
// continuation: rows without event id that share window index, window counter, and instant straddle a page
// boundary, and a continuation after the shared position skipped the rest of the group.
func TestLegacyContributionGroupsAcrossPagesAreReachable(t *testing.T) {
	total := supporthistory.MaxContributions + 23
	store := continuedBanStore(total, 0)
	rows := store.Contribs[banBucket]

	for index := range rows {
		rows[index].RequestID = fmt.Sprintf("req-%04d", index)
	}

	group := rows[490 : 490+20]
	for index := range group {
		group[index].EventID, group[index].At, group[index].WindowCurrent = "", group[0].At, int64p(491)
	}

	service := banService(t, store)
	byRequest := contributionListBy(func(item supporthistory.Contribution) string { return item.RequestID })

	for _, limit := range []int{0, 7, 61} {
		if keys := walkInner(t, service, supporthistory.InnerListContributions, continuedBanRef, limit, byRequest); len(keys) != total {
			t.Fatalf("limit %d reached %d contributions, want all %d", limit, len(keys), total)
		}
	}
}

// TestBanClaimantsBeyondTheBoundAreReachable reproduces the silent claimant cut: a ban hit by more claimants than
// MaxClaimants listed the most frequent ones only.
func TestBanClaimantsBeyondTheBoundAreReachable(t *testing.T) {
	added := supporthistory.MaxClaimants + 13
	service := banService(t, continuedBanStore(3, added))

	for _, limit := range []int{0, 9} {
		keys := walkInner(t, service, supporthistory.InnerListClaimants, continuedBanRef, limit, claimantList)
		if len(keys) != added+1 {
			t.Fatalf("limit %d reached %d claimants, want all %d", limit, len(keys), added+1)
		}

		for index := 1; index < len(keys); index++ {
			var previous, current int

			_, _ = fmt.Sscanf(keys[index-1], "%d|", &previous)
			_, _ = fmt.Sscanf(keys[index], "%d|", &current)

			if current > previous {
				t.Fatalf("claimant %s follows %s, want most hits first across pages", keys[index], keys[index-1])
			}
		}
	}
}

// TestOrphanClaimantsBeyondTheBoundAreReachable pins the same continuation for the claimants of hits outside every
// listed ban.
func TestOrphanClaimantsBeyondTheBoundAreReachable(t *testing.T) {
	store := continuedBanStore(3, 0)
	added := supporthistory.MaxClaimants + 4

	for index := range added {
		store.Volume = append(store.Volume, historytest.VolumeRow{CountedRecord: supporthistory.CountedRecord{
			At: banNow.Add(-150 * time.Minute), ClaimedUsername: fmt.Sprintf("orphan%03d@example.test", index)},
			Network: banNetwork, Kind: "ban_hit", HitSource: "l1"})
	}

	keys := walkInner(t, banService(t, store), supporthistory.InnerListOrphanClaimants, "", 0, orphanClaimantList)
	if len(keys) != added+1 {
		t.Fatalf("reached %d orphan claimants, want all %d", len(keys), added+1)
	}
}

// TestBanInnerCursorsAreBoundAndLimitsValidated pins that an inner cursor only continues its own list of its own
// ban and query and that inner limits and arguments are validated.
func TestBanInnerCursorsAreBoundAndLimitsValidated(t *testing.T) {
	service := banService(t, continuedBanStore(supporthistory.MaxContributions+1, supporthistory.MaxClaimants+1))

	first, err := banInnerPage(service, nil)
	if err != nil || len(first.Bans) != 1 || first.Bans[0].Contributions.NextCursor == nil ||
		first.Bans[0].Hits.ClaimantsNextCursor == nil {
		t.Fatalf("SearchBans() = %+v, %v, want both continuations", first, err)
	}

	contributions, claimants := *first.Bans[0].Contributions.NextCursor, *first.Bans[0].Hits.ClaimantsNextCursor
	page := func(list, banRef, cursor string, limit int) error {
		_, pageErr := banInnerPage(service, &supporthistory.BanInnerPageRequest{BanRef: banRef, List: list, Cursor: cursor, Limit: limit})

		return pageErr
	}

	otherWindow := func() error {
		_, windowErr := service.SearchBans(context.Background(), caller(definitions.ScopeHistoryRead), supporthistory.BanSearchRequest{
			SchemaVersion: "1", Target: supporthistory.BanTarget{IP: "198.51.100.17"},
			Filter:    supporthistory.BanSearchFilter{From: banNow.Add(-4 * time.Hour), Until: banNow},
			InnerPage: &supporthistory.BanInnerPageRequest{BanRef: continuedBanRef, List: supporthistory.InnerListContributions, Cursor: contributions}})

		return windowErr
	}

	cursorCases := map[string]error{
		"claimant cursor as contributions": page(supporthistory.InnerListContributions, continuedBanRef, claimants, 0),
		"contribution cursor as claimants": page(supporthistory.InnerListClaimants, continuedBanRef, contributions, 0),
		"other ban":                        page(supporthistory.InnerListContributions, strings.Repeat("b", 32), contributions, 0),
		"other window":                     otherWindow(),
		"orphan list":                      page(supporthistory.InnerListOrphanClaimants, "", claimants, 0),
	}

	for name, caseErr := range cursorCases {
		if !hasCode(caseErr, supporthistory.CodeInvalidCursor) {
			t.Fatalf("%s: error = %v, want INVALID_CURSOR", name, caseErr)
		}
	}

	requestCases := map[string]error{
		"contributions above maximum": page(supporthistory.InnerListContributions, continuedBanRef, "", supporthistory.MaxContributions+1),
		"claimants above maximum":     page(supporthistory.InnerListClaimants, continuedBanRef, "", supporthistory.MaxClaimants+1),
		"negative limit":              page(supporthistory.InnerListClaimants, continuedBanRef, "", -1),
		"missing ban":                 page(supporthistory.InnerListContributions, "", "", 0),
		"malformed ban":               page(supporthistory.InnerListContributions, "ban-1", "", 0),
		"orphans name a ban":          page(supporthistory.InnerListOrphanClaimants, continuedBanRef, "", 0),
		"unknown list":                page("hits", continuedBanRef, "", 0),
	}

	for name, caseErr := range requestCases {
		if !hasCode(caseErr, supporthistory.CodeInvalidRequest) {
			t.Fatalf("%s: error = %v, want INVALID_REQUEST", name, caseErr)
		}
	}
}

// TestClaimantCursorRefusesAChangedAggregate pins that an offset claimant cursor never continues over changed counts,
// where offsets could repeat or skip claimants.
func TestClaimantCursorRefusesAChangedAggregate(t *testing.T) {
	store := continuedBanStore(3, supporthistory.MaxClaimants+1)
	service := banService(t, store)

	first, err := banInnerPage(service, nil)
	if err != nil || len(first.Bans) != 1 || first.Bans[0].Hits.ClaimantsNextCursor == nil {
		t.Fatalf("SearchBans() = %+v, %v, want a claimant continuation", first, err)
	}

	store.Volume = append(store.Volume, historytest.VolumeRow{CountedRecord: supporthistory.CountedRecord{
		At: first.Bans[0].Activation.At.Add(time.Second), ClaimedUsername: "late@example.test"},
		Network: banNetwork, Kind: "ban_hit", HitSource: "redis"})

	_, err = banInnerPage(service, &supporthistory.BanInnerPageRequest{BanRef: continuedBanRef,
		List: supporthistory.InnerListClaimants, Cursor: *first.Bans[0].Hits.ClaimantsNextCursor})
	if !hasCode(err, supporthistory.CodeInvalidCursor) {
		t.Fatalf("continuation over a changed aggregate error = %v, want INVALID_CURSOR", err)
	}
}

// growReplayedFlow appends one second-factor event stored replays times (same event id, as a retried export stores
// it) followed by after distinct events, so a source read can consist of duplicates only.
func growReplayedFlow(store *historytest.Store, flow string, replays int, after int) {
	at := scenarioBase.Add(-30 * time.Minute)
	event := func(id string, at time.Time) supporthistory.AuthEventRecord {
		return supporthistory.AuthEventRecord{At: at, EventID: id, EventType: "mfa.verification", FlowRef: flow,
			Account: "acc-anna", FactorRole: "second_factor", Method: "totp", Result: "invalid", Reason: "invalid_code",
			FlowEffect: "none", EventVersion: 1, FailLatched: true}
	}

	for range replays {
		store.Events = append(store.Events, event("replayed-event", at))
	}

	for index := range after {
		store.Events = append(store.Events, event(fmt.Sprintf("after-%04d", index), at.Add(time.Duration(index+1)*time.Millisecond)))
	}
}

// TestReplayedEventsNeverEndThePagingEarly reproduces the review defect: a continuation read that holds only
// replays of the event at the cursor position deduplicated to nothing, so the paging ended before the distinct events
// that follow. Every distinct event must be reachable exactly once, from the first page and from continuations.
func TestReplayedEventsNeverEndThePagingEarly(t *testing.T) {
	for _, tc := range []struct{ replays, after, limit int }{{300, 12, 1}, {300, 12, 0}, {450, 250, 7}, {202, 3, 200}} {
		store := fixtureStore(t)
		growReplayedFlow(store, continuedFlow, tc.replays, tc.after)

		service := newService(t, store)
		attempts, _ := attemptsByID(t, service, caller(definitions.ScopeHistoryRead))
		attempt := attempts["fl1."+continuedFlow]
		collector := &eventCollector{t: t, seen: map[string]struct{}{}, key: eventKey}

		first, err := service.GetAttempt(context.Background(), caller(definitions.ScopeHistoryRead),
			supporthistory.AttemptDetailRequest{SchemaVersion: "1", AttemptID: attempt.AttemptID,
				Around: attempt.StartedAt, EventsPage: &supporthistory.PageRequest{Limit: tc.limit}})
		if err != nil || first.Attempt == nil {
			t.Fatalf("GetAttempt = %+v, %v", first, err)
		}

		collector.add(first.Attempt.Events)
		walkEvents(t, service, collector, first.Attempt.EventsPage, attempt.Outcome, tc.limit)

		if want := continuedFlowEvents + 1 + tc.after; len(collector.seen) != want {
			t.Fatalf("%d replays, %d after, limit %d: reachable distinct events = %d, want %d", tc.replays, tc.after,
				tc.limit, len(collector.seen), want)
		}
	}
}
