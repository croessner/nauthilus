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
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
)

const (
	ctxSubject = "kunde@example.test"
	ctxAccount = "kunde-1"
	ctxIP      = "203.0.113.42"
	ctxHost    = "203.0.113.42/32"
	ctxNet     = "203.0.113.0/24"
	ctxBucket  = "bucket-ctx"
	ctxRequest = "req-subject"
	ctxWindow  = int64(7)
)

// ctxNow is the frozen query time of the ban-context tests; the rejected request lies one hour before it.
var ctxNow = time.Now().UTC().Truncate(time.Second)

// contributor is one counted increment of the ban-context bucket.
type contributor struct {
	known   *bool
	id      string
	claim   string
	account string
}

// ctxActivation builds an activation of the host ban that a different request wrote ten minutes before the subject.
func ctxActivation(id, network string, at time.Time, current int64) supporthistory.LifecycleRecord {
	expires := at.Add(time.Hour)

	return supporthistory.LifecycleRecord{At: at, ExpiresAt: &expires, EventID: id, Kind: "ban_activated",
		Network: network, Rule: "example_failed_logins", StoredRule: "example_failed_logins", BucketID: ctxBucket,
		RequestID: "req-activator", PeriodSeconds: 3600, BanTimeSeconds: 3600, FailedRequests: current + 1,
		WindowIndex: int64p(ctxWindow), WindowCurrent: int64p(current), WindowPrevious: int64p(0)}
}

// ctxStore builds the telephone-support scenario: a brute-force rejected subject request with its recorded hit on
// the host ban, the activation by another request, and the given counted contributors in order.
func ctxStore(rejectAt time.Time, contributors ...contributor) *historytest.BanStore {
	activatedAt := rejectAt.Add(-10 * time.Minute)
	store := &historytest.BanStore{Store: &historytest.Store{DeployName: "it"}, Contribs: map[string][]supporthistory.CountedRecord{}}
	store.Logins = []supporthistory.LoginRecord{{At: rejectAt, EventID: "login-rejected", Session: ctxRequest,
		Username: ctxSubject, ClientIP: ctxIP, Protocol: "imap", Operation: "authenticate", Outcome: "fail",
		OutcomeStage: "pre_auth", OutcomeMarker: "auth.outcome.brute_force_reject", ContractVersion: 1}}
	store.Store.Lifecycle = []supporthistory.LifecycleRecord{ctxActivation("ban-host", ctxHost, activatedAt, int64(len(contributors)))}

	for index, item := range contributors {
		store.Contribs[ctxBucket] = append(store.Contribs[ctxBucket], supporthistory.CountedRecord{
			At: activatedAt.Add(time.Duration(index-len(contributors)) * time.Second), EventID: item.id,
			RequestID: "req-" + item.id, WindowIndex: int64p(ctxWindow), WindowCurrent: int64p(int64(index + 1)),
			ClaimedUsername: item.claim, Account: item.account, AccountKnown: item.known, CountSource: "backend_failure",
			Protocol: "imap", ClientIP: ctxIP, Crossed: boolp(index == len(contributors)-1)})
	}

	store.Volume = []historytest.VolumeRow{hitRow("hit-subject", ctxRequest, ctxHost, rejectAt, "redis")}

	return store
}

// withRecordedSubject adds a successful subject row that recorded its account, the basis for "another account".
func withRecordedSubject(store *historytest.BanStore) *historytest.BanStore {
	store.Logins = append(store.Logins, supporthistory.LoginRecord{At: ctxNow.Add(-90 * time.Minute),
		EventID: "login-ok", Session: "req-ok", Username: ctxSubject, Account: ctxAccount, ClientIP: "192.0.2.1",
		Operation: "authenticate", Outcome: "ok", ContractVersion: 1})

	return store
}

// hitRow builds one recorded ban hit of a request.
func hitRow(id, request, network string, at time.Time, source string) historytest.VolumeRow {
	return historytest.VolumeRow{CountedRecord: supporthistory.CountedRecord{At: at, EventID: id, RequestID: request,
		ClaimedUsername: ctxSubject}, Network: network, Kind: "ban_hit", HitSource: source, Rule: "example_failed_logins"}
}

// ctxService builds a service over the store with host and /24 rule prefixes and an optional audit log.
func ctxService(t *testing.T, store *historytest.BanStore, audit supporthistory.AuditRecorder) *supporthistory.Service {
	t.Helper()

	options := supporthistory.Options{Attempts: store, Bans: store, Audit: audit, Now: func() time.Time { return ctxNow },
		Prefixes: func() []supporthistory.Prefix {
			return []supporthistory.Prefix{{Family: 4, Bits: 32}, {Family: 4, Bits: 24}}
		}}
	if store == nil {
		options.Bans = nil
	}

	service, err := supporthistory.NewService(options)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// ctxRequestFor returns the telephone-support search of the subject with the ban context.
func ctxRequestFor(mode string) supporthistory.AttemptSearchRequest {
	return supporthistory.AttemptSearchRequest{SchemaVersion: "1", Subject: supporthistory.Subject{Login: ctxSubject},
		Filter: supporthistory.AttemptSearchFilter{From: ctxNow.Add(-2 * time.Hour), Until: ctxNow, ClientIP: ctxIP},
		Page:   supporthistory.PageRequest{Limit: 5}, IncludeBanContext: true, ResponseMode: mode}
}

// onlyContext runs the search and returns its single ban context.
func onlyContext(t *testing.T, service *supporthistory.Service, scope, mode string) supporthistory.BanContext {
	t.Helper()

	result, err := service.SearchAttempts(context.Background(), caller(scope), ctxRequestFor(mode))
	if err != nil {
		t.Fatalf("SearchAttempts() error = %v", err)
	}

	if result.BanContexts == nil || len(*result.BanContexts) != 1 {
		t.Fatalf("ban contexts = %+v, want exactly one", result.BanContexts)
	}

	return (*result.BanContexts)[0]
}

// attributionCase is one attribution scenario: contributors and the expected code, state, counts, and accounts.
type attributionCase struct {
	contributors []contributor
	code         string
	others       string
	counts       string
	accounts     []string
	limitation   string
}

// attributionCases returns the attribution scenarios on shared network evidence.
func attributionCases() map[string]attributionCase {
	known, unknown := boolp(true), boolp(false)
	other := contributor{id: "o1", claim: "anderes-konto@example.test", account: "anderes-konto@example.test", known: known}
	own := contributor{id: "s1", claim: ctxSubject, account: ctxAccount, known: known}

	return map[string]attributionCase{
		"shared network, other account only": {[]contributor{other, {id: "o2", claim: "dritter@example.test",
			account: "dritter@example.test", known: known}}, "OTHER_ACCOUNTS_ONLY", "observed", "2/0/0/2/2/0/0", []string{
			"anderes-konto@example.test", "dritter@example.test"}, ""},
		"own account only": {[]contributor{own, {id: "s2", claim: ctxSubject, account: ctxAccount, known: known}},
			"SUBJECT_ACCOUNT", "none_observed", "2/2/0/0/0/0/0", []string{ctxAccount}, ""},
		"mixed accounts": {[]contributor{own, other}, "MULTIPLE_ACCOUNTS", "observed", "2/1/0/1/1/0/0",
			[]string{"anderes-konto@example.test", ctxAccount}, ""},
		"same login name without account": {[]contributor{{id: "n1", claim: ctxSubject}}, "NOT_SUFFICIENTLY_ATTRIBUTABLE",
			"unknown", "1/0/1/0/0/0/0", []string{}, "SUBJECT_CLAIMS_WITHOUT_RECORDED_ACCOUNT"},
		"same login name next to another account": {[]contributor{{id: "n2", claim: ctxSubject, known: unknown}, other},
			"NOT_SUFFICIENTLY_ATTRIBUTABLE", "observed", "2/0/1/1/1/0/0", []string{"anderes-konto@example.test"},
			"SUBJECT_CLAIMS_WITHOUT_RECORDED_ACCOUNT"},
		"own account next to a bare login claim": {[]contributor{own, {id: "c1", claim: ctxSubject}}, "SUBJECT_ACCOUNT",
			"unknown", "2/1/1/0/0/0/0", []string{ctxAccount}, "SUBJECT_CLAIMS_WITHOUT_RECORDED_ACCOUNT"},
		"alias of the same account": {[]contributor{own, {id: "a1", claim: "kunde", account: ctxAccount, known: known}},
			"SUBJECT_ACCOUNT", "none_observed", "2/2/0/0/0/0/0", []string{ctxAccount}, ""},
		"alias without historical resolution": {[]contributor{own, {id: "a2", claim: "kunde"}}, "SUBJECT_ACCOUNT", "unknown",
			"2/1/0/0/0/0/1", []string{ctxAccount}, "UNRESOLVED_CONTRIBUTOR_IDENTITIES"},
		"other account behind unresolved claim": {[]contributor{other, {id: "u1", claim: "kunde"}},
			"NOT_SUFFICIENTLY_ATTRIBUTABLE", "observed", "2/0/0/1/1/0/1", []string{"anderes-konto@example.test"},
			"UNRESOLVED_CONTRIBUTOR_IDENTITIES"},
		"typo without account is not another account": {[]contributor{{id: "t1", claim: "kunde@exmaple.test", known: unknown}},
			"NOT_SUFFICIENTLY_ATTRIBUTABLE", "observed", "1/0/0/0/0/1/0", []string{}, "CLAIMS_WITHOUT_ACCOUNT_PRESENT"},
	}
}

// TestBanContextAttribution pins the attribution codes on the same evidence for both projections.
func TestBanContextAttribution(t *testing.T) {
	for name, tc := range attributionCases() {
		t.Run(name, func(t *testing.T) {
			store := ctxStore(ctxNow.Add(-time.Hour), tc.contributors...)
			if name != "same login name without account" {
				withRecordedSubject(store)
			}

			detail := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryDetail, "compact")
			support := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryRead, "compact")

			for _, entry := range []supporthistory.BanContext{detail, support} {
				if entry.Status != "matched" || len(entry.Bans) != 1 || entry.Bans[0].SubjectRelation != "HIT_EXISTING_BAN" {
					t.Fatalf("context = %+v, want the recorded hit on the host ban", entry)
				}

				assertAttribution(t, entry.Bans[0], tc.code, tc.others, tc.counts, tc.limitation)
			}

			if accounts := detail.Bans[0].Attribution.ContributingAccounts; !slices.Equal(accounts, tc.accounts) {
				t.Fatalf("detail accounts = %v, want %v", accounts, tc.accounts)
			}

			if redacted := support.Bans[0].Attribution; redacted.ContributingAccounts != nil || !redacted.IdentitiesRedacted {
				t.Fatalf("support attribution = %+v, want hidden foreign identities", redacted)
			}

			if !slices.EqualFunc(detail.Bans[0].Attribution.SubjectContributions, support.Bans[0].Attribution.SubjectContributions,
				func(a, b supporthistory.SubjectContribution) bool { return a.EventID == b.EventID }) {
				t.Fatal("own contributions differ between projections")
			}
		})
	}
}

// assertAttribution compares the code, the other-contributor state, the counts, and an expected limitation.
func assertAttribution(t *testing.T, ban supporthistory.BanContextBan, code, others, counts, limitation string) {
	t.Helper()

	c := ban.Attribution.Counts
	got := fmt.Sprintf("%d/%d/%d/%d/%d/%d/%d", c.Listed, c.SubjectByAccount, c.SubjectByLoginClaim, c.OtherAccounts,
		c.DistinctOtherAccounts, c.NoAccount, c.Unresolved)

	if ban.Attribution.Code != code || ban.Attribution.OtherContributors != others || got != counts ||
		ban.Attribution.PersonAttribution != "NOT_ESTABLISHED" {
		t.Fatalf("attribution = %s/%s/%s/%s, want %s/%s/%s", ban.Attribution.Code, ban.Attribution.OtherContributors, got,
			ban.Attribution.PersonAttribution, code, others, counts)
	}

	if limitation != "" && !slices.Contains(ban.Evidence.Limitations, limitation) {
		t.Fatalf("limitations = %v, want %s", ban.Evidence.Limitations, limitation)
	}

	if subject := c.SubjectByAccount + c.SubjectByLoginClaim; int64(len(ban.Attribution.SubjectContributions)) != subject {
		t.Fatalf("subject contributions = %+v, want %d", ban.Attribution.SubjectContributions, subject)
	}
}

// linkCase is one linking scenario: a store mutation and the expected status, relations, and limitations.
type linkCase struct {
	mutate    func(*historytest.BanStore)
	status    string
	relations []string
	limits    []string
}

// linkCases returns the linking scenarios around a request rejected at rejectAt.
func linkCases(rejectAt time.Time) map[string]linkCase {
	return map[string]linkCase{
		"recorded hit": {func(*historytest.BanStore) {}, "matched", []string{"HIT_EXISTING_BAN"}, nil},
		"activation race": {func(s *historytest.BanStore) { s.Volume[0].HitSource = "activation_race" }, "matched",
			[]string{"ACTIVATION_RACE"}, nil},
		"activating request": {func(s *historytest.BanStore) {
			s.Volume, s.Store.Lifecycle[0].RequestID = nil, ctxRequest
		}, "matched", []string{"ACTIVATING_REQUEST"}, nil},
		"unconfirmed activation": {func(s *historytest.BanStore) {
			s.Volume = nil
			s.Store.Lifecycle[0].Kind, s.Store.Lifecycle[0].RequestID, s.Store.Lifecycle[0].ExpiresAt = "ban_activation_unconfirmed", ctxRequest, nil
		}, "matched", []string{"ACTIVATION_UNCONFIRMED"}, nil},
		"hit not recorded": {func(s *historytest.BanStore) { s.Volume = nil }, "overlap_only", []string{"INTERVAL_OVERLAP"},
			[]string{"BAN_HIT_NOT_RECORDED"}},
		"hits not readable": {func(s *historytest.BanStore) {
			s.Errors = map[string]error{"RequestHits": errors.New("boom")}
		}, "overlap_only", []string{"INTERVAL_OVERLAP"}, []string{"BAN_HITS_NOT_READ"}},
		"host and network ban both active": {func(s *historytest.BanStore) {
			s.Volume = nil
			s.Store.Lifecycle = append(s.Store.Lifecycle, ctxActivation("ban-net", ctxNet, rejectAt.Add(-5*time.Minute), 1))
		}, "overlap_only", []string{"INTERVAL_OVERLAP", "INTERVAL_OVERLAP"}, []string{"MULTIPLE_BANS_MATCH"}},
		"no recorded ban": {func(s *historytest.BanStore) { s.Volume, s.Store.Lifecycle = nil, nil }, "no_recorded_ban", nil, nil},
		"hit without lifecycle": {func(s *historytest.BanStore) { s.Store.Lifecycle = nil }, "no_recorded_ban", nil,
			[]string{"BAN_LIFECYCLE_NOT_RECORDED"}},
		"unconfirmed activation without end never overlaps": {func(s *historytest.BanStore) {
			s.Volume = nil
			s.Store.Lifecycle[0].Kind, s.Store.Lifecycle[0].ExpiresAt, s.Store.Lifecycle[0].BanTimeSeconds = "ban_activation_unconfirmed", nil, 0
			s.Store.Lifecycle[0].At = rejectAt.Add(-48 * time.Hour)
		}, "no_recorded_ban", nil, nil},
		"earlier ban released, later ban effective": {func(s *historytest.BanStore) {
			earlier := ctxActivation("ban-early", ctxHost, rejectAt.Add(-50*time.Minute), 1)
			s.Store.Lifecycle = append(s.Store.Lifecycle,
				earlier,
				supporthistory.LifecycleRecord{At: rejectAt.Add(-40 * time.Minute), EventID: "rel-early", Kind: "ban_released",
					Network: ctxHost, ReleaseSource: "admin_flush"},
				supporthistory.LifecycleRecord{At: rejectAt.Add(-39 * time.Minute), EventID: "reset-early", Kind: "counters_reset",
					Network: ctxHost, BucketID: ctxBucket})
		}, "matched", []string{"HIT_EXISTING_BAN"}, nil},
	}
}

// TestBanContextLinksTheEffectiveBan pins how a rejected request is linked: by the recorded hit, the activation it
// wrote, an unconfirmed activation, or only by interval; several bans are listed and none is picked.
func TestBanContextLinksTheEffectiveBan(t *testing.T) {
	rejectAt := ctxNow.Add(-time.Hour)
	other := banOther

	for name, tc := range linkCases(rejectAt) {
		t.Run(name, func(t *testing.T) {
			store := ctxStore(rejectAt, other)
			tc.mutate(store)

			entry := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryRead, "compact")

			var relations []string
			for _, ban := range entry.Bans {
				relations = append(relations, ban.SubjectRelation)
			}

			if entry.Status != tc.status || !slices.Equal(relations, tc.relations) {
				t.Fatalf("context = %s %v (%v), want %s %v", entry.Status, relations, entry.Limitations, tc.status, tc.relations)
			}

			for _, code := range tc.limits {
				if !slices.Contains(entry.Limitations, code) {
					t.Fatalf("limitations = %v, want %s", entry.Limitations, code)
				}
			}

			if name == "earlier ban released, later ban effective" && entry.Bans[0].BanRef != "ban-host" {
				t.Fatalf("linked ban = %s, want the ban effective at the attempt", entry.Bans[0].BanRef)
			}
		})
	}
}

// TestBanContextNeverPromotesLaterRowsOrHits pins that increments after the activation, increments after a reset,
// replays, and hits never become contributions, and that the subject's own hit is no contribution.
func TestBanContextNeverPromotesLaterRowsOrHits(t *testing.T) {
	rejectAt := ctxNow.Add(-time.Hour)
	store := withRecordedSubject(ctxStore(rejectAt, banOther))
	activatedAt := store.Store.Lifecycle[0].At
	store.Contribs[ctxBucket] = append(store.Contribs[ctxBucket],
		supporthistory.CountedRecord{At: activatedAt.Add(-time.Second), EventID: "o1", RequestID: "req-o1",
			WindowIndex: int64p(ctxWindow), WindowCurrent: int64p(1), ClaimedUsername: "x@example.test",
			Account: "x@example.test", AccountKnown: boolp(true)},
		supporthistory.CountedRecord{At: rejectAt, EventID: "after", RequestID: ctxRequest, WindowIndex: int64p(ctxWindow),
			WindowCurrent: int64p(2), ClaimedUsername: ctxSubject, Account: ctxAccount, AccountKnown: boolp(true),
			BanActive: boolp(true)},
		supporthistory.CountedRecord{At: rejectAt.Add(time.Minute), EventID: "restart", RequestID: "req-restart",
			WindowIndex: int64p(ctxWindow), WindowCurrent: int64p(1), ClaimedUsername: ctxSubject, Account: ctxAccount,
			AccountKnown: boolp(true)})
	store.Store.Lifecycle = append(store.Store.Lifecycle, supporthistory.LifecycleRecord{At: rejectAt.Add(30 * time.Second),
		EventID: "reset", Kind: "counters_reset", Network: ctxHost, BucketID: ctxBucket})
	store.Volume = append(store.Volume, hitRow("hit-subject", ctxRequest, ctxHost, rejectAt, "redis"),
		hitRow("hit-later", "req-later", ctxHost, rejectAt.Add(2*time.Minute), "l1"))

	ban := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryDetail, "detailed").Bans[0]

	// The reset after the activation compares clocks of different instances, so exclusivity stays unproven.
	assertAttribution(t, ban, "NOT_SUFFICIENTLY_ATTRIBUTABLE", "observed", "1/0/0/1/1/0/0",
		"RESET_BOUNDS_COMPARE_CLOCKS_OF_DIFFERENT_INSTANCES")

	if ban.Detail == nil || len(ban.Detail.Contributions.Items) != 1 || ban.Detail.Contributions.Status != "complete" {
		t.Fatalf("detail = %+v, want the one complete contribution", ban.Detail)
	}
}

// TestBanContextEvidenceLimits pins that partial retention, truncation, late data, and loss keep every exclusive
// statement out of the answer while present contributions stay visible.
func TestBanContextEvidenceLimits(t *testing.T) {
	other := banOther

	for name, tc := range map[string]struct {
		rejectAt     time.Time
		mutate       func(*historytest.BanStore)
		code         string
		completeness string
		limitation   string
	}{
		"28-day rule beyond 14-day retention": {ctxNow.Add(-time.Hour), func(s *historytest.BanStore) {
			s.Store.Lifecycle[0].PeriodSeconds = int64((28 * 24 * time.Hour).Seconds())
			s.Summaries = []supporthistory.WindowSummary{{WindowIndex: ctxWindow, Events: 1, MinCurrent: int64p(1), MaxCurrent: int64p(1)}}
		}, "NOT_SUFFICIENTLY_ATTRIBUTABLE", "aggregate_only", "RAW_CONTRIBUTIONS_PARTIALLY_RETAINED"},
		"lost increment": {ctxNow.Add(-time.Hour), func(s *historytest.BanStore) {
			current := int64(2)
			s.Store.Lifecycle[0].WindowCurrent = &current
		}, "NOT_SUFFICIENTLY_ATTRIBUTABLE", "loss_detected", ""},
		"late export": {ctxNow.Add(-time.Minute), func(s *historytest.BanStore) {
			s.Store.Lifecycle[0].At = ctxNow.Add(-3 * time.Minute)
		}, "NOT_SUFFICIENTLY_ATTRIBUTABLE", "complete", "LATE_EVENTS_POSSIBLE"},
		"truncated items": {ctxNow.Add(-time.Hour), func(s *historytest.BanStore) {
			at := s.Store.Lifecycle[0].At
			for index := range supporthistory.MaxContributions + 1 {
				s.Contribs[ctxBucket] = append(s.Contribs[ctxBucket], supporthistory.CountedRecord{
					At: at.Add(-time.Duration(index+2) * time.Second), EventID: fmt.Sprintf("bulk-%d", index),
					WindowIndex: int64p(ctxWindow), WindowCurrent: int64p(int64(index + 2)), ClaimedUsername: "x@example.test",
					Account: "x@example.test", AccountKnown: boolp(true)})
			}

			current := int64(supporthistory.MaxContributions + 2)
			s.Store.Lifecycle[0].WindowCurrent = &current
		}, "NOT_SUFFICIENTLY_ATTRIBUTABLE", "expired", "CONTRIBUTION_ITEMS_TRUNCATED"},
		"replayed rows are no loss": {ctxNow.Add(-time.Hour), func(s *historytest.BanStore) {
			s.Contribs[ctxBucket] = append(s.Contribs[ctxBucket], s.Contribs[ctxBucket][0])
		}, "OTHER_ACCOUNTS_ONLY", "complete", ""},
	} {
		t.Run(name, func(t *testing.T) {
			store := withRecordedSubject(ctxStore(tc.rejectAt, other))
			tc.mutate(store)

			ban := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryRead, "compact").Bans[0]
			if ban.Attribution.Code != tc.code || ban.Evidence.Completeness != tc.completeness ||
				ban.Attribution.OtherContributors != "observed" || ban.Attribution.Counts.OtherAccounts == 0 {
				t.Fatalf("ban = %s/%s/%s %v, want %s/%s with the present contribution visible", ban.Attribution.Code,
					ban.Evidence.Completeness, ban.Attribution.OtherContributors, ban.Evidence.Limitations, tc.code, tc.completeness)
			}

			if tc.limitation != "" && !slices.Contains(ban.Evidence.Limitations, tc.limitation) {
				t.Fatalf("limitations = %v, want %s", ban.Evidence.Limitations, tc.limitation)
			}
		})
	}
}

// TestBanContextKeepsProjectionAndAttributionConsistent pins that the ban detail and the attribution use the same
// one-hop subject match: an alias row of the subject's recorded account is the subject's in both.
func TestBanContextKeepsProjectionAndAttributionConsistent(t *testing.T) {
	store := withRecordedSubject(ctxStore(ctxNow.Add(-time.Hour),
		contributor{id: "own", claim: ctxSubject, account: ctxAccount, known: boolp(true)},
		contributor{id: "alias", claim: "kunde", account: ctxAccount, known: boolp(true)}))

	ban := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryDetail, "detailed").Bans[0]

	for _, item := range ban.Detail.Contributions.Items {
		if item.SubjectMatch == nil || !*item.SubjectMatch {
			t.Fatalf("detail item %s subject_match = %v, want true like the attribution", item.EventID, item.SubjectMatch)
		}
	}

	assertAttribution(t, ban, "SUBJECT_ACCOUNT", "none_observed", "2/2/0/0/0/0/0", "")
}

// banRejectAt is the rejection instant of the bound and gap scenarios.
var banRejectAt = ctxNow.Add(-time.Hour)

// banOther is one contribution of another recorded account.
var banOther = contributor{id: "o1", claim: "x@example.test", account: "x@example.test", known: boolp(true)}

// TestBanContextMissingRequestIDNeverBorrowsHits pins that a row without request id is linked by interval only and never borrows the hits of other requests.
func TestBanContextMissingRequestIDNeverBorrowsHits(t *testing.T) {
	store := ctxStore(banRejectAt, banOther)
	store.Logins[0].Session = ""
	store.Volume = []historytest.VolumeRow{hitRow("foreign-hit", "", ctxHost, banRejectAt, "redis")}

	entry := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryRead, "compact")
	if entry.Status != "overlap_only" || entry.Bans[0].SubjectRelation != "INTERVAL_OVERLAP" ||
		!slices.Contains(entry.Limitations, "REQUEST_ID_NOT_RECORDED") {
		t.Fatalf("context = %+v, want an overlap without borrowed hits", entry)
	}
}

// TestBanContextUnusableClientAddress pins that a row without usable client address is not evaluated and claims no brute-force read.
func TestBanContextUnusableClientAddress(t *testing.T) {
	store := ctxStore(banRejectAt, banOther)
	store.Logins[0].ClientIP = ""

	request := ctxRequestFor("compact")
	request.Filter.ClientIP = ""

	result := search(t, ctxService(t, store, nil), request)
	if entry := (*result.BanContexts)[0]; entry.Status != "not_evaluated" || !slices.Contains(entry.Limitations, "CLIENT_IP_NOT_USABLE") ||
		result.BanHistory != nil {
		t.Fatalf("context = %+v history = %+v, want not_evaluated without a claimed read", entry, result.BanHistory)
	}
}

// TestBanContextContributionsNotReadable pins that a failed contribution read keeps the ban visible without attribution.
func TestBanContextContributionsNotReadable(t *testing.T) {
	store := ctxStore(banRejectAt, banOther)
	store.Errors = map[string]error{"Contributions": errors.New("boom")}

	ban := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryRead, "compact").Bans[0]
	if ban.Evidence.Completeness != "not_read" || ban.Attribution.Code != "NOT_SUFFICIENTLY_ATTRIBUTABLE" {
		t.Fatalf("ban = %+v, want not_read and no attribution", ban)
	}
}

// TestBanContextRequestBound pins that requests beyond the per-page bound are reported as not evaluated.
func TestBanContextRequestBound(t *testing.T) {
	store := ctxStore(banRejectAt, banOther)
	for index := range 21 {
		row := store.Logins[0]
		row.Session, row.EventID, row.At = fmt.Sprintf("req-%02d", index), fmt.Sprintf("login-%02d", index),
			banRejectAt.Add(time.Duration(index)*time.Second)
		store.Logins = append(store.Logins, row)
	}

	request := ctxRequestFor("compact")
	request.Page.Limit = 25

	contexts := *search(t, ctxService(t, store, nil), request).BanContexts
	bounded := slices.IndexFunc(contexts, func(entry supporthistory.BanContext) bool {
		return slices.Contains(entry.Limitations, "BAN_CONTEXT_LIMIT_REACHED")
	})

	if len(contexts) != 22 || bounded != 20 || contexts[bounded].Status != "not_evaluated" {
		t.Fatalf("contexts = %d, first bounded = %d, want 22 entries with the 21st and later not evaluated", len(contexts), bounded)
	}
}

// TestBanContextStableOrder pins a stable ban order for equal activation times, so both transports render the same bytes.
func TestBanContextStableOrder(t *testing.T) {
	store := ctxStore(banRejectAt, banOther)
	store.Volume = nil
	store.Store.Lifecycle = append(store.Store.Lifecycle, ctxActivation("ban-net", ctxNet, store.Store.Lifecycle[0].At, 1))

	for range 5 {
		entry := onlyContext(t, ctxService(t, store, nil), definitions.ScopeHistoryRead, "compact")
		if len(entry.Bans) != 2 || entry.Bans[0].BanRef != "ban-net" || entry.Bans[1].BanRef != "ban-host" {
			t.Fatalf("bans = %+v, want ban-net before ban-host every time", entry.Bans)
		}
	}
}

// TestBanContextOwnContributionsBounded pins the bound of the listed own contributions while every one is still counted.
func TestBanContextOwnContributionsBounded(t *testing.T) {
	own := make([]contributor, 0, 51)
	for index := range 51 {
		own = append(own, contributor{id: fmt.Sprintf("s%02d", index), claim: ctxSubject, account: ctxAccount, known: boolp(true)})
	}

	attribution := onlyContext(t, ctxService(t, withRecordedSubject(ctxStore(banRejectAt, own...)), nil),
		definitions.ScopeHistoryRead, "compact").Bans[0].Attribution
	if len(attribution.SubjectContributions) != 50 || !attribution.SubjectContributionsTruncated ||
		attribution.Counts.SubjectByAccount != 51 {
		t.Fatalf("attribution = %d listed, truncated %v, counted %d", len(attribution.SubjectContributions),
			attribution.SubjectContributionsTruncated, attribution.Counts.SubjectByAccount)
	}
}

// TestBanContextFailuresNeverFailTheSearch pins that missing or failing ban evidence only marks the entry.
func TestBanContextFailuresNeverFailTheSearch(t *testing.T) {
	store := ctxStore(ctxNow.Add(-time.Hour))

	for name, tc := range map[string]struct {
		service *supporthistory.Service
		limit   string
	}{
		"no ban store": {func() *supporthistory.Service {
			service, err := supporthistory.NewService(supporthistory.Options{Attempts: store, Now: func() time.Time { return ctxNow }})
			if err != nil {
				t.Fatal(err)
			}

			return service
		}(), "BAN_HISTORY_NOT_CONFIGURED"},
		"lifecycle read fails": {func() *supporthistory.Service {
			failing := ctxStore(ctxNow.Add(-time.Hour))
			failing.Errors = map[string]error{"Lifecycle": errors.New("boom")}

			return ctxService(t, failing, nil)
		}(), "BAN_LIFECYCLE_NOT_READ"},
	} {
		t.Run(name, func(t *testing.T) {
			entry := onlyContext(t, tc.service, definitions.ScopeHistoryRead, "")
			if entry.Status != "not_evaluated" || !slices.Contains(entry.Limitations, tc.limit) {
				t.Fatalf("context = %+v, want not_evaluated with %s", entry, tc.limit)
			}
		})
	}
}

// TestAttemptSearchResponseModes pins the unchanged default, the independent mode and ban-context switches, the
// audit operation, and the refusal of unknown modes.
func TestAttemptSearchResponseModes(t *testing.T) {
	log := &auditLog{}
	service := ctxService(t, ctxStore(ctxNow.Add(-time.Hour)), log)
	plain := ctxRequestFor("")
	plain.IncludeBanContext = false

	if members := jsonMembers(t, search(t, service, plain)); members != "attempts,history,page,queried_at,result_basis,schema_version,subject_resolution" {
		t.Fatalf("default members = %s, want the unchanged answer", members)
	}

	compact := plain
	compact.ResponseMode = "compact"
	assertCompactAnswer(t, search(t, service, compact))

	detailed := search(t, service, ctxRequestFor("detailed"))
	if len(detailed.Attempts) != 1 || detailed.AttemptSummaries != nil || detailed.BanContexts == nil ||
		detailed.BanHistory == nil || (*detailed.BanContexts)[0].Bans[0].Detail == nil {
		t.Fatalf("detailed = %+v, want full attempts plus the ban context with its detail", detailed)
	}

	operations := make([]string, 0, len(log.entries))
	for _, entry := range log.entries {
		operations = append(operations, fmt.Sprintf("%s:%d", entry.Operation, entry.Results))
	}

	if !slices.Equal(operations, []string{"attempt_search:1", "attempt_search:1", "attempt_search_ban_context:1"}) {
		t.Fatalf("audit = %v, want the ban-context read audited separately and compact results counted", operations)
	}

	invalid := plain
	invalid.ResponseMode = "verbose"

	if _, err := service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), invalid); !hasCode(err, supporthistory.CodeInvalidRequest) {
		t.Fatalf("unknown mode error = %v, want INVALID_REQUEST", err)
	}
}

// search runs one support-role attempt search and fails the test on an error.
func search(t *testing.T, service *supporthistory.Service, request supporthistory.AttemptSearchRequest) *supporthistory.AttemptSearchResult {
	t.Helper()

	result, err := service.SearchAttempts(context.Background(), caller(definitions.ScopeHistoryRead), request)
	if err != nil {
		t.Fatalf("SearchAttempts() error = %v", err)
	}

	return result
}

// assertCompactAnswer checks a compact answer without ban context: one summary with the decisive reason and its
// references, no attempt objects, and the echoed mode.
func assertCompactAnswer(t *testing.T, result *supporthistory.AttemptSearchResult) {
	t.Helper()

	if len(result.Attempts) != 0 || result.AttemptSummaries == nil || len(*result.AttemptSummaries) != 1 ||
		result.BanContexts != nil || result.ResponseMode == nil || *result.ResponseMode != "compact" {
		t.Fatalf("compact = %+v, want one summary, no attempts, and no ban context", result)
	}

	summary := (*result.AttemptSummaries)[0]
	if summary.Reason == nil || *summary.Reason != supporthistory.CodeBruteForceRejected ||
		!slices.Equal(summary.RequestIDs, []string{ctxRequest}) || summary.Detail.AttemptID != summary.AttemptID {
		t.Fatalf("summary = %+v, want the brute-force reason and references", summary)
	}
}

// jsonMembers returns the sorted top-level member names of a value's JSON form.
func jsonMembers(t *testing.T, value any) string {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	var members map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &members); err != nil {
		t.Fatal(err)
	}

	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}

	slices.Sort(names)

	return strings.Join(names, ",")
}
