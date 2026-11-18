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

package supporthistory

import (
	"context"
	"iter"
	"maps"
	"slices"
)

// Current mapping states of a subject resolution.
const (
	mappingResolved     = "resolved"
	mappingUnmapped     = "unmapped"
	mappingUnavailable  = "unavailable"
	mappingNotAttempted = "not_attempted"

	maxRecordedAccounts = 20
)

// subjectResolver turns a subject into match values. It runs only after authorization, inside the gate and the
// time budget, because reading mappings is data access.
type subjectResolver struct {
	identity IdentityResolver
	attempts AttemptStore
}

// resolve combines the supplied account, the current stored mapping, and accounts recorded at event time on rows
// of the literal login (one hop). Today's mapping cannot prove a historical alias; each match keeps its provenance.
func (r subjectResolver) resolve(ctx context.Context, subject Subject, window Window, recorded bool) (SubjectResolution, []ResolvedAccount, error) {
	resolution := SubjectResolution{SuppliedLogin: optional(subject.Login), SuppliedAccount: optional(subject.Account),
		CurrentMapping: mappingNotAttempted, Accounts: []ResolvedAccount{}}

	var accounts []ResolvedAccount

	add := func(account, provenance string) {
		for _, known := range accounts {
			if known.Account == account {
				return
			}
		}

		accounts = append(accounts, ResolvedAccount{Account: account, Provenance: provenance})
	}

	if subject.Account != "" {
		add(subject.Account, provenanceSupplied)
	}

	if subject.Login != "" {
		resolution.CurrentMapping = r.currentMapping(ctx, subject.Login, add)

		if recorded {
			found, err := r.attempts.RecordedAccounts(ctx, AccountQuery{From: window.From, Until: window.Until,
				Logins: loginVariants(subject.Login), Limit: maxRecordedAccounts})
			if err != nil {
				return resolution, nil, err
			}

			for _, account := range found {
				add(account, provenanceRecorded)
			}
		}
	}

	resolution.Accounts = append(resolution.Accounts, accounts...)

	return resolution, accounts, nil
}

// currentMapping reads today's stored login mapping without authenticating.
func (r subjectResolver) currentMapping(ctx context.Context, login string, add func(string, string)) string {
	if r.identity == nil {
		return mappingUnavailable
	}

	mappings := r.identity.ResolveLogins(ctx, []string{login})
	if len(mappings) != 1 || mappings[0].Err != nil {
		return mappingUnavailable
	}

	if len(mappings[0].Accounts) == 0 {
		return mappingUnmapped
	}

	for _, account := range mappings[0].Accounts {
		add(account, provenanceCurrentMapping)
	}

	return mappingResolved
}

// withRecordedAccounts adds accounts recorded on rows of the literal login of one attempt (detail lookups).
func (m subjectMatcher) withRecordedAccounts(login string, rows []LoginRecord) subjectMatcher {
	if login == "" {
		return m
	}

	return m.withClaimedAccounts(func(yield func(string, string) bool) {
		for _, row := range rows {
			if !yield(row.Username, row.Account) {
				return
			}
		}
	})
}

// withCountedAccounts adds accounts recorded on counted brute-force rows that claim a subject login, so aliases of
// the same account match in ban projections and attributions alike.
func (m subjectMatcher) withCountedAccounts(items []CountedRecord) subjectMatcher {
	return m.withClaimedAccounts(func(yield func(string, string) bool) {
		for _, item := range items {
			if !yield(item.ClaimedUsername, item.Account) {
				return
			}
		}
	})
}

// withClaimedAccounts returns a copy of the matcher that also matches every account recorded at event time with a
// claim of one of the subject's login variants (one hop); today's mapping is never consulted.
func (m subjectMatcher) withClaimedAccounts(claims iter.Seq2[string, string]) subjectMatcher {
	extended := subjectMatcher{logins: m.logins, accounts: maps.Clone(m.accounts), filter: m.filter,
		match: SubjectMatch{Logins: m.match.Logins, Accounts: slices.Clone(m.match.Accounts)}}

	for name, account := range claims {
		if _, claimed := m.logins[name]; !claimed || account == "" {
			continue
		}

		if _, known := extended.accounts[account]; !known {
			extended.accounts[account] = provenanceRecorded
			extended.match.Accounts = append(extended.match.Accounts, account)
		}
	}

	slices.Sort(extended.match.Accounts)

	return extended
}
