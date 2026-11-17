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

import "context"

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

	accounts := make([]ResolvedAccount, 0, len(m.accounts)+1)
	for account, provenance := range m.accounts {
		accounts = append(accounts, ResolvedAccount{Account: account, Provenance: provenance})
	}

	for _, row := range rows {
		if _, ok := m.logins[row.Username]; ok && row.Account != "" {
			accounts = append(accounts, ResolvedAccount{Account: row.Account, Provenance: provenanceRecorded})
		}
	}

	return newSubjectMatcher(login, accounts, m.filter)
}
