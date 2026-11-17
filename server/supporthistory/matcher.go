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
	"slices"
	"strings"
)

// Provenance values of a subject match.
const (
	matchedByLogin           = "login"
	provenanceSupplied       = "supplied_account"
	provenanceCurrentMapping = "current_account_mapping"
	provenanceRecorded       = "recorded_at_event"
)

// subjectMatcher evaluates in Go the same identity predicate the store renders into SQL. It decides subject
// binding, matched_by labels, redaction, and already-served attempts.
type subjectMatcher struct {
	logins   map[string]struct{}
	accounts map[string]string
	filter   AttemptFilter
	match    SubjectMatch
}

// loginVariants returns the literal login and its lower-case form; other case variants are not matched.
func loginVariants(login string) []string {
	if login == "" {
		return nil
	}

	lower := strings.ToLower(login)
	if lower == login {
		return []string{login}
	}

	return []string{login, lower}
}

// newSubjectMatcher builds the matcher from login variants and accounts with their provenance.
func newSubjectMatcher(login string, accounts []ResolvedAccount, filter AttemptFilter) subjectMatcher {
	matcher := subjectMatcher{logins: map[string]struct{}{}, accounts: map[string]string{}, filter: filter}

	for _, variant := range loginVariants(login) {
		matcher.logins[variant] = struct{}{}
		matcher.match.Logins = append(matcher.match.Logins, variant)
	}

	for _, account := range accounts {
		if _, seen := matcher.accounts[account.Account]; seen || account.Account == "" {
			continue
		}

		matcher.accounts[account.Account] = account.Provenance
		matcher.match.Accounts = append(matcher.match.Accounts, account.Account)
	}

	slices.Sort(matcher.match.Accounts)

	return matcher
}

// subjectMatch returns the store predicate.
func (m subjectMatcher) subjectMatch() SubjectMatch {
	return m.match
}

// identityOfLogin reports whether a login row belongs to the subject and how.
func (m subjectMatcher) identityOfLogin(record LoginRecord) (bool, string) {
	if _, ok := m.logins[record.Username]; ok {
		return true, matchedByLogin
	}

	if provenance, ok := m.accounts[record.Account]; ok && record.Account != "" {
		return true, provenance
	}

	return false, ""
}

// identityOfEvent reports whether a step event belongs to the subject and how.
func (m subjectMatcher) identityOfEvent(record AuthEventRecord) (bool, string) {
	if provenance, ok := m.accounts[record.Account]; ok && record.Account != "" {
		return true, provenance
	}

	return false, ""
}

// anchorsLogin mirrors the store anchor predicate for login rows: identity plus every set filter.
func (m subjectMatcher) anchorsLogin(record LoginRecord) bool {
	if matched, _ := m.identityOfLogin(record); !matched {
		return false
	}

	filter := m.filter

	return (filter.ClientIP == "" || record.ClientIP == filter.ClientIP) &&
		(filter.Protocol == "" || record.Protocol == filter.Protocol) &&
		(filter.OIDCClientID == "" || record.OIDCClientID == filter.OIDCClientID) &&
		(filter.SAMLEntityID == "" || record.SAMLEntityID == filter.SAMLEntityID)
}

// anchorsEvent mirrors the store anchor predicate for step events: identity plus every set filter on the event
// columns. OIDC flows that reuse a session have no login row, so their events must anchor filtered searches too.
func (m subjectMatcher) anchorsEvent(record AuthEventRecord) bool {
	if matched, _ := m.identityOfEvent(record); !matched {
		return false
	}

	filter := m.filter

	return (filter.ClientIP == "" || record.ClientIP == filter.ClientIP) &&
		(filter.Protocol == "" || record.Protocol == filter.Protocol) &&
		(filter.OIDCClientID == "" || record.ClientID == filter.OIDCClientID) &&
		(filter.SAMLEntityID == "" || record.SAMLEntityID == filter.SAMLEntityID)
}
