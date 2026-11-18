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
	"time"
)

// Attribution codes of one ban (stable API values).
const (
	// AttributionSubjectAccount means contributions were recorded under the requested account; it is exclusive only
	// together with other_contributors "none_observed".
	AttributionSubjectAccount = "SUBJECT_ACCOUNT"

	// AttributionMultipleAccounts means contributions were recorded under the requested and at least one other account.
	AttributionMultipleAccounts = "MULTIPLE_ACCOUNTS"

	// AttributionOtherAccountsOnly means every listed contribution was recorded under another account and the
	// evidence is complete enough to say so.
	AttributionOtherAccountsOnly = "OTHER_ACCOUNTS_ONLY"

	// AttributionInsufficient means the evidence does not support one of the other codes.
	AttributionInsufficient = "NOT_SUFFICIENTLY_ATTRIBUTABLE"
)

// Other-contributor states and the fixed person attribution.
const (
	othersObserved     = "observed"
	othersNoneObserved = "none_observed"
	othersUnknown      = "unknown"
	personNotEstablish = "NOT_ESTABLISHED"
	matchedByAccount   = "recorded_account"
	matchedByClaim     = "login_claim"

	// maxSubjectContributions bounds the listed own contributions of the subject per ban.
	maxSubjectContributions = 50
)

// Attribution limitation codes.
const (
	limitUnresolvedIdentities = "UNRESOLVED_CONTRIBUTOR_IDENTITIES"
	limitNoAccountClaims      = "CLAIMS_WITHOUT_ACCOUNT_PRESENT"
	limitNoAccountBasis       = "NO_RECORDED_SUBJECT_ACCOUNT_TO_COMPARE"
	limitCountedAfter         = "COUNTED_AFTER_ACTIVATION_TIME"
	limitLateEvents           = "LATE_EVENTS_POSSIBLE"
	limitEndEstimated         = "BAN_END_ESTIMATED_FROM_BAN_TIME"
	limitClaimOnly            = "SUBJECT_CLAIMS_WITHOUT_RECORDED_ACCOUNT"
)

// contributorClass is the account class of one counted row relative to the subject.
type contributorClass uint8

const (
	classUnresolved contributorClass = iota
	classSubjectAccount
	classSubjectClaim
	classOtherAccount
	classNoAccount
)

// contributorClassifier decides under whose account a counted row was recorded. It uses the same one-hop matcher as
// the ban projection (subjectMatcher.withCountedAccounts), so aliases of the same account never count as other
// accounts. Only accounts recorded at event time or supplied by the caller can prove "another account"; today's
// mapping can confirm the subject but never refute it.
type contributorClassifier struct {
	matcher subjectMatcher
	trusted bool
}

// newContributorClassifier builds the classifier from the search matcher extended by the counted rows.
func newContributorClassifier(matcher subjectMatcher, items []CountedRecord) contributorClassifier {
	classifier := contributorClassifier{matcher: matcher.withCountedAccounts(items)}

	for _, provenance := range classifier.matcher.accounts {
		classifier.trusted = classifier.trusted || provenance == provenanceSupplied || provenance == provenanceRecorded
	}

	return classifier
}

// classify returns the account class of one counted row.
func (c contributorClassifier) classify(item CountedRecord) contributorClass {
	_, ownAccount := c.matcher.accounts[item.Account]
	_, ownClaim := c.matcher.logins[item.ClaimedUsername]

	switch {
	case item.Account != "" && ownAccount:
		return classSubjectAccount
	case ownClaim:
		return classSubjectClaim
	case item.Account != "" && c.trusted:
		return classOtherAccount
	case item.Account == "" && item.AccountKnown != nil && !*item.AccountKnown:
		return classNoAccount
	default:
		return classUnresolved
	}
}

// attributionInput is everything one ban attribution depends on; attempts maps the projected request ids of the page
// to their attempt ids.
type attributionInput struct {
	activatedAt time.Time
	queriedAt   time.Time
	attempts    map[string]string
	matcher     subjectMatcher
	items       []CountedRecord
	ban         Ban
	projection  Projection
	estimated   bool
}

// attribute classifies the listed contributions of one ban and derives the attribution code, the other-contributor
// state, and the evidence block. Every code is computed on unredacted rows; only the projection decides what is shown.
func attribute(input attributionInput) (BanAttribution, BanEvidence) {
	items := input.items
	classifier := newContributorClassifier(input.matcher, items)
	attribution := BanAttribution{SubjectContributions: []SubjectContribution{}, PersonAttribution: personNotEstablish,
		IdentitiesRedacted: input.projection != ProjectionDetail}
	others, accounts := map[string]struct{}{}, map[string]struct{}{}
	countedAfter := false

	for _, item := range items {
		class := classifier.classify(item)
		attribution.Counts.add(class, item)
		countedAfter = countedAfter || item.At.After(input.activatedAt)

		if item.Account != "" {
			accounts[item.Account] = struct{}{}
		}

		if class == classOtherAccount {
			others[item.Account] = struct{}{}
		}

		if class == classSubjectAccount || class == classSubjectClaim {
			attribution.addSubjectContribution(item, class, input.attempts)
		}
	}

	attribution.Counts.DistinctOtherAccounts = int64(len(others))
	evidence := banEvidence(input, attribution.Counts, classifier.trusted, countedAfter)
	attribution.Code, attribution.OtherContributors = attributionCode(attribution.Counts, sufficient(evidence))

	if input.projection == ProjectionDetail {
		attribution.ContributingAccounts = sortedKeys(accounts)
	}

	return attribution, evidence
}

// add counts one classified row.
func (c *AttributionCounts) add(class contributorClass, item CountedRecord) {
	c.Listed++

	if item.BanActive != nil && *item.BanActive {
		c.CountedWhileBanned++
	}

	switch class {
	case classSubjectAccount:
		c.SubjectByAccount++
	case classSubjectClaim:
		c.SubjectByLoginClaim++
	case classOtherAccount:
		c.OtherAccounts++
	case classNoAccount:
		c.NoAccount++
	default:
		c.Unresolved++
	}
}

// addSubjectContribution lists one own contribution of the subject up to the bound.
func (a *BanAttribution) addSubjectContribution(item CountedRecord, class contributorClass, attempts map[string]string) {
	if len(a.SubjectContributions) >= maxSubjectContributions {
		a.SubjectContributionsTruncated = true

		return
	}

	matched := matchedByAccount
	if class == classSubjectClaim {
		matched = matchedByClaim
	}

	contribution := SubjectContribution{At: item.At.UTC(), WindowIndex: item.WindowIndex, WindowCurrent: item.WindowCurrent,
		BanActive: item.BanActive, EventID: item.EventID, RequestID: recordedText(item.RequestID),
		CountSource: item.CountSource, Protocol: item.Protocol, MatchedBy: matched}

	if attemptID, ok := attempts[contribution.RequestID]; ok {
		contribution.AttemptID = &attemptID
	}

	a.SubjectContributions = append(a.SubjectContributions, contribution)
}

// banEvidence collects the completeness and every limitation of one ban's contribution evidence.
func banEvidence(input attributionInput, counts AttributionCounts, trusted, countedAfter bool) BanEvidence {
	evidence := BanEvidence{Completeness: input.ban.Contributions.Status, Limitations: []string{}}
	if slices.Contains(input.ban.Unknowns, unknownContributions) {
		evidence.Completeness = evidenceNotRead
	}

	add := func(condition bool, code string) {
		if condition && !slices.Contains(evidence.Limitations, code) {
			evidence.Limitations = append(evidence.Limitations, code)
		}
	}

	for _, code := range append(append([]string{}, input.ban.Unknowns...), input.ban.Contributions.Caveats...) {
		add(true, code)
	}

	add(counts.Unresolved > 0, limitUnresolvedIdentities)
	add(counts.NoAccount > 0, limitNoAccountClaims)
	add(counts.SubjectByLoginClaim > 0, limitClaimOnly)
	add(!trusted && counts.Listed > 0, limitNoAccountBasis)
	add(countedAfter, limitCountedAfter)
	add(input.queriedAt.Sub(input.activatedAt) < lateEventHorizon, limitLateEvents)
	add(input.estimated, limitEndEstimated)

	return evidence
}

// blockingLimitations are the limitations that keep a ban from proving the absence of other contributors.
var blockingLimitations = []string{unknownContributions, unknownLifecycleTrimmed, caveatItemsTruncated,
	caveatPartiallyRetained, caveatResetSkew, limitUnresolvedIdentities, limitNoAccountClaims, limitNoAccountBasis,
	limitClaimOnly, limitCountedAfter, limitLateEvents}

// sufficient reports whether the evidence is complete enough to state that no other contributor exists.
func sufficient(evidence BanEvidence) bool {
	return evidence.Completeness == statusComplete && !slices.ContainsFunc(evidence.Limitations, func(code string) bool {
		return slices.Contains(blockingLimitations, code)
	})
}

// attributionCode derives the code and the other-contributor state. Only a recorded subject account makes a
// contribution "under the requested account"; a bare login claim cannot tell the customer from anybody typing the
// same name. A claim without account is not another account either (it is often the customer's own typo), so it never
// yields MULTIPLE_ACCOUNTS or OTHER_ACCOUNTS_ONLY.
func attributionCode(counts AttributionCounts, sufficient bool) (string, string) {
	subject := counts.SubjectByAccount

	others := othersUnknown

	switch {
	case counts.OtherAccounts > 0 || counts.NoAccount > 0:
		others = othersObserved
	case counts.Unresolved == 0 && sufficient:
		others = othersNoneObserved
	}

	switch {
	case subject > 0 && counts.OtherAccounts > 0:
		return AttributionMultipleAccounts, others
	case subject > 0:
		return AttributionSubjectAccount, others
	case counts.OtherAccounts > 0 && counts.SubjectByLoginClaim == 0 && sufficient:
		return AttributionOtherAccountsOnly, others
	default:
		return AttributionInsufficient, others
	}
}

// countedEventID returns the idempotency key of a counted row.
func countedEventID(record CountedRecord) string {
	return record.EventID
}

// sortedKeys returns the keys of a set in a stable order.
func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, recordedText(key))
	}

	slices.Sort(keys)

	return keys
}
