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

import "time"

// Response modes of an attempt search. The mode selects only the presentation; the caller's projection still comes
// from its verified scopes, so "detailed" never releases more than the caller may see.
const (
	// ResponseModeDetailed is the full attempt answer (the default).
	ResponseModeDetailed = "detailed"

	// ResponseModeCompact replaces the attempt objects by one summary per attempt.
	ResponseModeCompact = "compact"
)

// AttemptReference is the input of an attempt detail lookup for one attempt.
type AttemptReference struct {
	Around    time.Time `json:"around"`
	AttemptID string    `json:"attempt_id"`
}

// AttemptSummary is the compact form of one attempt: its outcome, the decisive code, and references.
type AttemptSummary struct {
	StartedAt      time.Time        `json:"started_at"`
	LastObservedAt time.Time        `json:"last_observed_at"`
	Reason         *string          `json:"reason"`
	Detail         AttemptReference `json:"detail"`
	FindingCodes   []string         `json:"finding_codes"`
	ClientIPs      []string         `json:"client_ips"`
	Protocols      []string         `json:"protocols"`
	RequestIDs     []string         `json:"request_ids"`
	KnownGaps      []string         `json:"known_gaps"`
	AttemptID      string           `json:"attempt_id"`
	Kind           string           `json:"kind"`
	Outcome        string           `json:"outcome"`
	OutcomeBasis   string           `json:"outcome_basis"`
	Progress       string           `json:"progress"`
	FinalObserved  bool             `json:"final_outcome_observed"`
	Truncated      bool             `json:"events_truncated"`
	Withheld       bool             `json:"events_withheld"`
}

// SubjectContribution is one counted increment recorded under the subject (its own data, both projections).
type SubjectContribution struct {
	At            time.Time `json:"at"`
	WindowIndex   *int64    `json:"window_index"`
	WindowCurrent *int64    `json:"window_current"`
	BanActive     *bool     `json:"ban_active"`
	AttemptID     *string   `json:"attempt_id"`
	EventID       string    `json:"event_id"`
	RequestID     string    `json:"request_id"`
	CountSource   string    `json:"count_source"`
	Protocol      string    `json:"protocol"`
	MatchedBy     string    `json:"matched_by"`
}

// AttributionCounts classifies the listed contributions of one ban by whose account recorded them.
type AttributionCounts struct {
	Listed                int64 `json:"listed"`
	SubjectByAccount      int64 `json:"subject_by_account"`
	SubjectByLoginClaim   int64 `json:"subject_by_login_claim"`
	OtherAccounts         int64 `json:"other_accounts"`
	DistinctOtherAccounts int64 `json:"distinct_other_accounts"`
	NoAccount             int64 `json:"no_account"`
	Unresolved            int64 `json:"unresolved"`
	CountedWhileBanned    int64 `json:"counted_while_banned"`
}

// BanAttribution states under which accounts the contributions of one ban were recorded. It never names a person:
// a claim of the subject's login can come from anybody, and the activating request is not a culprit.
type BanAttribution struct {
	ContributingAccounts          []string              `json:"contributing_accounts"`
	SubjectContributions          []SubjectContribution `json:"subject_contributions"`
	Counts                        AttributionCounts     `json:"counts"`
	Code                          string                `json:"code"`
	OtherContributors             string                `json:"other_contributors"`
	PersonAttribution             string                `json:"person_attribution"`
	IdentitiesRedacted            bool                  `json:"identities_redacted"`
	SubjectContributionsTruncated bool                  `json:"subject_contributions_truncated"`
}

// BanEvidence states how complete the contribution evidence of one ban is and what limits it.
type BanEvidence struct {
	Completeness string   `json:"completeness"`
	Limitations  []string `json:"limitations"`
}

// BanHistoryReference is the input of a bruteforce_history call that explains the same ban instance.
type BanHistoryReference struct {
	From    time.Time `json:"from"`
	Until   time.Time `json:"until"`
	BanRef  string    `json:"ban_ref"`
	Network string    `json:"network"`
}

// BanContextBan is one ban instance linked to a rejected request.
type BanContextBan struct {
	ActivatedAt      time.Time           `json:"activated_at"`
	PlannedEnd       *time.Time          `json:"planned_end"`
	Detail           *Ban                `json:"detail"`
	Attribution      BanAttribution      `json:"attribution"`
	Evidence         BanEvidence         `json:"evidence"`
	End              BanEnd              `json:"end"`
	History          BanHistoryReference `json:"ban_history"`
	BanRef           string              `json:"ban_ref"`
	Network          string              `json:"network"`
	Scope            string              `json:"scope"`
	Rule             string              `json:"rule"`
	ActivationReason string              `json:"activation_reason"`
	SubjectRelation  string              `json:"subject_relation"`
}

// BanContext links one subject request rejected by brute-force protection to the ban instances recorded for it.
type BanContext struct {
	At          time.Time       `json:"at"`
	ClientIP    *string         `json:"client_ip"`
	Bans        []BanContextBan `json:"bans"`
	Limitations []string        `json:"limitations"`
	AttemptID   string          `json:"attempt_id"`
	RequestID   string          `json:"request_id"`
	Reason      string          `json:"reason"`
	Status      string          `json:"status"`
}
