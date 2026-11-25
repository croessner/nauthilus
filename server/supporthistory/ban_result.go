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

// BanTarget selects the address of a ban search: exactly one of IP or Network.
type BanTarget struct {
	IP      string `json:"ip,omitempty"`
	Network string `json:"network,omitempty"`
}

// BanSearchFilter combines the window with an optional ban reference.
type BanSearchFilter struct {
	From   time.Time `json:"from"`
	Until  time.Time `json:"until"`
	BanRef string    `json:"ban_ref,omitempty"`
}

// BanSearchRequest explains recorded bans of one IP or network. Subject optionally names the person to attribute.
type BanSearchRequest struct {
	Subject        *Subject             `json:"subject,omitempty"`
	InnerPage      *BanInnerPageRequest `json:"inner_page,omitempty"`
	Target         BanTarget            `json:"target"`
	Filter         BanSearchFilter      `json:"filter"`
	Page           PageRequest          `json:"page"`
	SchemaVersion  string               `json:"schema_version"`
	AuditReference string               `json:"audit_reference,omitempty"`
}

// Inner lists a ban search can page.
const (
	// InnerListContributions pages the counted contributions of one ban (default and maximum MaxContributions).
	InnerListContributions = "contributions"

	// InnerListClaimants pages the hit claimants of one ban (default and maximum MaxClaimants).
	InnerListClaimants = "claimants"

	// InnerListOrphanClaimants pages the claimants of hits outside every ban instance (default and maximum
	// MaxClaimants); it names no ban.
	InnerListOrphanClaimants = "orphan_claimants"
)

// BanInnerPageRequest selects one page of an inner list. For contributions and claimants, BanRef names the ban and
// the answer lists only that ban; Cursor is the contributions.next_cursor or hits.claimants_next_cursor of an earlier
// answer to the same target and window. Orphan claimants name no ban and continue orphan_hits.claimants_next_cursor.
// An inner page is never combined with page.cursor.
type BanInnerPageRequest struct {
	BanRef string `json:"ban_ref,omitempty"`
	List   string `json:"list"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// ResolvedTarget echoes the canonical target and the computed candidate networks.
type ResolvedTarget struct {
	IP                *string  `json:"ip"`
	CandidateNetworks []string `json:"candidate_networks"`
}

// Activation is the recorded start of one ban instance. The activating request is never a culprit.
type Activation struct {
	At                time.Time  `json:"at"`
	BucketID          *string    `json:"bucket_id"`
	WindowIndex       *int64     `json:"window_index"`
	WindowCurrent     *int64     `json:"window_current"`
	WindowPrevious    *int64     `json:"window_previous"`
	Total             *float64   `json:"total"`
	EffectiveLimit    *float64   `json:"effective_limit"`
	PlannedEnd        *time.Time `json:"planned_end"`
	Kind              string     `json:"kind"`
	Rule              string     `json:"rule"`
	StoredRule        string     `json:"stored_rule"`
	RuleFingerprint   string     `json:"rule_fingerprint"`
	Instance          string     `json:"instance"`
	ActivatingRequest string     `json:"activating_request"`
	PeriodSeconds     int64      `json:"period_seconds"`
	BanTimeSeconds    int64      `json:"ban_time_seconds"`
	FailedRequests    int64      `json:"failed_requests"`
}

// BanEnd states how a ban instance ended, as far as it was recorded.
type BanEnd struct {
	At            *time.Time `json:"at"`
	ReleaseSource *string    `json:"release_source"`
	Reason        string     `json:"reason"`
}

// WindowStatus is the completeness of the contributions of one bucket window.
type WindowStatus struct {
	Expected               *int64 `json:"expected"`
	Present                *int64 `json:"present"`
	Window                 string `json:"window"`
	Status                 string `json:"status"`
	Evidence               string `json:"evidence"`
	WindowIndex            int64  `json:"window_index"`
	CountsAreUpperBounds   bool   `json:"counts_are_upper_bounds"`
	SummaryCheckUnreliable bool   `json:"summary_check_unreliable"`
}

// Contribution is one counted increment that fed the activation.
type Contribution struct {
	At              time.Time `json:"at"`
	WindowIndex     *int64    `json:"window_index"`
	WindowCurrent   *int64    `json:"window_current"`
	Crossed         *bool     `json:"crossed"`
	AccountKnown    *bool     `json:"account_known"`
	ClaimedUsername *string   `json:"claimed_username"`
	Account         *string   `json:"account"`
	ClientIP        *string   `json:"client_ip"`
	SubjectMatch    *bool     `json:"subject_match"`
	EventID         string    `json:"event_id"`
	RequestID       string    `json:"request_id"`
	CountSource     string    `json:"count_source"`
	Protocol        string    `json:"protocol"`
}

// CrossingCandidate is the latest crossed increment before activation; a heuristic, never a unique cause.
type CrossingCandidate struct {
	At            time.Time `json:"at"`
	WindowCurrent *int64    `json:"window_current"`
	EventID       string    `json:"event_id"`
	Basis         string    `json:"basis"`
}

// Contributions is the attributed counted evidence of one activation.
type Contributions struct {
	CrossingCandidate    *CrossingCandidate `json:"crossing_candidate"`
	DistinctClaimedNames *int64             `json:"distinct_claimed_names"`
	Windows              []WindowStatus     `json:"windows"`
	Items                []Contribution     `json:"items"`
	// NextCursor continues Items through inner_page {ban_ref, list: contributions, cursor}; Truncated is true exactly
	// when it is set.
	NextCursor *string  `json:"next_cursor,omitempty"`
	Caveats    []string `json:"caveats"`
	Status     string   `json:"status"`
	Truncated  bool     `json:"truncated"`
}

// Claimant is one claimed login name behind a network with its hit count.
type Claimant struct {
	ClaimedUsername *string `json:"claimed_username"`
	Account         *string `json:"account"`
	Hits            int64   `json:"hits"`
}

// HitSummary aggregates requests rejected by an existing ban.
type HitSummary struct {
	BySource             map[string]int64 `json:"by_source"`
	DistinctClaimedNames *int64           `json:"distinct_claimed_names"`
	SubjectHits          *int64           `json:"subject_hits"`
	Claimants            []Claimant       `json:"claimants"`
	Evidence             string           `json:"evidence"`
	Count                int64            `json:"count"`
	CountIsUpperBound    bool             `json:"count_is_upper_bound"`
	IntervalApproximate  bool             `json:"interval_approximate"`

	// ClaimantsNextCursor continues Claimants through inner_page {ban_ref, list: claimants, cursor}, or list
	// orphan_claimants for orphan hits. Answers that are no ban search (ban contexts) never carry it; their
	// ban_history reference reads the ban whose answer does.
	ClaimantsNextCursor *string `json:"claimants_next_cursor,omitempty"`

	// ClaimantsTruncated tells that more claimants than listed hit the ban; the most frequent are listed first.
	ClaimantsTruncated bool `json:"claimants_truncated"`
}

// Ban is one recorded ban instance with its attributed evidence.
type Ban struct {
	Activation    Activation    `json:"activation"`
	End           BanEnd        `json:"end"`
	Contributions Contributions `json:"contributions"`
	Hits          HitSummary    `json:"hits"`
	Unknowns      []string      `json:"unknowns"`
	BanRef        string        `json:"ban_ref"`
	Network       string        `json:"network"`
}

// LifecycleEvent is one recorded unconfirmed activation, release, or counter reset.
type LifecycleEvent struct {
	At               time.Time `json:"at"`
	BucketID         *string   `json:"bucket_id"`
	ReleaseSource    *string   `json:"release_source"`
	OperatorClientID *string   `json:"operator_client_id"`
	KeysRemoved      *int64    `json:"keys_removed"`
	EventID          string    `json:"event_id"`
	Kind             string    `json:"kind"`
	Network          string    `json:"network"`
	Rule             string    `json:"rule"`
}

// ToleratedSummary counts suppressed bans in the window; never a ban.
type ToleratedSummary struct {
	Evidence          string `json:"evidence"`
	Count             int64  `json:"count"`
	CountIsUpperBound bool   `json:"count_is_upper_bound"`
}

// BanPage is the paging block of a ban search.
type BanPage struct {
	NextCursor *string `json:"next_cursor"`
	Limit      int     `json:"limit"`
}

// BanSearchResult is the processed answer of a ban search.
type BanSearchResult struct {
	QueriedAt              time.Time        `json:"queried_at"`
	History                Coverage         `json:"history"`
	Target                 ResolvedTarget   `json:"target"`
	Bans                   []Ban            `json:"bans"`
	OrphanHits             HitSummary       `json:"orphan_hits"`
	ThresholdTolerated     ToleratedSummary `json:"threshold_tolerated"`
	UnconfirmedActivations []LifecycleEvent `json:"unconfirmed_activations"`
	Releases               []LifecycleEvent `json:"releases"`
	CounterResets          []LifecycleEvent `json:"counter_resets"`
	Page                   BanPage          `json:"page"`
	Projection             string           `json:"projection"`
	SchemaVersion          string           `json:"schema_version"`
	ResultBasis            string           `json:"result_basis"`
}
