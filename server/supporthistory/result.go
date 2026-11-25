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

// SchemaVersion is the version of every request and response of this service.
const SchemaVersion = "1"

// Coverage states which evidence a response is based on; it is part of every processed answer.
type Coverage struct {
	ContractRowsSince *time.Time `json:"contract_rows_since"`
	// CompletionEventsSince is the first recorded OIDC completion event of the deployment within retention; flows
	// before it predate completion recording and keep FLOW_COMPLETION_NEVER_RECORDED.
	CompletionEventsSince *time.Time       `json:"oidc_completion_events_since"`
	Sources               []SourceCoverage `json:"sources"`
	Conditions            []string         `json:"conditions"`
	KnownLimits           []string         `json:"known_limits"`
	Availability          string           `json:"availability"`
	Deployment            string           `json:"deployment"`
	DeliveryCompleteness  string           `json:"delivery_completeness"`
	LateEventsPossible    bool             `json:"late_events_possible"`
}

// SourceCoverage is the read state and retention fit of one source.
type SourceCoverage struct {
	Source         string `json:"source"`
	State          string `json:"state"`
	WindowCoverage string `json:"window_coverage"`
	RetentionDays  int    `json:"retention_days"`
}

// ResolvedAccount is one account the search matched, with its provenance.
type ResolvedAccount struct {
	Account    string `json:"account"`
	Provenance string `json:"provenance"`
}

// SubjectResolution explains how the subject was turned into match values.
type SubjectResolution struct {
	SuppliedLogin   *string           `json:"supplied_login"`
	SuppliedAccount *string           `json:"supplied_account"`
	Accounts        []ResolvedAccount `json:"accounts"`
	CurrentMapping  string            `json:"current_mapping"`
}

// Finding is one observed failure or noteworthy condition; UIs use Code, never text.
type Finding struct {
	EventID     *string  `json:"event_id"`
	Uncertainty []string `json:"uncertainty"`
	Code        string   `json:"code"`
	Category    string   `json:"category"`
	Certainty   string   `json:"certainty"`
}

// EventIdentity holds the identity claims recorded with one event.
type EventIdentity struct {
	SuppliedLogin    *string `json:"supplied_login"`
	CanonicalAccount *string `json:"canonical_account"`
	AccountFound     *bool   `json:"account_found_at_capture"`
	MatchedBy        *string `json:"matched_by"`
	SubjectMatch     bool    `json:"subject_match"`
}

// EventContext holds the request context recorded with one event.
type EventContext struct {
	ClientIP        *string `json:"client_ip"`
	Protocol        *string `json:"protocol"`
	Service         *string `json:"service"`
	OIDCClientID    *string `json:"oidc_client_id"`
	SAMLEntityID    *string `json:"saml_entity_id"`
	GrantType       *string `json:"grant_type"`
	Transport       *string `json:"transport"`
	TransportStatus *int    `json:"transport_status"`
}

// Decision is the recorded Policy result of a login row.
//
// AnsweredStatusCode and AnsweredStatusMessage are the host status code and status text selected for the sealed
// terminal decision (logins.http_status, logins.status_msg). They are neither the committed transport status
// (EventContext.TransportStatus) nor necessarily what a browser displayed: IdP pages render their own text. Unknown
// values are null, never a success default.
type Decision struct {
	BruteForceBucket      *string  `json:"brute_force_bucket"`
	BruteForceTolerated   *bool    `json:"brute_force_tolerated"`
	AnsweredStatusCode    *int     `json:"answered_status_code"`
	AnsweredStatusMessage *string  `json:"answered_status_message"`
	DecisionSources       []string `json:"decision_sources"`
	Operation             string   `json:"operation"`
	Outcome               string   `json:"outcome"`
	OutcomeStage          string   `json:"outcome_stage"`
	OutcomeMarker         string   `json:"outcome_marker"`
	ResponseMarker        string   `json:"response_marker"`
	PolicyRule            string   `json:"policy_rule"`
	TempFailReason        string   `json:"tempfail_reason"`
	TempFailCheckpoint    string   `json:"tempfail_checkpoint"`
	PolicyStatus          string   `json:"policy_status"`
	FSMState              string   `json:"fsm_state"`
}

// Factor is the recorded result of one second-factor verification event.
type Factor struct {
	Result      string `json:"result"`
	Reason      string `json:"reason"`
	FlowEffect  string `json:"flow_effect"`
	FailLatched bool   `json:"fail_latched"`
}

// Reputation is the structured reputation evidence of one login row.
type Reputation struct {
	Assessments []ReputationAssessment `json:"assessments"`
	State       string                 `json:"state"`
	Truncated   bool                   `json:"truncated"`
}

// Event is one recorded row or step event, interpreted under the data contract.
type Event struct {
	OccurredAt    time.Time     `json:"occurred_at"`
	EventID       *string       `json:"event_id"`
	FactorRole    *string       `json:"factor_role"`
	Method        *string       `json:"method"`
	Decision      *Decision     `json:"decision"`
	Factor        *Factor       `json:"factor"`
	Reputation    *Reputation   `json:"reputation"`
	Identity      EventIdentity `json:"identity"`
	Context       EventContext  `json:"context"`
	Source        string        `json:"source"`
	RequestID     string        `json:"request_id"`
	Instance      string        `json:"instance"`
	Stage         string        `json:"stage"`
	Result        string        `json:"result"`
	Code          string        `json:"code"`
	Category      string        `json:"category"`
	Sequence      int           `json:"sequence"`
	RecordVersion int           `json:"record_version"`
}

// Steps states per step whether evidence was recorded or does not apply. Primary is session_reused for
// an OIDC flow that /authorize started for an already authenticated session.
type Steps struct {
	Primary        string `json:"primary"`
	SecondFactor   string `json:"second_factor"`
	CodeIssuance   string `json:"code_issuance"`
	CodeRedemption string `json:"code_redemption"`
}

// Completion is the recorded OIDC authorization-code completion of one flow. Nauthilus's part ends with the token
// response for the flow's code (state tokens_issued); a relying-party session after it is never observed.
type Completion struct {
	CodeIssuedAt         *time.Time `json:"code_issued_at"`
	CodeRedeemableUntil  *time.Time `json:"code_redeemable_until"`
	RedemptionObservedAt *time.Time `json:"redemption_observed_at"`
	Scope                string     `json:"scope"`
	State                string     `json:"state"`
	Authentication       string     `json:"authentication"`
}

// Recording describes evidence limits of one attempt. EventsTruncated is true exactly when more recorded events
// follow the listed ones, that is when the attempt carries events_page.next_cursor.
type Recording struct {
	KnownGaps          []string `json:"known_gaps"`
	ReplayedRowsMerged int      `json:"replayed_rows_merged"`
	LegacyRows         int      `json:"legacy_rows"`
	EventsTruncated    bool     `json:"events_truncated"`
}

// EventsPage continues the events of one attempt. NextCursor is set while more recorded events follow the listed
// ones; the next page is the attempt detail lookup with Detail's attempt_id and around and events_page.cursor set
// to NextCursor. Limit is the events page size this answer applied.
type EventsPage struct {
	NextCursor *string          `json:"next_cursor"`
	Detail     AttemptReference `json:"detail"`
	Limit      int              `json:"limit"`
}

// Attempt is one diagnostic attempt: an IdP flow or a single authentication request. Events and Findings hold one
// events page; every other member is derived from the attempt's interpretation read and is the same on every page.
// EventsPage appears when more events follow or the detail request selected an events page.
type Attempt struct {
	StartedAt            time.Time   `json:"started_at"`
	LastObservedAt       time.Time   `json:"last_observed_at"`
	Completion           *Completion `json:"completion"`
	EventsPage           *EventsPage `json:"events_page,omitempty"`
	Findings             []Finding   `json:"findings"`
	Events               []Event     `json:"events"`
	Recording            Recording   `json:"recording"`
	Steps                Steps       `json:"steps"`
	AttemptID            string      `json:"attempt_id"`
	Kind                 string      `json:"kind"`
	Projection           string      `json:"projection"`
	Outcome              string      `json:"outcome"`
	OutcomeBasis         string      `json:"outcome_basis"`
	Progress             string      `json:"progress"`
	FinalOutcomeObserved bool        `json:"final_outcome_observed"`
}

// AttemptPage is the paging block of an attempt search.
type AttemptPage struct {
	ScannedUntil time.Time `json:"scanned_until"`
	NextCursor   *string   `json:"next_cursor"`
	Limit        int       `json:"limit"`
}

// AttemptSearchResult is the processed answer of an attempt search. The members after ResultBasis appear only when
// the request selected a response mode or the ban context, so answers to earlier requests stay unchanged. In compact
// mode Attempts is empty and AttemptSummaries carries one summary per found attempt.
type AttemptSearchResult struct {
	QueriedAt         time.Time         `json:"queried_at"`
	History           Coverage          `json:"history"`
	SubjectResolution SubjectResolution `json:"subject_resolution"`
	Attempts          []Attempt         `json:"attempts"`
	Page              AttemptPage       `json:"page"`
	SchemaVersion     string            `json:"schema_version"`
	ResultBasis       string            `json:"result_basis"`
	ResponseMode      *string           `json:"response_mode,omitempty"`
	AttemptSummaries  *[]AttemptSummary `json:"attempt_summaries,omitempty"`
	BanContexts       *[]BanContext     `json:"ban_contexts,omitempty"`
	BanHistory        *Coverage         `json:"ban_history,omitempty"`
	found             int
}

// AttemptDetailResult is the processed answer of an attempt detail lookup; Attempt is nil when nothing visible to
// the caller was found.
type AttemptDetailResult struct {
	QueriedAt         time.Time          `json:"queried_at"`
	Attempt           *Attempt           `json:"attempt"`
	SubjectResolution *SubjectResolution `json:"subject_resolution"`
	History           Coverage           `json:"history"`
	SchemaVersion     string             `json:"schema_version"`
	ResultBasis       string             `json:"result_basis"`
}
