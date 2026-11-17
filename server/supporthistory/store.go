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
	"errors"
	"time"
)

// Store errors. Implementations wrap them so the service can map store failures to stable codes.
var (
	// ErrBudgetExceeded reports a read that hit a server-side read or time budget.
	ErrBudgetExceeded = errors.New("history read budget exceeded")

	// ErrSourceNotInstalled reports a missing table or database.
	ErrSourceNotInstalled = errors.New("history source not installed")

	// ErrSourceUnavailable reports a failed, truncated, or unparseable read.
	ErrSourceUnavailable = errors.New("history source unavailable")

	// ErrReaderUnsafe reports a reader account that is writable or does not enforce read budgets.
	ErrReaderUnsafe = errors.New("history reader unsafe")
)

// Source names one recorded ClickHouse table.
type Source string

const (
	// SourceLogins is nauthilus.logins.
	SourceLogins Source = "logins"

	// SourceAuthEvents is nauthilus.auth_events.
	SourceAuthEvents Source = "auth_events"

	// SourceBanLifecycle is nauthilus.bruteforce_lifecycle.
	SourceBanLifecycle Source = "bruteforce_lifecycle"

	// SourceBanAttempts is nauthilus.bruteforce_attempts.
	SourceBanAttempts Source = "bruteforce_attempts"

	// SourceBanSummary is nauthilus.bruteforce_attempt_summary.
	SourceBanSummary Source = "bruteforce_attempt_summary"
)

// SourcePresence is the installation and row state of one source for the configured deployment.
type SourcePresence string

const (
	// PresenceRows means the source holds rows of the deployment within its retention.
	PresenceRows SourcePresence = "has_rows"

	// PresenceNoRows means no row of the deployment exists: the stream is disabled or nothing was recorded.
	PresenceNoRows SourcePresence = "no_rows_for_deployment"

	// PresenceNotInstalled means the table is missing.
	PresenceNotInstalled SourcePresence = "not_installed"

	// PresenceUnknown means the probe failed or exceeded its budget.
	PresenceUnknown SourcePresence = "state_unknown"
)

// ReputationAssessment is one projected reputation record (contract §6).
type ReputationAssessment struct {
	RiskScore       *float64 `json:"risk_score"`
	TrustScore      *float64 `json:"trust_score"`
	Confidence      *float64 `json:"confidence"`
	Samples         *float64 `json:"samples"`
	SourceDiversity *int64   `json:"source_diversity"`
	AgeSeconds      *int64   `json:"age_seconds"`
	Fact            string   `json:"fact"`
	Role            string   `json:"role"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	Profile         string   `json:"profile"`
	Band            string   `json:"band"`
	Override        string   `json:"override"`
}

// LoginRecord is one stored nauthilus.logins row reduced to the columns the service may read. Password hashes,
// client ports, user agents, host names, and HIBP data are never selected.
type LoginRecord struct {
	At                  time.Time
	TransportStatus     *int
	UserFound           *bool
	BruteForceTolerated *bool
	DecisionSources     []string
	Reputation          []ReputationAssessment
	EventID             string
	Session             string
	Instance            string
	Service             string
	Protocol            string
	Method              string
	Username            string
	Account             string
	ClientIP            string
	ClientNet           string
	OIDCClientID        string
	SAMLEntityID        string
	GrantType           string
	FlowRef             string
	Operation           string
	Outcome             string
	OutcomeStage        string
	OutcomeMarker       string
	ResponseMarker      string
	PolicyRule          string
	TempFailReason      string
	TempFailCheckpoint  string
	PolicyStatus        string
	FSMState            string
	Transport           string
	BruteForceBucket    string
	ContractVersion     int
	ReputationTruncated bool
}

// AuthEventRecord is one stored nauthilus.auth_events row.
type AuthEventRecord struct {
	At           time.Time
	EventID      string
	EventType    string
	RequestID    string
	FlowRef      string
	Instance     string
	Protocol     string
	ClientID     string
	SAMLEntityID string
	Account      string
	ClientIP     string
	FactorRole   string
	Method       string
	Result       string
	Reason       string
	FlowEffect   string
	EventVersion int
	FailLatched  bool
}

// AttemptKind distinguishes IdP flows from single authentication requests.
type AttemptKind string

const (
	// AttemptFlow groups every row and event of one IdP browser flow by flow_ref.
	AttemptFlow AttemptKind = "flow"

	// AttemptRequest groups the rows and events of one request without flow_ref.
	AttemptRequest AttemptKind = "request"
)

// AttemptKey identifies one attempt by its non-authorizing correlation value.
type AttemptKey struct {
	Kind  AttemptKind
	Value string
}

// SubjectMatch is the identity predicate of a search; the store renders it into SQL and the service evaluates the
// same predicate in Go (subjectMatcher).
type SubjectMatch struct {
	Logins   []string
	Accounts []string
}

// AttemptFilter narrows which login rows anchor an attempt; it never prunes events inside an attempt.
type AttemptFilter struct {
	ClientIP     string
	Protocol     string
	OIDCClientID string
	SAMLEntityID string
}

// isEmpty reports whether no filter is set.
func (f AttemptFilter) isEmpty() bool {
	return f == AttemptFilter{}
}

// AnchorPosition is the exclusive newest-first paging position (anchor time, key value).
type AnchorPosition struct {
	At  time.Time
	Key string
}

// AnchorQuery selects attempt anchors inside one scan slice.
type AnchorQuery struct {
	Before  *AnchorPosition
	From    time.Time
	Until   time.Time
	Subject SubjectMatch
	Filter  AttemptFilter
	Limit   int
}

// AttemptAnchor is the latest subject-matching row time of one attempt inside the queried slice.
type AttemptAnchor struct {
	At  time.Time
	Key AttemptKey
}

// AccountQuery selects accounts recorded on rows whose supplied login matches.
type AccountQuery struct {
	From   time.Time
	Until  time.Time
	Logins []string
	Limit  int
}

// RowQuery selects every row of the given attempts inside a read range. Request rows are additionally restricted
// by Subject (when set) to keep the scan targeted.
type RowQuery struct {
	From          time.Time
	Until         time.Time
	Subject       *SubjectMatch
	Flows         []string
	Requests      []string
	LimitPerGroup int
}

// AttemptStore is the narrow read surface of recorded login rows and step events.
type AttemptStore interface {
	// Deployment returns the writer deployment every query is bound to.
	Deployment() string

	// SelfCheck verifies that the reader account is read-only and enforces the read budget.
	SelfCheck(ctx context.Context) error

	// RecordedAccounts returns distinct non-empty accounts of rows whose username is one of the logins.
	RecordedAccounts(ctx context.Context, query AccountQuery) ([]string, error)

	// Anchors returns attempt anchors newest first.
	Anchors(ctx context.Context, query AnchorQuery) ([]AttemptAnchor, error)

	// LoginRows returns the authenticate and legacy rows of the attempts.
	LoginRows(ctx context.Context, query RowQuery) ([]LoginRecord, error)

	// AuthEvents returns the second-factor events of the attempts.
	AuthEvents(ctx context.Context, query RowQuery) ([]AuthEventRecord, error)

	// Presence reports whether a source holds rows of the deployment within its retention.
	Presence(ctx context.Context, source Source) SourcePresence

	// ContractRowsSince returns the first contract row in [from, until); known is false when the probe failed or
	// exceeded its budget, and a nil time with known=true means the window holds no contract row.
	ContractRowsSince(ctx context.Context, from, until time.Time) (since *time.Time, known bool)
}

// IdentityMapping is the current stored login-name to account mapping of one login.
type IdentityMapping struct {
	Err      error
	Login    string
	Accounts []string
}

// IdentityResolver resolves login names through stored mappings only; it never authenticates.
type IdentityResolver interface {
	ResolveLogins(ctx context.Context, logins []string) []IdentityMapping
}
