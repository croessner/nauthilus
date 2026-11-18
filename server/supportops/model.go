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

package supportops

import "time"

// SchemaVersion is the request and response schema version of the diagnostics service.
const SchemaVersion = "1"

// Component vocabulary. Requests may only name these components.
const (
	ComponentLDAP              = "ldap"
	ComponentAuthBackend       = "auth_backend"
	ComponentBackendMonitoring = "backend_monitoring"
	ComponentRedis             = "redis"
	ComponentClickHouseExport  = "clickhouse_export"
	ComponentAuthEventDelivery = "auth_event_delivery"
	ComponentPolicy            = "policy"
)

// Components lists every diagnosable component in response order.
var Components = []string{
	ComponentLDAP, ComponentAuthBackend, ComponentBackendMonitoring, ComponentRedis, ComponentClickHouseExport,
	ComponentAuthEventDelivery, ComponentPolicy,
}

// Source names. Requests may only name these sources.
const (
	SourceRuntime    = "nauthilus_runtime"
	SourceLoki       = "loki"
	SourcePrometheus = "prometheus"
)

// SourceNames lists every source in response order.
var SourceNames = []string{SourceRuntime, SourceLoki, SourcePrometheus}

// IsHistorical reports whether the named source reports recorded evidence inside the requested window.
func IsHistorical(name string) bool {
	return name == SourceLoki || name == SourcePrometheus
}

// SourceKind tells whether a source reports the current local state or recorded history.
type SourceKind string

const (
	// SourceKindLocalCurrent is the current state of this one instance.
	SourceKindLocalCurrent SourceKind = "local_current"

	// SourceKindHistorical is recorded evidence inside the requested window.
	SourceKindHistorical SourceKind = "historical"
)

// SourceStatus is the completeness of one source's contribution.
type SourceStatus string

const (
	// SourceStatusOK means the source answered completely.
	SourceStatusOK SourceStatus = "ok"

	// SourceStatusPartial means part of the source's answer is missing or truncated.
	SourceStatusPartial SourceStatus = "partial"

	// SourceStatusUnavailable means the source could not be read.
	SourceStatusUnavailable SourceStatus = "unavailable"

	// SourceStatusTimeout means the source ran out of time.
	SourceStatusTimeout SourceStatus = "timeout"

	// SourceStatusNotConfigured means the source is not configured on this instance.
	SourceStatusNotConfigured SourceStatus = "not_configured"

	// SourceStatusNotRequested means the request excluded the source.
	SourceStatusNotRequested SourceStatus = "not_requested"
)

// Status is the state a finding reports. Missing data is unknown, never ok.
type Status string

const (
	// StatusFailing is a current state that prevents the component from working.
	StatusFailing Status = "failing"

	// StatusDegraded is a current state that limits the component.
	StatusDegraded Status = "degraded"

	// StatusObserved means symptoms were counted (since process start or inside the log window).
	StatusObserved Status = "observed"

	// StatusNotObserved means the source covered the scope and counted no symptom.
	StatusNotObserved Status = "not_observed"

	// StatusOK is a current state without a symptom.
	StatusOK Status = "ok"

	// StatusUnknown means the source has no data for the scope.
	StatusUnknown Status = "unknown"
)

// ScopeKind tells whether a finding is about one instance or about the whole deployment.
type ScopeKind string

const (
	// ScopeInstance is one named instance.
	ScopeInstance ScopeKind = "instance"

	// ScopeDeployment is the whole deployment.
	ScopeDeployment ScopeKind = "deployment"
)

// FreshnessBasis names what the time of a finding means.
type FreshnessBasis string

const (
	// BasisCurrentState is a gauge read at observation time.
	BasisCurrentState FreshnessBasis = "current_state"

	// BasisProcessLifetimeCounter is a counter accumulated since process start; it is not tied to the window.
	BasisProcessLifetimeCounter FreshnessBasis = "process_lifetime_counter"

	// BasisLogWindow is a count of log lines inside the covered window.
	BasisLogWindow FreshnessBasis = "log_window"

	// BasisMetricWindow is the increase of a counter inside the covered window.
	BasisMetricWindow FreshnessBasis = "metric_window"
)

// Coverage views.
const (
	CoverageLocalInstance = "local_instance"
	CoverageLogLabels     = "log_labels"
	CoverageMetricLabels  = "metric_labels"
)

// Note codes explain how to read a result.
const (
	NoteLocalViewNotCluster        = "LOCAL_VIEW_NOT_CLUSTER"
	NoteRuntimeIsCurrentStateOnly  = "RUNTIME_IS_CURRENT_STATE_ONLY"
	NoteRuntimeCountersAreLifetime = "RUNTIME_COUNTERS_ARE_PROCESS_LIFETIME"
	NoteNoHistoricalSource         = "NO_HISTORICAL_SOURCE"
	NoteHistoricalSourceIncomplete = "HISTORICAL_SOURCE_INCOMPLETE"
	NoteValuesAreUntrusted         = "VALUES_ARE_UNTRUSTED_DATA"
	NoteHypothesesAreNotFindings   = "HYPOTHESES_ARE_NOT_FINDINGS"
)

// DiagnosticsRequest asks for the operational state of the support-relevant components.
type DiagnosticsRequest struct {
	Window         *Window  `json:"window,omitempty"`
	Components     []string `json:"components,omitempty"`
	Sources        []string `json:"sources,omitempty"`
	SchemaVersion  string   `json:"schema_version"`
	AuditReference string   `json:"audit_reference,omitempty"`
}

// Window is a time window with inclusive From and exclusive Until.
type Window struct {
	From  time.Time `json:"from"`
	Until time.Time `json:"until"`
}

// DiagnosticsResult is the answer of one diagnostics call. Findings and hypotheses are separate lists.
type DiagnosticsResult struct {
	Sources       []SourceReport `json:"sources"`
	Findings      []Finding      `json:"findings"`
	Hypotheses    []Hypothesis   `json:"hypotheses"`
	Notes         []string       `json:"notes"`
	Scope         ResultScope    `json:"scope"`
	SchemaVersion string         `json:"schema_version"`
}

// ResultScope names what the result covers.
type ResultScope struct {
	Window     Window    `json:"window"`
	QueriedAt  time.Time `json:"queried_at"`
	Deployment string    `json:"deployment,omitempty"`
	Instance   string    `json:"instance"`
}

// SourceReport is the completeness statement of one source.
type SourceReport struct {
	Coverage  Coverage     `json:"coverage"`
	Name      string       `json:"name"`
	Kind      SourceKind   `json:"kind"`
	Status    SourceStatus `json:"status"`
	Code      string       `json:"code,omitempty"`
	Truncated bool         `json:"truncated"`
}

// Coverage states which time span and which instances a source actually covered.
type Coverage struct {
	From      *time.Time `json:"from,omitempty"`
	Until     *time.Time `json:"until,omitempty"`
	Instances []string   `json:"instances"`
	View      string     `json:"view,omitempty"`
}

// Finding is one observation about one component in one scope from one source.
type Finding struct {
	Labels    map[string]string `json:"labels,omitempty"`
	Symptoms  []Symptom         `json:"symptoms"`
	Observed  Observation       `json:"observed"`
	Freshness Freshness         `json:"freshness"`
	Scope     FindingScope      `json:"scope"`
	ID        string            `json:"id"`
	Component string            `json:"component"`
	Source    string            `json:"source"`
	Status    Status            `json:"status"`
}

// FindingScope is the instance or deployment a finding is about.
type FindingScope struct {
	Kind     ScopeKind `json:"kind"`
	Instance string    `json:"instance,omitempty"`
}

// Observation is the time a finding refers to: a point for current state, a span for log evidence.
type Observation struct {
	At    *time.Time `json:"at,omitempty"`
	From  *time.Time `json:"from,omitempty"`
	Until *time.Time `json:"until,omitempty"`
}

// Freshness states when the evidence was read and what its time means.
type Freshness struct {
	ObservedAt    time.Time      `json:"observed_at"`
	CountingSince *time.Time     `json:"counting_since,omitempty"`
	Basis         FreshnessBasis `json:"basis"`
	AgeSeconds    int64          `json:"age_seconds"`
}

// Symptom is one counted or present symptom code.
type Symptom struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

// Hypothesis is a possible explanation derived from findings; it is never a finding itself.
type Hypothesis struct {
	FindingIDs []string `json:"finding_ids"`
	Caveats    []string `json:"caveats"`
	Code       string   `json:"code"`
	Confidence string   `json:"confidence"`
	Basis      string   `json:"basis"`
}
