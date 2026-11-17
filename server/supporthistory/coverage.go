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

// Source read states reported in coverage.
const (
	stateRead          = "read"
	stateReadFailed    = "read_failed"
	stateNotInstalled  = "not_installed"
	stateWithoutRows   = "no_rows_for_deployment"
	stateNotQueried    = "not_queried"
	availabilityFull   = "available"
	availabilityPart   = "partial"
	coverageWithin     = "within_retention"
	coveragePartial    = "partially_expired"
	coverageExpired    = "expired"
	deliveryNotGranted = "not_guaranteed"
)

// Coverage condition codes.
const (
	conditionNotInstalled     = "SOURCE_NOT_INSTALLED"
	conditionReadFailed       = "SOURCE_READ_FAILED"
	conditionWithoutRows      = "SOURCE_WITHOUT_ROWS_STREAM_DISABLED_OR_NO_TRAFFIC"
	conditionStateUnknown     = "SOURCE_STATE_UNKNOWN"
	conditionWindowExpired    = "WINDOW_EXPIRED"
	conditionWindowPartial    = "WINDOW_PARTIALLY_EXPIRED"
	conditionLegacyRows       = "LEGACY_ROWS_PRESENT"
	conditionCutoverUnknown   = "CONTRACT_CUTOVER_UNKNOWN"
	conditionNoContractRows   = "NO_CONTRACT_ROWS_IN_WINDOW"
	conditionCandidatePartial = "CANDIDATE_NETWORKS_PARTIAL"
	conditionLifecycleTrimmed = "LIFECYCLE_ROWS_TRUNCATED"
)

// Result basis values of every answer.
const (
	basisMatchesFound      = "matches_found"
	basisNoMatches         = "no_matches"
	basisIdentityUnresolve = "identity_unresolved"
	basisEvidenceTruncated = "evidence_truncated"
)

// primaryBasis maps the read state and window fit of the primary source to the basis of an answer without matches.
// Secondary sources (step events, raw brute-force rows, summaries) only feed conditions and availability: a
// deployment that never writes them must still be able to answer no_matches.
var primaryBasis = map[string]string{
	stateNotInstalled:  "source_not_installed",
	stateWithoutRows:   "source_without_rows",
	stateReadFailed:    "source_read_failed",
	coverageExpired:    "window_expired",
	coveragePartial:    "window_partially_expired",
}

// resultBasis states the match state: matches win over any condition; otherwise the read state of the primary source,
// then its window fit, then truncated evidence, then an unresolved identity, then a plain miss.
func resultBasis(found bool, coverage Coverage, primary Source, identityUnresolved bool) string {
	if found {
		return basisMatchesFound
	}

	for _, source := range coverage.Sources {
		if source.Source != string(primary) {
			continue
		}

		for _, value := range []string{source.State, source.WindowCoverage} {
			if basis := primaryBasis[value]; basis != "" {
				return basis
			}
		}
	}

	if slices.Contains(coverage.Conditions, conditionLifecycleTrimmed) ||
		slices.Contains(coverage.Conditions, conditionCandidatePartial) {
		return basisEvidenceTruncated
	}

	if identityUnresolved {
		return basisIdentityUnresolve
	}

	return basisNoMatches
}

// limitNoGlobalOrder states that rows of different instances have no common order.
const limitNoGlobalOrder = "NO_GLOBAL_ORDER_ACROSS_INSTANCES"

// attemptKnownLimits are the coverage limits of login and step-event history (contract §1, §8, terminal post-actions).
var attemptKnownLimits = []string{
	"SUCCESS_DEDUPLICATION_MAY_HIDE_REPEATS",
	"FAILURE_DEDUPLICATION_MAY_HIDE_REPEATS",
	"BOUNDED_BUFFERS_MAY_DROP_ROWS",
	"BEST_EFFORT_TERMINAL_POST_ACTIONS_MAY_BE_DROPPED",
	"NO_ROW_WITHOUT_ANALYTICS_EFFECT",
	"EXPORT_DELAY",
	"FLOW_COMPLETION_NEVER_RECORDED",
	"BROWSER_ABORTS_NOT_RECORDED",
	limitNoGlobalOrder,
	"LOGIN_CASE_VARIANTS_NOT_MATCHED",
	"ALIAS_HISTORY_NOT_RECORDED",
}

// sourceRead is the outcome of reading one source in one operation.
type sourceRead struct {
	source    Source
	retention time.Duration
	failed    error
	presence  SourcePresence
	queried   bool
}

// sourceState folds the read error and presence into one coverage state.
func (r sourceRead) sourceState() string {
	switch {
	case !r.queried:
		return stateNotQueried
	case errorIs(r.failed, ErrSourceNotInstalled) || r.presence == PresenceNotInstalled:
		return stateNotInstalled
	case r.failed != nil:
		return stateReadFailed
	case r.presence == PresenceNoRows:
		return stateWithoutRows
	default:
		return stateRead
	}
}

// windowCoverage relates the window to the retention of a source at the query time.
func windowCoverage(now time.Time, window Window, retention time.Duration) string {
	horizon := now.Add(-retention)

	switch {
	case !window.Until.After(horizon):
		return coverageExpired
	case window.From.Before(horizon):
		return coveragePartial
	default:
		return coverageWithin
	}
}

// coverageInput collects everything that determines the coverage block.
type coverageInput struct {
	now           time.Time
	window        Window
	deployment    string
	reads         []sourceRead
	contractSince *time.Time
	limits        []string
	conditions    []string
	contractKnown bool
	legacyRows    bool
}

// buildCoverage renders the coverage block of a processed answer.
func buildCoverage(input coverageInput) Coverage {
	coverage := Coverage{Deployment: input.deployment, DeliveryCompleteness: deliveryNotGranted,
		Availability: availabilityFull, ContractRowsSince: input.contractSince,
		KnownLimits: append([]string{}, input.limits...), Sources: []SourceCoverage{},
		LateEventsPossible: !input.window.Until.Before(input.now.Add(-lateEventHorizon))}
	conditions := append([]string{}, input.conditions...)

	for _, read := range input.reads {
		state := read.sourceState()
		windowFit := windowCoverage(input.now, input.window, read.retention)
		coverage.Sources = append(coverage.Sources, SourceCoverage{Source: string(read.source), State: state,
			RetentionDays: int(read.retention / (24 * time.Hour)), WindowCoverage: windowFit})
		conditions = append(conditions, readConditions(read, state, windowFit)...)

		if state != stateRead && state != stateNotQueried {
			coverage.Availability = availabilityPart
		}
	}

	if input.legacyRows {
		conditions = append(conditions, conditionLegacyRows)
	}

	if slices.ContainsFunc(input.reads, func(read sourceRead) bool { return read.source == SourceLogins }) {
		switch {
		case !input.contractKnown:
			conditions = append(conditions, conditionCutoverUnknown)
		case input.contractSince == nil:
			conditions = append(conditions, conditionNoContractRows)
		}
	}

	slices.Sort(conditions)
	coverage.Conditions = slices.Compact(conditions)

	return coverage
}

// readConditions lists the conditions one source contributes.
func readConditions(read sourceRead, state, windowFit string) []string {
	var conditions []string

	switch state {
	case stateNotInstalled:
		conditions = append(conditions, conditionNotInstalled)
	case stateReadFailed:
		conditions = append(conditions, conditionReadFailed)
	case stateWithoutRows:
		conditions = append(conditions, conditionWithoutRows)
	}

	if read.queried && read.presence == PresenceUnknown && state == stateRead {
		conditions = append(conditions, conditionStateUnknown)
	}

	switch windowFit {
	case coverageExpired:
		conditions = append(conditions, conditionWindowExpired)
	case coveragePartial:
		conditions = append(conditions, conditionWindowPartial)
	}

	return conditions
}
