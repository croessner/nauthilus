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

import "slices"

// Symptom codes shared by the sources and the hypothesis rules.
const (
	SymptomLDAPTargetUnhealthy        = "LDAP_TARGET_UNHEALTHY"
	SymptomLDAPBreakerOpen            = "LDAP_BREAKER_OPEN"
	SymptomLDAPBreakerHalfOpen        = "LDAP_BREAKER_HALF_OPEN"
	SymptomLDAPErrors                 = "LDAP_ERRORS"
	SymptomLDAPBindRejected           = "LDAP_BIND_REJECTED"
	SymptomLDAPConnectionError        = "LDAP_CONNECTION_ERROR"
	SymptomLDAPConnectionFailed       = "LDAP_CONNECTION_FAILED"
	SymptomLDAPSearchError            = "LDAP_SEARCH_ERROR"
	SymptomAuthBackendsFailed         = "AUTH_BACKENDS_FAILED"
	SymptomUnclassifiedBackendFailure = "UNCLASSIFIED_BACKEND_TEMPFAIL"
	SymptomAuthApplicationErrors      = "AUTH_APPLICATION_ERRORS"
	SymptomPluginBackendCallFailures  = "PLUGIN_BACKEND_CALL_FAILURES"
	SymptomLuaBackendVMReplaced       = "LUA_BACKEND_VM_REPLACED"
	SymptomBackendServersDown         = "BACKEND_SERVERS_DOWN"
	SymptomRedisPoolTimeouts          = "REDIS_POOL_TIMEOUTS"
	SymptomRedisPipelineError         = "REDIS_PIPELINE_ERROR"
	SymptomRedisWritePipelineFailed   = "REDIS_WRITE_PIPELINE_FAILED"
	SymptomClickHouseFlushFailed      = "CLICKHOUSE_FLUSH_FAILED"
	SymptomClickHouseRowsDropped      = "CLICKHOUSE_ROWS_DROPPED"
	SymptomAuthEventsDropped          = "AUTH_EVENTS_DROPPED"
	SymptomPolicyTechnicalErrors      = "POLICY_CHECK_TECHNICAL_ERRORS"
)

// Hypothesis codes, confidences, and caveats.
const (
	HypothesisDirectoryUnreachable    = "DIRECTORY_UNREACHABLE_OR_OVERLOADED"
	HypothesisAuthBackendFailures     = "AUTHENTICATION_BACKEND_FAILURES"
	HypothesisMonitoredBackendsDown   = "MONITORED_BACKENDS_DOWN"
	HypothesisRedisDegraded           = "REDIS_DEGRADED"
	HypothesisHistoryExportIncomplete = "SUPPORT_HISTORY_MAY_BE_INCOMPLETE"
	HypothesisPolicyTechnicalErrors   = "POLICY_TECHNICAL_ERRORS"

	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"

	CaveatLocalInstanceOnly       = "LOCAL_INSTANCE_ONLY"
	CaveatCounterNotWindowBound   = "COUNTER_NOT_BOUND_TO_WINDOW"
	CaveatLogEvidenceNotCurrent   = "LOG_EVIDENCE_IS_NOT_CURRENT_STATE"
	CaveatSingleSourceEvidence    = "SINGLE_SOURCE_EVIDENCE"
	CaveatCorrelationNotCausation = "CORRELATION_IS_NOT_CAUSATION"
)

// hypothesisRule derives one hypothesis from findings that show any of its symptoms.
type hypothesisRule struct {
	symptoms []string
	code     string
	basis    string
}

// hypothesisRules is the fixed rule table; the order is the response order.
var hypothesisRules = []hypothesisRule{
	{code: HypothesisDirectoryUnreachable, basis: "LDAP target health, breaker state, or LDAP connection errors",
		symptoms: []string{SymptomLDAPTargetUnhealthy, SymptomLDAPBreakerOpen, SymptomLDAPBreakerHalfOpen, SymptomLDAPConnectionError,
			SymptomLDAPConnectionFailed}},
	{code: HypothesisAuthBackendFailures, basis: "authentication backend failures or temporary-failure answers",
		symptoms: []string{SymptomAuthBackendsFailed, SymptomUnclassifiedBackendFailure, SymptomAuthApplicationErrors,
			SymptomPluginBackendCallFailures, SymptomLuaBackendVMReplaced, SymptomLDAPErrors, SymptomLDAPSearchError}},
	{code: HypothesisMonitoredBackendsDown, basis: "backend health monitoring reports servers that are not alive",
		symptoms: []string{SymptomBackendServersDown}},
	{code: HypothesisRedisDegraded, basis: "Redis pool wait timeouts or failed Redis pipelines",
		symptoms: []string{SymptomRedisPoolTimeouts, SymptomRedisPipelineError, SymptomRedisWritePipelineFailed}},
	{code: HypothesisHistoryExportIncomplete, basis: "failed ClickHouse flushes or dropped diagnostic rows or events",
		symptoms: []string{SymptomClickHouseFlushFailed, SymptomClickHouseRowsDropped, SymptomAuthEventsDropped}},
	{code: HypothesisPolicyTechnicalErrors, basis: "modeled policy checks ended with technical errors",
		symptoms: []string{SymptomPolicyTechnicalErrors}},
}

// deriveHypotheses applies the rule table to findings that show a symptom. Confidence is medium only when current
// state and log evidence agree; it is never higher, and every hypothesis carries its caveats.
func deriveHypotheses(findings []Finding) []Hypothesis {
	hypotheses := []Hypothesis{}

	for _, rule := range hypothesisRules {
		matched := matchingFindings(findings, rule.symptoms)
		if len(matched) == 0 {
			continue
		}

		hypotheses = append(hypotheses, buildHypothesis(rule, matched))
	}

	return hypotheses
}

// matchingFindings returns findings with a positive status and one of the symptoms.
func matchingFindings(findings []Finding, symptoms []string) []Finding {
	var matched []Finding

	for _, finding := range findings {
		if finding.Status != StatusFailing && finding.Status != StatusDegraded && finding.Status != StatusObserved {
			continue
		}

		if slices.ContainsFunc(finding.Symptoms, func(symptom Symptom) bool { return slices.Contains(symptoms, symptom.Code) }) {
			matched = append(matched, finding)
		}
	}

	return matched
}

// buildHypothesis states one hypothesis with its findings, confidence, and caveats.
func buildHypothesis(rule hypothesisRule, matched []Finding) Hypothesis {
	hypothesis := Hypothesis{Code: rule.code, Basis: rule.basis, Confidence: ConfidenceLow,
		FindingIDs: make([]string, 0, len(matched)), Caveats: []string{CaveatCorrelationNotCausation}}

	sources := map[string]struct{}{}
	currentState := false
	lifetimeCounter := false

	for _, finding := range matched {
		hypothesis.FindingIDs = append(hypothesis.FindingIDs, finding.ID)
		sources[finding.Source] = struct{}{}
		currentState = currentState || finding.Freshness.Basis == BasisCurrentState
		lifetimeCounter = lifetimeCounter || finding.Freshness.Basis == BasisProcessLifetimeCounter
	}

	_, fromRuntime := sources[SourceRuntime]
	_, fromLogs := sources[SourceLoki]

	if fromRuntime && fromLogs && currentState {
		hypothesis.Confidence = ConfidenceMedium
	}

	if len(sources) == 1 {
		hypothesis.Caveats = append(hypothesis.Caveats, CaveatSingleSourceEvidence)
	}

	if fromRuntime {
		hypothesis.Caveats = append(hypothesis.Caveats, CaveatLocalInstanceOnly)
	}

	if lifetimeCounter {
		hypothesis.Caveats = append(hypothesis.Caveats, CaveatCounterNotWindowBound)
	}

	if fromLogs {
		hypothesis.Caveats = append(hypothesis.Caveats, CaveatLogEvidenceNotCurrent)
	}

	return hypothesis
}
