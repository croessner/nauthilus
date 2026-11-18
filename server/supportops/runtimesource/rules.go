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

package runtimesource

import (
	"regexp"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// Metric families and labels read by the rule table. They are defined in server/stats, server/policy/observability,
// and the ClickHouse plugin; the rule tests pin them.
const (
	familyLDAPTargetHealth   = "ldap_target_health"
	familyLDAPBreakerState   = "ldap_breaker_state"
	familyLDAPErrors         = "ldap_errors_total"
	familyBackendServers     = "backend_servers_status"
	familyRedisTimeouts      = "redis_connection_timeouts_total"
	familyAuthEvents         = "plugin_auth_events_total"
	familyPolicyTechnical    = "policy_check_technical_errors_total"
	labelPool                = "pool"
	labelTarget              = "target"
	labelServerStatus        = "server_status"
	labelPoolName            = "pool_name"
	labelOutcome             = "outcome"
	labelLane                = "lane"
	labelResult              = "result"
	labelMetric              = "metric"
	serverStatusWanted       = "wanted"
	serverStatusAlive        = "alive"
	outcomeDropped           = "dropped"
	breakerStateOpen         = 1
	breakerStateHalfOpen     = 2
	targetHealthHealthyValue = 1
)

var (
	// clickHouseFlushFamilies matches the plugin's scoped flush counters of every row and event stream.
	clickHouseFlushFamilies = regexp.MustCompile(`^nauthilus_plugin_(?:[a-z0-9_]+_)?clickhouse(?:_[a-z0-9_]+)?_flush_batches_total$`)

	// clickHouseQueueFamilies matches the plugin's scoped enqueue counters of every row and event stream.
	clickHouseQueueFamilies = regexp.MustCompile(`^nauthilus_plugin_(?:[a-z0-9_]+_)?clickhouse(?:_[a-z0-9_]+)?_queued_rows_total$`)

	// clickHouseFlushFailures are the flush results that lose or delay rows.
	clickHouseFlushFailures = []string{"http_error", "status_error", "no_url"}

	// clickHouseQueueLosses are the enqueue results that never reach ClickHouse.
	clickHouseQueueLosses = []string{"dropped", "dropped_reject_limit", "encode_error"}
)

// ldapTarget keys one LDAP pool target.
type ldapTarget struct {
	pool   string
	target string
}

// ldapFindings reports the current health and breaker state per target and the lifetime error count per pool.
func (s *snapshot) ldapFindings() []supportops.Finding {
	states := map[ldapTarget]*supportops.Finding{}
	order := []ldapTarget{}

	stateFinding := func(key ldapTarget) *supportops.Finding {
		if finding, ok := states[key]; ok {
			return finding
		}

		finding := s.finding(supportops.ComponentLDAP, supportops.BasisCurrentState, supportops.StatusOK,
			map[string]string{labelPool: key.pool, labelTarget: key.target})
		states[key] = &finding
		order = append(order, key)

		return &finding
	}

	for _, entry := range s.familySeries(familyLDAPTargetHealth) {
		finding := stateFinding(ldapTarget{pool: entry.labels[labelPool], target: entry.labels[labelTarget]})
		if entry.value < targetHealthHealthyValue {
			raise(finding, supportops.StatusFailing, supportops.SymptomLDAPTargetUnhealthy, 1)
		}
	}

	for _, entry := range s.familySeries(familyLDAPBreakerState) {
		finding := stateFinding(ldapTarget{pool: entry.labels[labelPool], target: entry.labels[labelTarget]})

		switch int(entry.value) {
		case breakerStateOpen:
			raise(finding, supportops.StatusFailing, supportops.SymptomLDAPBreakerOpen, 1)
		case breakerStateHalfOpen:
			raise(finding, supportops.StatusDegraded, supportops.SymptomLDAPBreakerHalfOpen, 1)
		}
	}

	findings := make([]supportops.Finding, 0, len(order)+1)
	for _, key := range order {
		findings = append(findings, *states[key])
	}

	return append(findings, s.counterFindings(supportops.ComponentLDAP, s.familySeries(familyLDAPErrors), labelPool,
		supportops.SymptomLDAPErrors)...)
}

// raise records a symptom and keeps the worse status.
func raise(finding *supportops.Finding, status supportops.Status, symptom string, amount int64) {
	if severity(status) > severity(finding.Status) {
		finding.Status = status
	}

	finding.Symptoms = append(finding.Symptoms, supportops.Symptom{Code: symptom, Count: amount})
}

// severity orders current-state statuses.
func severity(status supportops.Status) int {
	switch status {
	case supportops.StatusFailing:
		return 3
	case supportops.StatusDegraded:
		return 2
	case supportops.StatusOK:
		return 1
	default:
		return 0
	}
}

// backendMonitoringFindings compares the wanted and alive monitored backend servers.
func (s *snapshot) backendMonitoringFindings() []supportops.Finding {
	values := map[string]float64{}

	for _, entry := range s.familySeries(familyBackendServers) {
		values[entry.labels[labelServerStatus]] = entry.value
	}

	wanted, hasWanted := values[serverStatusWanted]
	alive, hasAlive := values[serverStatusAlive]

	if !hasWanted || !hasAlive || wanted <= 0 {
		return nil
	}

	finding := s.finding(supportops.ComponentBackendMonitoring, supportops.BasisCurrentState, supportops.StatusOK, nil)

	switch down := count(wanted - alive); {
	case alive <= 0:
		raise(&finding, supportops.StatusFailing, supportops.SymptomBackendServersDown, count(wanted))
	case down > 0:
		raise(&finding, supportops.StatusDegraded, supportops.SymptomBackendServersDown, down)
	}

	return []supportops.Finding{finding}
}

// redisFindings reports pool wait timeouts per pool since process start.
func (s *snapshot) redisFindings() []supportops.Finding {
	return s.counterFindings(supportops.ComponentRedis, s.familySeries(familyRedisTimeouts), labelPoolName,
		supportops.SymptomRedisPoolTimeouts)
}

// clickHouseFindings reports failed flushes and lost rows of the ClickHouse export streams since process start.
func (s *snapshot) clickHouseFindings() []supportops.Finding {
	flushes := filterSeries(s.matchingSeries(clickHouseFlushFamilies, labelMetric), labelResult, clickHouseFlushFailures)
	losses := filterSeries(s.matchingSeries(clickHouseQueueFamilies, labelMetric), labelResult, clickHouseQueueLosses)

	if !s.hasFamily(clickHouseFlushFamilies) && !s.hasFamily(clickHouseQueueFamilies) {
		return nil
	}

	findings := s.counterFindings(supportops.ComponentClickHouseExport, flushes, labelMetric, supportops.SymptomClickHouseFlushFailed)

	return append(findings, s.counterFindings(supportops.ComponentClickHouseExport, losses, labelMetric,
		supportops.SymptomClickHouseRowsDropped)...)
}

// authEventFindings reports dropped host diagnostic events per lane since process start.
func (s *snapshot) authEventFindings() []supportops.Finding {
	events := s.familySeries(familyAuthEvents)
	if events == nil {
		return nil
	}

	dropped := filterSeries(events, labelOutcome, []string{outcomeDropped})

	return s.counterFindings(supportops.ComponentAuthEventDelivery, dropped, labelLane, supportops.SymptomAuthEventsDropped)
}

// policyFindings reports technical policy check errors since process start.
func (s *snapshot) policyFindings() []supportops.Finding {
	return s.counterFindings(supportops.ComponentPolicy, s.familySeries(familyPolicyTechnical), "", supportops.SymptomPolicyTechnicalErrors)
}

// hasFamily reports whether any registered family matches pattern.
func (s *snapshot) hasFamily(pattern *regexp.Regexp) bool {
	for name := range s.families {
		if pattern.MatchString(name) {
			return true
		}
	}

	return false
}

// filterSeries keeps the series whose label takes one of values; a nil input (unknown family) stays nil.
func filterSeries(input []series, label string, values []string) []series {
	if input == nil {
		return nil
	}

	kept := make([]series, 0, len(input))

	for _, entry := range input {
		if slices.Contains(values, entry.labels[label]) {
			kept = append(kept, entry)
		}
	}

	return kept
}

// counterFindings sums lifetime counters per group label (or overall for an empty label). A registered family that
// counted nothing answers not_observed; an absent family answers nothing, so the component becomes unknown.
func (s *snapshot) counterFindings(component string, input []series, groupLabel string, symptom string) []supportops.Finding {
	if input == nil {
		return nil
	}

	totals := map[string]float64{}
	groups := []string{}

	for _, entry := range input {
		group := entry.labels[groupLabel]
		if _, seen := totals[group]; !seen {
			groups = append(groups, group)
		}

		totals[group] += entry.value
	}

	if len(groups) == 0 {
		return []supportops.Finding{s.finding(component, supportops.BasisProcessLifetimeCounter, supportops.StatusNotObserved, nil)}
	}

	slices.SortFunc(groups, strings.Compare)

	findings := make([]supportops.Finding, 0, len(groups))

	for _, group := range groups {
		var labels map[string]string
		if groupLabel != "" {
			labels = map[string]string{groupLabel: group}
		}

		finding := s.finding(component, supportops.BasisProcessLifetimeCounter, supportops.StatusNotObserved, labels)
		if total := count(totals[group]); total > 0 {
			finding.Status = supportops.StatusObserved
			finding.Symptoms = []supportops.Symptom{{Code: symptom, Count: total}}
		}

		findings = append(findings, finding)
	}

	return findings
}
