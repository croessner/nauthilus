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

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/metricnames"
)

// Metric families and labels read by the rule table. The vocabulary shared with the Prometheus source lives in
// package metricnames; the gauges and labels below are read from the in-process registry only. The rule tests pin
// them.
const (
	familyLDAPTargetHealth   = "ldap_target_health"
	familyLDAPBreakerState   = "ldap_breaker_state"
	familyBackendServers     = "backend_servers_status"
	familyLDAPErrors         = metricnames.LDAPErrors
	familyRedisTimeouts      = metricnames.RedisTimeouts
	familyAuthEvents         = metricnames.AuthEvents
	familyPolicyTechnical    = metricnames.PolicyTechnical
	familyPluginCalls        = metricnames.PluginCalls
	familyLuaVMReplaced      = metricnames.LuaVMReplaced
	familyAuthAppErrors      = metricnames.AuthApplicationErrors
	labelOp                  = metricnames.LabelOp
	labelCode                = metricnames.LabelCode
	labelExtensionPoint      = metricnames.LabelExtensionPoint
	labelKey                 = metricnames.LabelKey
	labelOutcome             = metricnames.LabelOutcome
	labelResult              = metricnames.LabelResult
	outcomeDropped           = metricnames.OutcomeDropped
	labelModule              = "module"
	labelComponent           = "component"
	labelTransport           = "transport"
	labelKind                = "kind"
	labelName                = "name"
	kindPlugin               = "plugin"
	kindLua                  = "lua"
	kindApplication          = "application"
	labelPool                = "pool"
	labelTarget              = "target"
	labelServerStatus        = "server_status"
	labelPoolName            = "pool_name"
	labelLane                = "lane"
	labelMetric              = "metric"
	serverStatusWanted       = "wanted"
	serverStatusAlive        = "alive"
	breakerStateOpen         = 1
	breakerStateHalfOpen     = 2
	targetHealthHealthyValue = 1

	// groupKeySeparator joins group label values into one ordering key.
	groupKeySeparator = "\x1f"
)

var (
	// clickHouseFlushFamilies matches the plugin's scoped flush counters of every row and event stream.
	clickHouseFlushFamilies = regexp.MustCompile("^" + metricnames.ClickHouseFlushFamilyPattern + "$")

	// clickHouseQueueFamilies matches the plugin's scoped enqueue counters of every row and event stream.
	clickHouseQueueFamilies = regexp.MustCompile("^" + metricnames.ClickHouseQueueFamilyPattern + "$")
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

	return append(findings, s.classifiedCounterFindings(supportops.ComponentLDAP, s.familySeries(familyLDAPErrors),
		[]string{labelPool, labelOp, labelCode}, classifyLDAPError)...)
}

// classifyLDAPError separates the directory's answer to a rejected user password from a directory error. The pool
// itself reads every non-transport bind error as a credential rejection, so the result code 49 of a user bind is an
// outcome about the client; every other operation and code stays a directory error.
func classifyLDAPError(labels map[string]string) string {
	if labels[labelOp] == definitions.LDAPErrorOpBind && labels[labelCode] == definitions.LDAPResultCodeInvalidCredentials {
		return supportops.SymptomLDAPBindRejected
	}

	return supportops.SymptomLDAPErrors
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
	flushes := filterSeries(s.matchingSeries(clickHouseFlushFamilies, labelMetric), labelResult, metricnames.ClickHouseFlushFailures)
	losses := filterSeries(s.matchingSeries(clickHouseQueueFamilies, labelMetric), labelResult, metricnames.ClickHouseQueueLosses)

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

// classifier maps the labels of one counter series to the symptom it raises.
type classifier func(labels map[string]string) string

// counterGroup accumulates the series of one lifetime-counter finding.
type counterGroup struct {
	labels  map[string]string
	symptom string
	total   float64
}

// counterFindings sums lifetime counters per group label (or overall for an empty label) under one symptom. A
// registered family that counted nothing answers not_observed; an absent family answers nothing, so the component
// becomes unknown.
func (s *snapshot) counterFindings(component string, input []series, groupLabel string, symptom string) []supportops.Finding {
	var groupLabels []string
	if groupLabel != "" {
		groupLabels = []string{groupLabel}
	}

	return s.classifiedCounterFindings(component, input, groupLabels, func(map[string]string) string { return symptom })
}

// classifiedCounterFindings sums lifetime counters per combination of group labels and symptom, so a classifier can
// split one family into several symptoms. Findings are ordered by their group label values.
func (s *snapshot) classifiedCounterFindings(component string, input []series, groupLabels []string, classify classifier) []supportops.Finding {
	if input == nil {
		return nil
	}

	groups := groupCounters(input, groupLabels, classify)
	if len(groups) == 0 {
		return []supportops.Finding{s.finding(component, supportops.BasisProcessLifetimeCounter, supportops.StatusNotObserved, nil)}
	}

	findings := make([]supportops.Finding, 0, len(groups))

	for _, group := range groups {
		finding := s.finding(component, supportops.BasisProcessLifetimeCounter, supportops.StatusNotObserved, group.labels)
		if total := count(group.total); total > 0 {
			finding.Status = supportops.StatusObserved
			finding.Symptoms = []supportops.Symptom{{Code: group.symptom, Count: total}}
		}

		findings = append(findings, finding)
	}

	return findings
}

// groupCounters sums the series per group label values and symptom, ordered by those values.
func groupCounters(input []series, groupLabels []string, classify classifier) []*counterGroup {
	byKey := map[string]*counterGroup{}
	keys := []string{}

	for _, entry := range input {
		symptom := classify(entry.labels)
		values := make([]string, 0, len(groupLabels))

		for _, name := range groupLabels {
			values = append(values, entry.labels[name])
		}

		key := strings.Join(values, groupKeySeparator) + groupKeySeparator + symptom

		group, seen := byKey[key]
		if !seen {
			group = &counterGroup{symptom: symptom, labels: pickLabels(entry.labels, groupLabels)}
			byKey[key] = group

			keys = append(keys, key)
		}

		group.total += entry.value
	}

	slices.SortFunc(keys, strings.Compare)

	groups := make([]*counterGroup, 0, len(keys))
	for _, key := range keys {
		groups = append(groups, byKey[key])
	}

	return groups
}

// pickLabels returns the named labels of one series; no names give no labels.
func pickLabels(labels map[string]string, names []string) map[string]string {
	if len(names) == 0 {
		return nil
	}

	picked := make(map[string]string, len(names))
	for _, name := range names {
		picked[name] = labels[name]
	}

	return picked
}

// authBackendFindings reports the runtime evidence of failing authentication backends since process start: failed
// native plugin backend calls, replaced Lua backend VMs, and unexpected authentication application errors.
func (s *snapshot) authBackendFindings() []supportops.Finding {
	return s.classifiedCounterFindings(supportops.ComponentAuthBackend, s.authBackendSeries(), []string{labelKind, labelName},
		func(labels map[string]string) string { return authBackendSymptoms[labels[labelKind]] })
}

// authBackendSymptoms maps the evidence kind of authBackendSeries to its symptom.
var authBackendSymptoms = map[string]string{
	kindPlugin:      supportops.SymptomPluginBackendCallFailures,
	kindLua:         supportops.SymptomLuaBackendVMReplaced,
	kindApplication: supportops.SymptomAuthApplicationErrors,
}

// authBackendEvidence projects the series of one counter family onto a kind/name pair; it returns false for series
// that are not backend fault evidence.
type authBackendEvidence struct {
	family  string
	kind    string
	project func(labels map[string]string) (string, bool)
}

// authBackendEvidenceTable lists the counter families behind the auth_backend component.
var authBackendEvidenceTable = []authBackendEvidence{
	{family: familyPluginCalls, kind: kindPlugin, project: pluginBackendFailure},
	{family: familyLuaVMReplaced, kind: kindLua, project: luaBackendVM},
	{family: familyAuthAppErrors, kind: kindApplication, project: func(labels map[string]string) (string, bool) {
		return labels[labelTransport], true
	}},
}

// authBackendSeries merges the evidence families into series labeled with kind and name. It is nil when none of the
// families is known, so the component answers unknown, and empty when they are known but counted nothing.
func (s *snapshot) authBackendSeries() []series {
	var merged []series

	for _, evidence := range authBackendEvidenceTable {
		input := s.familySeries(evidence.family)
		if input == nil {
			continue
		}

		if merged == nil {
			merged = []series{}
		}

		for _, entry := range input {
			if name, counts := evidence.project(entry.labels); counts {
				merged = append(merged, series{labels: map[string]string{labelKind: evidence.kind, labelName: name}, value: entry.value})
			}
		}
	}

	return merged
}

// pluginBackendFailure names the module and component of a failed native plugin backend call. Canceled calls are
// client outcomes and admission-limited calls are host capacity limits, so only these results count.
func pluginBackendFailure(labels map[string]string) (string, bool) {
	if labels[labelExtensionPoint] != metricnames.BackendExtensionPoint || !slices.Contains(metricnames.PluginFailureResults, labels[labelResult]) {
		return "", false
	}

	return labels[labelModule] + "/" + labels[labelComponent], true
}

// luaBackendVM names the pool of a replaced Lua backend VM; VM pools of other roles are not backend evidence.
func luaBackendVM(labels map[string]string) (string, bool) {
	key := labels[labelKey]

	return key, strings.HasPrefix(key, metricnames.LuaBackendPoolPrefix)
}
