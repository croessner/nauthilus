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

package prometheussource

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/metricnames"
)

// nameLabel is the PromQL label that holds the metric name.
const nameLabel = "__name__"

// profileEntry binds one symptom to the counter series that raise it. The selectors must be disjoint, so summing
// their increases never counts a series twice.
type profileEntry struct {
	component string
	symptom   string
	selectors []seriesSelector
}

// query returns the instant query that sums the increase of the entry's series per instance over a window.
func (e profileEntry) query(instanceLabel string, fixed []string) func(int64) string {
	return func(rangeSeconds int64) string {
		increases := make([]string, 0, len(e.selectors))

		for _, selector := range e.selectors {
			increases = append(increases, fmt.Sprintf("increase(%s[%ds])", selector.render(fixed), rangeSeconds))
		}

		return fmt.Sprintf("sum by (%s) (%s)", instanceLabel, strings.Join(increases, " or "))
	}
}

// diagnosticsProfile is the compiled nauthilus_diagnostics query profile, the windowed counterpart of the runtime
// source rules: the same families and the same classification, summed per instance over the requested window.
var diagnosticsProfile = []profileEntry{
	{supportops.ComponentLDAP, supportops.SymptomLDAPBindRejected, []seriesSelector{
		{name: metricnames.LDAPErrors, matchers: []string{
			equal(metricnames.LabelOp, definitions.LDAPErrorOpBind),
			equal(metricnames.LabelCode, definitions.LDAPResultCodeInvalidCredentials)}}}},
	{supportops.ComponentLDAP, supportops.SymptomLDAPErrors, []seriesSelector{
		{name: metricnames.LDAPErrors, matchers: []string{notEqual(metricnames.LabelOp, definitions.LDAPErrorOpBind)}},
		{name: metricnames.LDAPErrors, matchers: []string{
			equal(metricnames.LabelOp, definitions.LDAPErrorOpBind),
			notEqual(metricnames.LabelCode, definitions.LDAPResultCodeInvalidCredentials)}}}},
	{supportops.ComponentAuthBackend, supportops.SymptomPluginBackendCallFailures, []seriesSelector{
		{name: metricnames.PluginCalls, matchers: []string{
			equal(metricnames.LabelExtensionPoint, metricnames.BackendExtensionPoint),
			anyOf(metricnames.LabelResult, metricnames.PluginFailureResults...)}}}},
	{supportops.ComponentAuthBackend, supportops.SymptomLuaBackendVMReplaced, []seriesSelector{
		{name: metricnames.LuaVMReplaced, matchers: []string{
			metricnames.LabelKey + "=~" + strconv.Quote(regexp.QuoteMeta(metricnames.LuaBackendPoolPrefix)+".+")}}}},
	{supportops.ComponentAuthBackend, supportops.SymptomAuthApplicationErrors, []seriesSelector{
		{name: metricnames.AuthApplicationErrors, matchers: []string{}}}},
	{supportops.ComponentRedis, supportops.SymptomRedisPoolTimeouts, []seriesSelector{
		{name: metricnames.RedisTimeouts, matchers: []string{}}}},
	{supportops.ComponentAuthEventDelivery, supportops.SymptomAuthEventsDropped, []seriesSelector{
		{name: metricnames.AuthEvents, matchers: []string{equal(metricnames.LabelOutcome, metricnames.OutcomeDropped)}}}},
	{supportops.ComponentClickHouseExport, supportops.SymptomClickHouseFlushFailed, []seriesSelector{
		{matchers: []string{
			nameMatching(metricnames.ClickHouseFlushFamilyPattern),
			anyOf(metricnames.LabelResult, metricnames.ClickHouseFlushFailures...)}}}},
	{supportops.ComponentClickHouseExport, supportops.SymptomClickHouseRowsDropped, []seriesSelector{
		{matchers: []string{
			nameMatching(metricnames.ClickHouseQueueFamilyPattern),
			anyOf(metricnames.LabelResult, metricnames.ClickHouseQueueLosses...)}}}},
	{supportops.ComponentPolicy, supportops.SymptomPolicyTechnicalErrors, []seriesSelector{
		{name: metricnames.PolicyTechnical, matchers: []string{}}}},
}

// notEqual renders an inequality matcher.
func notEqual(label string, value string) string {
	return label + "!=" + strconv.Quote(value)
}

// anyOf renders a regular-expression matcher that accepts exactly the listed values. PromQL anchors it.
func anyOf(label string, values ...string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, regexp.QuoteMeta(value))
	}

	return label + "=~" + strconv.Quote(strings.Join(quoted, "|"))
}

// nameMatching renders a matcher on the metric name from an unanchored RE2 pattern. PromQL anchors it.
func nameMatching(pattern string) string {
	return nameLabel + "=~" + strconv.Quote(pattern)
}
