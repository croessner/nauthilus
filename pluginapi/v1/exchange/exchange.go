// Copyright (C) 2026 Christian Roessner
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

// Package exchange defines the public runtime exchange keyspace shared by
// Nauthilus plugins.
package exchange

import (
	"fmt"
	"sort"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	// Prefix is the top-level runtime key prefix for standard exchange values.
	Prefix = "plugin.exchange."

	// KeyDecisionSources stores stable analytics source names selected by policy-aware components.
	KeyDecisionSources = Prefix + "decision_sources"

	// KeyFeaturePrefix is the prefix for standard feature-marker runtime keys.
	KeyFeaturePrefix = Prefix + "feature."

	// KeyGeoIP stores GeoIP and ASN enrichment fields.
	KeyGeoIP = Prefix + "geoip"

	// KeyGeoIPReputation stores reputation scores and decision hints.
	KeyGeoIPReputation = Prefix + "geoip_reputation"

	// KeyFailedLoginHotspot stores failed-login hotspot counters.
	KeyFailedLoginHotspot = Prefix + "failed_login_hotspot"

	// KeyAccountProtection stores account-protection state.
	KeyAccountProtection = Prefix + "account_protection"

	// KeyGlobalPattern stores global pattern counters.
	KeyGlobalPattern = Prefix + "global_pattern"

	// KeyDynamicResponse stores dynamic response diagnostics.
	KeyDynamicResponse = Prefix + "dynamic_response"

	// KeyHaveIBeenPwned stores safe Have I Been Pwned result fields.
	KeyHaveIBeenPwned = Prefix + "haveibeenpwnd"
)

const (
	// FeatureBlocklist identifies external blocklist policy decisions.
	FeatureBlocklist = "blocklist"

	// FeatureGeoIPPolicy identifies delegated GeoIP policy decisions.
	FeatureGeoIPPolicy = "geoip_policyd"

	// FeatureFailedLoginHotspot identifies failed-login hotspot decisions.
	FeatureFailedLoginHotspot = "failed_login_hotspot"

	// FeatureAccountProtection identifies account-protection policy decisions.
	FeatureAccountProtection = "account_protection"

	// FeatureGeoIPReputation identifies reputation-based GeoIP decisions.
	FeatureGeoIPReputation = "geoip_reputation"

	// FeatureGlobalPattern identifies global-pattern policy decisions.
	FeatureGlobalPattern = "global_pattern"

	// FeatureDynamicResponse identifies dynamic response decisions.
	FeatureDynamicResponse = "dynamic_response"

	// FeatureHaveIBeenPwned identifies Have I Been Pwned decisions.
	FeatureHaveIBeenPwned = "haveibeenpwnd"
)

const (
	// FieldTriggered marks a feature marker as contributing to the selected decision.
	FieldTriggered = "triggered"

	// FieldDecision stores a bounded decision hint such as "suspicious".
	FieldDecision = "decision"

	// FieldSource stores a low-cardinality producer or data-source name.
	FieldSource = "source"

	// FieldReason stores an optional bounded reason string.
	FieldReason = "reason"

	// FieldHashInfo stores the HIBP short prefix/count value used by analytics.
	FieldHashInfo = "hash_info"

	// FieldLeaked stores whether HIBP reported a leaked password hash.
	FieldLeaked = "leaked"

	// FieldCount stores a non-negative HIBP leak count.
	FieldCount = "count"
)

const (
	factPrefixLuaPlugin = "lua.plugin."
	factPrefixPlugin    = "plugin."
)

var featureOrder = []string{
	FeatureBlocklist,
	FeatureGeoIPPolicy,
	FeatureFailedLoginHotspot,
	FeatureAccountProtection,
	FeatureGeoIPReputation,
	FeatureGlobalPattern,
	FeatureDynamicResponse,
	FeatureHaveIBeenPwned,
}

// FeatureMarker describes one standard feature marker value.
type FeatureMarker struct {
	Triggered bool
	Decision  string
	Source    string
	Reason    string
}

// HIBPResult contains secret-safe Have I Been Pwned exchange fields.
type HIBPResult struct {
	HashInfo string
	Leaked   *bool
	Count    *uint64
}

// Snapshot is a read-only view over standard exchange runtime values and policy facts.
type Snapshot struct {
	values map[string]any
	facts  map[string]map[string]any
}

// FeatureKey returns the standard runtime key for a feature marker.
func FeatureKey(name string) string {
	return KeyFeaturePrefix + strings.TrimSpace(name)
}

// FeatureMarkerValue builds a JSON-compatible feature-marker map.
func FeatureMarkerValue(marker FeatureMarker) map[string]any {
	value := make(map[string]any, 4)
	if marker.Triggered {
		value[FieldTriggered] = true
	}

	setStringField(value, FieldDecision, marker.Decision)
	setStringField(value, FieldSource, marker.Source)
	setStringField(value, FieldReason, marker.Reason)

	return value
}

// FeatureRuntimeDelta builds a runtime delta for one feature marker.
func FeatureRuntimeDelta(name string, marker FeatureMarker) pluginapi.RuntimeDelta {
	featureName := strings.TrimSpace(name)
	if featureName == "" {
		return pluginapi.RuntimeDelta{}
	}

	return runtimeDelta(FeatureKey(featureName), FeatureMarkerValue(marker))
}

// HIBPValue builds a JSON-compatible HIBP exchange map.
func HIBPValue(result HIBPResult) map[string]any {
	value := make(map[string]any, 3)
	setStringField(value, FieldHashInfo, result.HashInfo)

	if result.Leaked != nil {
		value[FieldLeaked] = *result.Leaked
	}

	if result.Count != nil {
		value[FieldCount] = *result.Count
	}

	return value
}

// HIBPRuntimeDelta builds a runtime delta for HIBP exchange data.
func HIBPRuntimeDelta(result HIBPResult) pluginapi.RuntimeDelta {
	return runtimeDelta(KeyHaveIBeenPwned, HIBPValue(result))
}

// GeoIPValue returns a defensive copy of GeoIP exchange fields.
func GeoIPValue(fields map[string]any) map[string]any {
	return cloneMap(fields)
}

// GeoIPRuntimeDelta builds a runtime delta for GeoIP exchange data.
func GeoIPRuntimeDelta(fields map[string]any) pluginapi.RuntimeDelta {
	return runtimeDelta(KeyGeoIP, GeoIPValue(fields))
}

// GeoIPReputationValue returns a defensive copy of GeoIP reputation exchange fields.
func GeoIPReputationValue(fields map[string]any) map[string]any {
	return cloneMap(fields)
}

// GeoIPReputationRuntimeDelta builds a runtime delta for GeoIP reputation exchange data.
func GeoIPReputationRuntimeDelta(fields map[string]any) pluginapi.RuntimeDelta {
	return runtimeDelta(KeyGeoIPReputation, GeoIPReputationValue(fields))
}

// NewSnapshot builds a standard exchange view from a runtime context and policy facts.
func NewSnapshot(runtime pluginapi.RuntimeContext, facts []pluginapi.PolicyFact) Snapshot {
	values := map[string]any{}
	if runtime != nil {
		values = runtime.Snapshot()
	}

	return NewSnapshotFromValues(values, facts)
}

// NewSnapshotFromValues builds a standard exchange view from raw runtime values.
func NewSnapshotFromValues(values map[string]any, facts []pluginapi.PolicyFact) Snapshot {
	return Snapshot{
		values: cloneMap(values),
		facts:  factsByNamespace(facts),
	}
}

// Value returns one cloned runtime value.
func (s Snapshot) Value(key string) any {
	return cloneValue(s.values[key])
}

// Map returns one standard exchange map value.
func (s Snapshot) Map(key string) map[string]any {
	return MapValue(s.values[key])
}

// HIBPHashInfo returns the standard HIBP short hash information for analytics.
func (s Snapshot) HIBPHashInfo() string {
	return StringValue(s.Map(KeyHaveIBeenPwned)[FieldHashInfo])
}

// GeoIPReputation returns exchange reputation data or policy-fact fallback data.
func (s Snapshot) GeoIPReputation() map[string]any {
	if values := s.Map(KeyGeoIPReputation); len(values) > 0 {
		return values
	}

	return cloneMap(s.facts[FeatureGeoIPReputation])
}

// DecisionSources returns deterministic, deduplicated analytics source names.
func (s Snapshot) DecisionSources() []string {
	collector := sourceCollector{}
	collector.addAll(StringList(s.values[KeyDecisionSources]))
	s.addFeatureMarkerSources(&collector)
	s.addExchangeMapSources(&collector)
	s.addPolicyFactSources(&collector)

	return collector.values
}

// DecisionSourcesString returns DecisionSources joined for analytics row fields.
func (s Snapshot) DecisionSourcesString() string {
	return strings.Join(s.DecisionSources(), ",")
}

// MapValue returns a defensive string-keyed map copy when value is map-like.
func MapValue(value any) map[string]any {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		return cloneMap(typed)
	case map[string]string:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			result[key] = nested
		}

		return result
	case map[string]bool:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			result[key] = nested
		}

		return result
	default:
		return nil
	}
}

// StringValue converts scalar optional values to strings.
func StringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

// StringList normalizes string-list exchange values with deterministic map ordering.
func StringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return cleanStringList(typed)
	case []any:
		return stringListFromAnySlice(typed)
	case map[string]any:
		return stringListFromAnyMap(typed)
	case map[string]bool:
		return stringListFromBoolMap(typed)
	default:
		return nil
	}
}

// stringListFromAnySlice normalizes arbitrary list items into trimmed strings.
func stringListFromAnySlice(values []any) []string {
	result := make([]string, 0, len(values))

	for _, item := range values {
		if text := strings.TrimSpace(StringValue(item)); text != "" {
			result = append(result, text)
		}
	}

	return result
}

// stringListFromAnyMap returns sorted keys whose exchange values are truthy.
func stringListFromAnyMap(values map[string]any) []string {
	result := make([]string, 0, len(values))

	for key, enabled := range values {
		if !Truthy(enabled) {
			continue
		}

		if text := strings.TrimSpace(key); text != "" {
			result = append(result, text)
		}
	}

	sort.Strings(result)

	return result
}

// stringListFromBoolMap returns sorted keys whose boolean value is true.
func stringListFromBoolMap(values map[string]bool) []string {
	result := make([]string, 0, len(values))

	for key, enabled := range values {
		if !enabled {
			continue
		}

		if text := strings.TrimSpace(key); text != "" {
			result = append(result, text)
		}
	}

	sort.Strings(result)

	return result
}

// Truthy reports whether a runtime or fact value is true.
func Truthy(value any) bool {
	result, ok := boolFromAny(value)

	return ok && result
}

// runtimeDelta returns one standard exchange delta or an empty delta.
func runtimeDelta(key string, value map[string]any) pluginapi.RuntimeDelta {
	if !strings.HasPrefix(key, Prefix) || len(value) == 0 {
		return pluginapi.RuntimeDelta{}
	}

	return pluginapi.RuntimeDelta{
		Set: map[string]any{
			key: value,
		},
	}
}

// addFeatureMarkerSources collects triggered standard feature markers.
func (s Snapshot) addFeatureMarkerSources(collector *sourceCollector) {
	names := s.featureMarkerNames()
	for _, name := range names {
		if Truthy(s.Map(FeatureKey(name))[FieldTriggered]) {
			collector.add(name)
		}
	}
}

// addExchangeMapSources collects source names implied by standard exchange maps.
func (s Snapshot) addExchangeMapSources(collector *sourceCollector) {
	if Truthy(s.Map(KeyGeoIP)["rejected"]) {
		collector.add(FeatureGeoIPPolicy)
	}

	if Truthy(s.Map(KeyFailedLoginHotspot)[FieldTriggered]) {
		collector.add(FeatureFailedLoginHotspot)
	}

	if Truthy(s.Map(KeyAccountProtection)["active"]) {
		collector.add(FeatureAccountProtection)
	}

	if reputationDecisionTriggersSource(s.Map(KeyGeoIPReputation)) {
		collector.add(FeatureGeoIPReputation)
	}
}

// addPolicyFactSources maps policy facts into analytics source names.
func (s Snapshot) addPolicyFactSources(collector *sourceCollector) {
	if Truthy(s.facts[FeatureBlocklist]["matched"]) {
		collector.add(FeatureBlocklist)
	}

	if Truthy(s.facts["geoip"]["rejected"]) {
		collector.add(FeatureGeoIPPolicy)
	}

	if Truthy(s.facts[FeatureFailedLoginHotspot][FieldTriggered]) {
		collector.add(FeatureFailedLoginHotspot)
	}

	if Truthy(s.facts[FeatureAccountProtection]["active"]) {
		collector.add(FeatureAccountProtection)
	}

	if reputationDecisionTriggersSource(s.facts[FeatureGeoIPReputation]) {
		collector.add(FeatureGeoIPReputation)
	}
}

// featureMarkerNames returns standard feature marker names in deterministic order.
func (s Snapshot) featureMarkerNames() []string {
	found := make(map[string]struct{})

	for key := range s.values {
		if !strings.HasPrefix(key, KeyFeaturePrefix) {
			continue
		}

		name := strings.TrimSpace(strings.TrimPrefix(key, KeyFeaturePrefix))
		if name != "" {
			found[name] = struct{}{}
		}
	}

	return orderedFeatureNames(found)
}

// factsByNamespace groups Lua and native plugin policy facts by feature namespace.
func factsByNamespace(facts []pluginapi.PolicyFact) map[string]map[string]any {
	result := make(map[string]map[string]any)

	for _, fact := range facts {
		namespace, key, ok := factNamespaceKey(fact.Attribute)
		if !ok {
			continue
		}

		if result[namespace] == nil {
			result[namespace] = make(map[string]any)
		}

		result[namespace][key] = fact.Value
	}

	return result
}

// factNamespaceKey extracts feature namespace and field from known fact IDs.
func factNamespaceKey(attribute string) (string, string, bool) {
	attribute = strings.TrimSpace(attribute)
	if strings.HasPrefix(attribute, factPrefixLuaPlugin) {
		return namespaceAfterPrefix(attribute, factPrefixLuaPlugin)
	}

	if strings.HasPrefix(attribute, factPrefixPlugin) {
		return namespaceAfterNativeProducer(attribute)
	}

	return "", "", false
}

// namespaceAfterPrefix extracts namespace and field after a static prefix.
func namespaceAfterPrefix(attribute string, prefix string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(attribute, prefix), ".")
	if len(parts) < 2 {
		return "", "", false
	}

	return parts[0], strings.Join(parts[1:], "."), true
}

// namespaceAfterNativeProducer extracts namespace and field after plugin.<producer>.
func namespaceAfterNativeProducer(attribute string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(attribute, factPrefixPlugin), ".")
	if len(parts) < 3 {
		return "", "", false
	}

	return parts[1], strings.Join(parts[2:], "."), true
}

// reputationDecisionTriggersSource reports whether reputation caused a suspicious decision.
func reputationDecisionTriggersSource(values map[string]any) bool {
	return strings.EqualFold(strings.TrimSpace(StringValue(values[FieldDecision])), "suspicious")
}

// setStringField stores a trimmed non-empty string field.
func setStringField(target map[string]any, key string, value string) {
	if text := strings.TrimSpace(value); text != "" {
		target[key] = text
	}
}

// cleanStringList trims empty values while preserving order.
func cleanStringList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text := strings.TrimSpace(value); text != "" {
			result = append(result, text)
		}
	}

	return result
}

// orderedFeatureNames sorts known features by standard order and unknown features lexically.
func orderedFeatureNames(found map[string]struct{}) []string {
	if len(found) == 0 {
		return nil
	}

	result := make([]string, 0, len(found))
	for _, name := range featureOrder {
		if _, ok := found[name]; !ok {
			continue
		}

		result = append(result, name)
		delete(found, name)
	}

	unknown := make([]string, 0, len(found))
	for name := range found {
		unknown = append(unknown, name)
	}

	sort.Strings(unknown)

	return append(result, unknown...)
}

// cloneMap returns a deep copy of supported runtime maps.
func cloneMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = cloneValue(value)
	}

	return cloned
}

// cloneValue returns a deep copy of supported runtime container values.
func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneValue(item)
		}

		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}

// boolFromAny converts bool-like runtime values.
func boolFromAny(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true":
			return true, true
		case "false":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

type sourceCollector struct {
	values []string
}

// addAll appends source names while preserving first-seen order.
func (c *sourceCollector) addAll(values []string) {
	for _, value := range values {
		c.add(value)
	}
}

// add appends one source name unless it was already seen.
func (c *sourceCollector) add(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}

	for _, existing := range c.values {
		if existing == value {
			return
		}
	}

	c.values = append(c.values, value)
}
