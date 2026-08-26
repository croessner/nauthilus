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

package main

import (
	"context"
	"fmt"
	"net/netip"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	decisionInputClientIP            = "input.auth.client_ip"
	decisionOutputMaximumStringBytes = 512
	decisionOutputMaximumStrings     = 64
	decisionPolicyNamespace          = "authn"
)

var _ pluginapi.DecisionFactProvider = (*geoIPDecisionFactProvider)(nil)

// geoIPDecisionFactProvider exposes the redacted lookup as the sole generic Policy capability.
type geoIPDecisionFactProvider struct {
	plugin *Plugin
}

// Descriptor declares the exact authn targets and bounded GeoIP fact vocabulary.
func (geoIPDecisionFactProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{
		Targets:   geoIPDecisionTargets(),
		Outputs:   geoIPDecisionFactOutputs(),
		Namespace: decisionPolicyNamespace,
		Name:      componentSource,
		Timeout:   pluginapi.MaximumDecisionFactProviderTimeout,
	}
}

// Collect resolves the admitted client address through the shared GeoIP lookup path.
func (p geoIPDecisionFactProvider) Collect(
	ctx context.Context,
	request pluginapi.DecisionFactRequest,
) (pluginapi.DecisionFactResult, error) {
	if p.plugin == nil {
		return pluginapi.DecisionFactResult{}, fmt.Errorf("geoip decision provider has no plugin")
	}

	clientIP, valid := decisionClientIP(request)
	if !valid {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
	}

	result, err := (geoIPLookupService(p)).evaluateClientIP(ctx, clientIP)
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	outputs := make([]pluginapi.DecisionFactOutput, 0, len(result.Facts))
	for _, fact := range result.Facts {
		output, convertErr := geoIPDecisionFactOutput(fact)
		if convertErr != nil {
			return pluginapi.DecisionFactResult{}, convertErr
		}

		outputs = append(outputs, output)
	}

	return pluginapi.DecisionFactResult{Facts: outputs}, nil
}

// geoIPDecisionTargets returns the exact immutable generic target allowlist.
func geoIPDecisionTargets() []pluginapi.DecisionTargetSelector {
	return []pluginapi.DecisionTargetSelector{
		{Namespace: decisionPolicyNamespace, Action: "authenticate"},
		{Namespace: decisionPolicyNamespace, Action: "lookup_identity"},
	}
}

// decisionClientIP selects one correctly typed admitted fact for an allowed target.
func decisionClientIP(request pluginapi.DecisionFactRequest) (string, bool) {
	if !geoIPDecisionTargetAllowed(request.Target()) {
		return "", false
	}

	for _, fact := range request.Facts() {
		if fact.ID() != decisionInputClientIP {
			continue
		}

		if fact.Category() != pluginapi.DecisionFactCategoryEnvironment {
			return "", false
		}

		value, ok := fact.Value().StringValue()
		if !ok || value == "" {
			return "", false
		}

		if _, err := netip.ParseAddr(value); err != nil {
			return "", false
		}

		return value, true
	}

	return "", false
}

// geoIPDecisionTargetAllowed reports whether the request selects one declared target.
func geoIPDecisionTargetAllowed(target pluginapi.DecisionTargetSelector) bool {
	for _, allowed := range geoIPDecisionTargets() {
		if target == allowed {
			return true
		}
	}

	return false
}

type geoIPDecisionOutputSpec struct {
	name string
	kind pluginapi.DecisionValueKind
}

// geoIPDecisionFactOutputs returns the exact public generic fact vocabulary.
func geoIPDecisionFactOutputs() []pluginapi.DecisionFactOutputDescriptor {
	specifications := geoIPDecisionOutputSpecifications()
	outputs := make([]pluginapi.DecisionFactOutputDescriptor, 0, len(specifications))

	for _, specification := range specifications {
		outputs = append(outputs, geoIPDecisionFactOutputDescriptor(specification))
	}

	return outputs
}

// geoIPDecisionOutputSpecifications defines each local output once for lookup and descriptor construction.
func geoIPDecisionOutputSpecifications() []geoIPDecisionOutputSpec {
	return []geoIPDecisionOutputSpec{
		{name: factMatched, kind: pluginapi.DecisionValueKindBoolean},
		{name: factCountryISO, kind: pluginapi.DecisionValueKindString},
		{name: factCountryName, kind: pluginapi.DecisionValueKindString},
		{name: factCityName, kind: pluginapi.DecisionValueKindString},
		{name: factASN, kind: pluginapi.DecisionValueKindInteger},
		{name: factASNOrg, kind: pluginapi.DecisionValueKindString},
		{name: factASNPrefix, kind: pluginapi.DecisionValueKindString},
		{name: factASNRegistry, kind: pluginapi.DecisionValueKindString},
		{name: factASNCountryISO, kind: pluginapi.DecisionValueKindString},
		{name: factASNAllocated, kind: pluginapi.DecisionValueKindString},
		{name: factASNStatus, kind: pluginapi.DecisionValueKindString},
		{name: factPrivacyLookupState, kind: pluginapi.DecisionValueKindString},
		{name: factPrivacyDetected, kind: pluginapi.DecisionValueKindBoolean},
		{name: factPrivacyClasses, kind: pluginapi.DecisionValueKindStrings},
		{name: factPrivacyPrimaryClass, kind: pluginapi.DecisionValueKindString},
		{name: factPrivacyConfidence, kind: pluginapi.DecisionValueKindDouble},
		{name: factPrivacySourceAuthorities, kind: pluginapi.DecisionValueKindStrings},
		{name: factPrivacyDataStale, kind: pluginapi.DecisionValueKindBoolean},
		{name: factPrivacyDataAgeSeconds, kind: pluginapi.DecisionValueKindDouble},
		{name: factIsTorExitNode, kind: pluginapi.DecisionValueKindBoolean},
		{name: factIsKnownVPNExit, kind: pluginapi.DecisionValueKindBoolean},
		{name: factIsCommunityVPNExit, kind: pluginapi.DecisionValueKindBoolean},
		{name: factIsPublicProxy, kind: pluginapi.DecisionValueKindBoolean},
		{name: factIsPrivacyRelay, kind: pluginapi.DecisionValueKindBoolean},
		{name: factIsHostingNetwork, kind: pluginapi.DecisionValueKindBoolean},
		{name: factIsSharedEgress, kind: pluginapi.DecisionValueKindBoolean},
	}
}

// geoIPDecisionFactOutputDescriptor applies the declared bounds for one output kind.
func geoIPDecisionFactOutputDescriptor(specification geoIPDecisionOutputSpec) pluginapi.DecisionFactOutputDescriptor {
	descriptor := pluginapi.DecisionFactOutputDescriptor{
		Name:     specification.name,
		Category: pluginapi.DecisionFactCategoryEnvironment,
		Kind:     specification.kind,
	}

	switch specification.kind {
	case pluginapi.DecisionValueKindString:
		descriptor.MaxLength = decisionOutputMaximumStringBytes
	case pluginapi.DecisionValueKindStrings:
		descriptor.MaxLength = decisionOutputMaximumStringBytes
		descriptor.MaxItems = decisionOutputMaximumStrings
	}

	return descriptor
}

// geoIPDecisionFactOutput converts one local lookup fact without retaining mutable values.
func geoIPDecisionFactOutput(fact geoIPLookupFact) (pluginapi.DecisionFactOutput, error) {
	value, err := geoIPDecisionValue(fact.Value)
	if err != nil {
		return pluginapi.DecisionFactOutput{}, fmt.Errorf("geoip fact %q: %w", fact.Name, err)
	}

	return pluginapi.DecisionFactOutput{Name: fact.Name, Value: value}, nil
}

// geoIPDecisionValue converts the closed set emitted by the shared lookup implementation.
func geoIPDecisionValue(value any) (pluginapi.DecisionValue, error) {
	switch typed := value.(type) {
	case string:
		if len(typed) > decisionOutputMaximumStringBytes {
			return pluginapi.DecisionValue{}, fmt.Errorf(
				"string exceeds generic output bound of %d bytes",
				decisionOutputMaximumStringBytes,
			)
		}

		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &typed})
	case bool:
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Boolean: &typed})
	case int:
		integer := int64(typed)

		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Integer: &integer})
	case int64:
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Integer: &typed})
	case float64:
		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Double: &typed})
	case []string:
		if err := validateGeoIPDecisionStrings(typed); err != nil {
			return pluginapi.DecisionValue{}, err
		}

		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Strings: typed})
	default:
		return pluginapi.DecisionValue{}, fmt.Errorf("unsupported generic value type %T", value)
	}
}

// validateGeoIPDecisionStrings rejects list values outside the declared generic bounds.
func validateGeoIPDecisionStrings(values []string) error {
	if len(values) > decisionOutputMaximumStrings {
		return fmt.Errorf("string list exceeds generic output bound of %d items", decisionOutputMaximumStrings)
	}

	for _, value := range values {
		if len(value) > decisionOutputMaximumStringBytes {
			return fmt.Errorf(
				"string list member exceeds generic output bound of %d bytes",
				decisionOutputMaximumStringBytes,
			)
		}
	}

	return nil
}
