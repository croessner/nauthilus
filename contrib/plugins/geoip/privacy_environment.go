// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"slices"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
)

const (
	factPrivacyLookupState       = "plugin.environment.geoip." + exchange.FieldPrivacyLookupState
	factPrivacyDetected          = "plugin.environment.geoip." + exchange.FieldPrivacyDetected
	factPrivacyClasses           = "plugin.environment.geoip." + exchange.FieldPrivacyClasses
	factPrivacyPrimaryClass      = "plugin.environment.geoip." + exchange.FieldPrivacyPrimaryClass
	factPrivacyConfidence        = "plugin.environment.geoip." + exchange.FieldPrivacyConfidence
	factPrivacySourceAuthorities = "plugin.environment.geoip." + exchange.FieldPrivacySourceAuthorities
	factPrivacyDataStale         = "plugin.environment.geoip." + exchange.FieldPrivacyDataStale
	factPrivacyDataAgeSeconds    = "plugin.environment.geoip." + exchange.FieldPrivacyDataAgeSeconds
	factIsTorExitNode            = "plugin.environment.geoip." + exchange.FieldIsTorExitNode
	factIsKnownVPNExit           = "plugin.environment.geoip." + exchange.FieldIsKnownVPNExit
	factIsCommunityVPNExit       = "plugin.environment.geoip." + exchange.FieldIsCommunityVPNExit
	factIsPublicProxy            = "plugin.environment.geoip." + exchange.FieldIsPublicProxy
	factIsPrivacyRelay           = "plugin.environment.geoip." + exchange.FieldIsPrivacyRelay
	factIsHostingNetwork         = "plugin.environment.geoip." + exchange.FieldIsHostingNetwork
)

type privacyClassFact struct {
	class     privacyClass
	attribute string
	key       string
}

var privacyClassFacts = []privacyClassFact{
	{class: privacyClassTor, attribute: factIsTorExitNode, key: exchange.FieldIsTorExitNode},
	{class: privacyClassKnownVPN, attribute: factIsKnownVPNExit, key: exchange.FieldIsKnownVPNExit},
	{class: privacyClassCommunityVPN, attribute: factIsCommunityVPNExit, key: exchange.FieldIsCommunityVPNExit},
	{class: privacyClassPublicProxy, attribute: factIsPublicProxy, key: exchange.FieldIsPublicProxy},
	{class: privacyClassRelay, attribute: factIsPrivacyRelay, key: exchange.FieldIsPrivacyRelay},
	{class: privacyClassHosting, attribute: factIsHostingNetwork, key: exchange.FieldIsHostingNetwork},
}

// enrichPrivacyResult adds privacy facts, public fields, and exchange values to one GeoIP result.
func enrichPrivacyResult(result pluginapi.EnvironmentResult, lookup privacyLookupResult, publicLogs bool) pluginapi.EnvironmentResult {
	values := privacyRuntimeValues(result)
	values[exchange.FieldPrivacyLookupState] = lookup.State
	values[exchange.FieldPrivacyDataStale] = lookup.Stale
	result.Facts = append(result.Facts,
		pluginapi.PolicyFact{Attribute: factPrivacyLookupState, Value: lookup.State},
		pluginapi.PolicyFact{Attribute: factPrivacyDataStale, Value: lookup.Stale},
	)

	if privacyClassificationsAvailable(lookup.State) {
		addPrivacyClassifications(&result, values, lookup)
	}

	addPrivacyEvidenceDetails(&result, values, lookup)
	result.RuntimeDelta = exchange.GeoIPRuntimeDelta(values)

	if publicLogs {
		result.Logs = append(result.Logs, publicPrivacyLogFields(lookup)...)
	}

	return result
}

// privacyRuntimeValues copies the existing GeoIP exchange map before extending it.
func privacyRuntimeValues(result pluginapi.EnvironmentResult) map[string]any {
	if result.RuntimeDelta.Set == nil {
		return make(map[string]any)
	}

	values, _ := result.RuntimeDelta.Set[exchange.KeyGeoIP].(map[string]any)

	return exchange.GeoIPValue(values)
}

// privacyClassificationsAvailable reports whether false values represent a valid lookup.
func privacyClassificationsAvailable(state string) bool {
	return state == privacyLookupStateEvaluated || state == privacyLookupStateStale
}

// addPrivacyClassifications emits explicit positive or negative classification values.
func addPrivacyClassifications(result *pluginapi.EnvironmentResult, values map[string]any, lookup privacyLookupResult) {
	classes := privacyClassStrings(lookup.Classes)
	detected := slices.ContainsFunc(lookup.Classes, func(class privacyClass) bool { return class != privacyClassHosting })

	result.Facts = append(result.Facts,
		pluginapi.PolicyFact{Attribute: factPrivacyDetected, Value: detected},
		pluginapi.PolicyFact{Attribute: factPrivacyClasses, Value: classes},
	)
	values[exchange.FieldPrivacyDetected] = detected
	values[exchange.FieldPrivacyClasses] = classes

	for _, definition := range privacyClassFacts {
		matched := slices.Contains(lookup.Classes, definition.class)
		result.Facts = append(result.Facts, pluginapi.PolicyFact{Attribute: definition.attribute, Value: matched})
		values[definition.key] = matched
	}
}

// addPrivacyEvidenceDetails emits optional values only when evidence gives them meaning.
func addPrivacyEvidenceDetails(result *pluginapi.EnvironmentResult, values map[string]any, lookup privacyLookupResult) {
	if lookup.PrimaryClass != "" {
		primaryClass := string(lookup.PrimaryClass)
		confidence := float64(lookup.Confidence)
		result.Facts = append(result.Facts,
			pluginapi.PolicyFact{Attribute: factPrivacyPrimaryClass, Value: primaryClass},
			pluginapi.PolicyFact{Attribute: factPrivacyConfidence, Value: confidence},
		)
		values[exchange.FieldPrivacyPrimaryClass] = primaryClass
		values[exchange.FieldPrivacyConfidence] = confidence
	}

	if len(lookup.Authorities) == 0 {
		return
	}

	authorities := privacyAuthorityStrings(lookup.Authorities)
	ageSeconds := float64(max(lookup.DataAge/time.Second, 0))
	result.Facts = append(result.Facts,
		pluginapi.PolicyFact{Attribute: factPrivacySourceAuthorities, Value: authorities},
		pluginapi.PolicyFact{Attribute: factPrivacyDataAgeSeconds, Value: ageSeconds},
	)
	values[exchange.FieldPrivacySourceAuthorities] = authorities
	values[exchange.FieldPrivacyDataAgeSeconds] = ageSeconds
}

// publicPrivacyLogFields returns only the approved bounded central log surface.
func publicPrivacyLogFields(lookup privacyLookupResult) []pluginapi.LogField {
	fields := make([]pluginapi.LogField, 0, 7)
	if !privacyClassificationsAvailable(lookup.State) {
		return fields
	}

	addPublicGeoIPLogField(&fields, exchange.FieldPrivacyPrimaryClass, string(lookup.PrimaryClass))

	if lookup.PrimaryClass != "" {
		addPublicGeoIPLogField(&fields, exchange.FieldPrivacyConfidence, float64(lookup.Confidence))
	}

	addPublicGeoIPLogField(&fields, exchange.FieldPrivacyDataStale, lookup.Stale)

	for _, definition := range privacyClassFacts {
		if definition.class == privacyClassCommunityVPN || definition.class == privacyClassRelay {
			continue
		}

		addPublicGeoIPLogField(&fields, definition.key, slices.Contains(lookup.Classes, definition.class))
	}

	return fields
}

// privacyClassStrings converts stable internal class enums to policy-safe strings.
func privacyClassStrings(classes []privacyClass) []string {
	values := make([]string, len(classes))
	for index, class := range classes {
		values[index] = string(class)
	}

	return values
}

// privacyAuthorityStrings converts stable authority enums to policy-safe strings.
func privacyAuthorityStrings(authorities []privacyAuthority) []string {
	values := make([]string, len(authorities))
	for index, authority := range authorities {
		values[index] = string(authority)
	}

	return values
}
