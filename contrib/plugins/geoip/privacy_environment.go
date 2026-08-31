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

	"github.com/croessner/nauthilus/v4/pluginapi/v1/exchange"
)

const (
	factPrivacyLookupState       = exchange.FieldPrivacyLookupState
	factPrivacyDetected          = exchange.FieldPrivacyDetected
	factPrivacyClasses           = exchange.FieldPrivacyClasses
	factPrivacyPrimaryClass      = exchange.FieldPrivacyPrimaryClass
	factPrivacyConfidence        = exchange.FieldPrivacyConfidence
	factPrivacySourceAuthorities = exchange.FieldPrivacySourceAuthorities
	factPrivacyDataStale         = exchange.FieldPrivacyDataStale
	factPrivacyDataAgeSeconds    = exchange.FieldPrivacyDataAgeSeconds
	factIsTorExitNode            = exchange.FieldIsTorExitNode
	factIsKnownVPNExit           = exchange.FieldIsKnownVPNExit
	factIsCommunityVPNExit       = exchange.FieldIsCommunityVPNExit
	factIsPublicProxy            = exchange.FieldIsPublicProxy
	factIsPrivacyRelay           = exchange.FieldIsPrivacyRelay
	factIsHostingNetwork         = exchange.FieldIsHostingNetwork
	factIsSharedEgress           = exchange.FieldIsSharedEgress
)

type privacyClassFact struct {
	class privacyClass
	name  string
}

var privacyClassFacts = []privacyClassFact{
	{class: privacyClassTor, name: factIsTorExitNode},
	{class: privacyClassKnownVPN, name: factIsKnownVPNExit},
	{class: privacyClassCommunityVPN, name: factIsCommunityVPNExit},
	{class: privacyClassPublicProxy, name: factIsPublicProxy},
	{class: privacyClassRelay, name: factIsPrivacyRelay},
	{class: privacyClassHosting, name: factIsHostingNetwork},
	{class: privacyClassSharedEgress, name: factIsSharedEgress},
}

// enrichPrivacyResult adds generic privacy facts to one GeoIP result.
func enrichPrivacyResult(result geoIPLookupResult, lookup privacyLookupResult) geoIPLookupResult {
	result.Facts = append(result.Facts,
		geoIPLookupFact{Name: factPrivacyLookupState, Value: lookup.State},
		geoIPLookupFact{Name: factPrivacyDataStale, Value: lookup.Stale},
	)

	if privacyClassificationsAvailable(lookup.State) {
		addPrivacyClassifications(&result, lookup)
	}

	addPrivacyEvidenceDetails(&result, lookup)

	return result
}

// privacyClassificationsAvailable reports whether false values represent a valid lookup.
func privacyClassificationsAvailable(state string) bool {
	return state == privacyLookupStateEvaluated || state == privacyLookupStateStale
}

// addPrivacyClassifications emits explicit positive or negative classification values.
func addPrivacyClassifications(result *geoIPLookupResult, lookup privacyLookupResult) {
	classes := privacyClassStrings(lookup.Classes)
	detected := slices.ContainsFunc(lookup.Classes, func(class privacyClass) bool { return class != privacyClassHosting })

	result.Facts = append(result.Facts,
		geoIPLookupFact{Name: factPrivacyDetected, Value: detected},
		geoIPLookupFact{Name: factPrivacyClasses, Value: classes},
	)

	for _, definition := range privacyClassFacts {
		matched := slices.Contains(lookup.Classes, definition.class)
		result.Facts = append(result.Facts, geoIPLookupFact{Name: definition.name, Value: matched})
	}
}

// addPrivacyEvidenceDetails emits optional values only when evidence gives them meaning.
func addPrivacyEvidenceDetails(result *geoIPLookupResult, lookup privacyLookupResult) {
	if lookup.PrimaryClass != "" {
		primaryClass := string(lookup.PrimaryClass)
		confidence := float64(lookup.Confidence)
		result.Facts = append(result.Facts,
			geoIPLookupFact{Name: factPrivacyPrimaryClass, Value: primaryClass},
			geoIPLookupFact{Name: factPrivacyConfidence, Value: confidence},
		)
	}

	if len(lookup.Authorities) == 0 {
		return
	}

	authorities := privacyAuthorityStrings(lookup.Authorities)
	ageSeconds := float64(max(lookup.DataAge/time.Second, 0))
	result.Facts = append(result.Facts,
		geoIPLookupFact{Name: factPrivacySourceAuthorities, Value: authorities},
		geoIPLookupFact{Name: factPrivacyDataAgeSeconds, Value: ageSeconds},
	)
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
