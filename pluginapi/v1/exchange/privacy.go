// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package exchange

import (
	"math"
	"reflect"
	"strings"
)

const (
	// FieldPrivacyLookupState stores the privacy lookup availability state.
	FieldPrivacyLookupState = "privacy_lookup_state"
	// FieldPrivacyDetected stores the aggregate privacy detection result.
	FieldPrivacyDetected = "privacy_detected"
	// FieldPrivacyClasses stores stable matched privacy classes.
	FieldPrivacyClasses = "privacy_classes"
	// FieldPrivacyPrimaryClass stores the selected primary privacy class.
	FieldPrivacyPrimaryClass = "privacy_primary_class"
	// FieldPrivacyConfidence stores evidence confidence, not authentication risk.
	FieldPrivacyConfidence = "privacy_confidence"
	// FieldPrivacySourceAuthorities stores stable evidence authority classes.
	FieldPrivacySourceAuthorities = "privacy_source_authorities"
	// FieldPrivacyDataStale stores whether the evaluated evidence is stale.
	FieldPrivacyDataStale = "privacy_data_stale"
	// FieldPrivacyDataAgeSeconds stores the non-negative evidence age.
	FieldPrivacyDataAgeSeconds = "privacy_data_age_seconds"
	// FieldIsTorExitNode stores official Tor exit evidence.
	FieldIsTorExitNode = "is_tor_exit_node"
	// FieldIsKnownVPNExit stores known VPN exit evidence.
	FieldIsKnownVPNExit = "is_known_vpn_exit"
	// FieldIsCommunityVPNExit stores community VPN exit evidence.
	FieldIsCommunityVPNExit = "is_community_vpn_exit"
	// FieldIsPublicProxy stores public proxy evidence.
	FieldIsPublicProxy = "is_public_proxy"
	// FieldIsPrivacyRelay stores privacy relay evidence.
	FieldIsPrivacyRelay = "is_privacy_relay"
	// FieldIsHostingNetwork stores hosting or cloud network evidence.
	FieldIsHostingNetwork = "is_hosting_network"
)

var privacyBoolFields = []struct {
	field  string
	assign func(*GeoIPPrivacyAnalytics, *bool)
}{
	{FieldPrivacyDetected, func(value *GeoIPPrivacyAnalytics, result *bool) { value.Detected = result }},
	{FieldIsTorExitNode, func(value *GeoIPPrivacyAnalytics, result *bool) { value.IsTorExitNode = result }},
	{FieldIsKnownVPNExit, func(value *GeoIPPrivacyAnalytics, result *bool) { value.IsKnownVPNExit = result }},
	{FieldIsCommunityVPNExit, func(value *GeoIPPrivacyAnalytics, result *bool) { value.IsCommunityVPNExit = result }},
	{FieldIsPublicProxy, func(value *GeoIPPrivacyAnalytics, result *bool) { value.IsPublicProxy = result }},
	{FieldIsPrivacyRelay, func(value *GeoIPPrivacyAnalytics, result *bool) { value.IsPrivacyRelay = result }},
	{FieldIsHostingNetwork, func(value *GeoIPPrivacyAnalytics, result *bool) { value.IsHostingNetwork = result }},
}

// GeoIPAnalytics is a defensive typed view over standard GeoIP exchange data.
type GeoIPAnalytics struct {
	Fields          map[string]any
	Privacy         GeoIPPrivacyAnalytics
	MalformedFields []string
}

// GeoIPPrivacyAnalytics contains normalized nullable privacy evidence for analytics.
type GeoIPPrivacyAnalytics struct {
	Classes            []string
	SourceAuthorities  []string
	LookupState        string
	PrimaryClass       string
	Detected           *bool
	Confidence         *float64
	DataStale          *bool
	DataAgeSeconds     *uint64
	IsTorExitNode      *bool
	IsKnownVPNExit     *bool
	IsCommunityVPNExit *bool
	IsPublicProxy      *bool
	IsPrivacyRelay     *bool
	IsHostingNetwork   *bool
}

// GeoIPAnalytics returns exchange-first GeoIP data with policy-fact privacy fallback.
func (s Snapshot) GeoIPAnalytics() GeoIPAnalytics {
	fields := s.Map(KeyGeoIP)
	view := GeoIPAnalytics{
		Fields: fields,
		Privacy: GeoIPPrivacyAnalytics{
			Classes:           []string{},
			SourceAuthorities: []string{},
		},
	}

	view.Privacy.LookupState = s.privacyString(fields, FieldPrivacyLookupState, &view.MalformedFields)
	view.Privacy.PrimaryClass = s.privacyString(fields, FieldPrivacyPrimaryClass, &view.MalformedFields)
	view.Privacy.Classes = s.privacyStringList(fields, FieldPrivacyClasses, &view.MalformedFields)
	view.Privacy.SourceAuthorities = s.privacyStringList(fields, FieldPrivacySourceAuthorities, &view.MalformedFields)
	view.Privacy.Confidence = s.privacyFloat(fields, FieldPrivacyConfidence, &view.MalformedFields)
	view.Privacy.DataAgeSeconds = s.privacyAge(fields, FieldPrivacyDataAgeSeconds, &view.MalformedFields)
	view.Privacy.DataStale = s.privacyBool(fields, FieldPrivacyDataStale, &view.MalformedFields)

	if privacyClassificationsAvailable(view.Privacy.LookupState) {
		for _, definition := range privacyBoolFields {
			definition.assign(&view.Privacy, s.privacyBool(fields, definition.field, &view.MalformedFields))
		}
	}

	return view
}

// privacyClassificationsAvailable rejects negative claims from unavailable lookup states.
func privacyClassificationsAvailable(state string) bool {
	switch strings.TrimSpace(state) {
	case "evaluated", "stale":
		return true
	default:
		return false
	}
}

// privacyValue returns a valid runtime value or falls back to a valid GeoIP fact.
func (s Snapshot) privacyValue(fields map[string]any, field string, validate func(any) bool, malformed *[]string) (any, bool) {
	if value, exists := fields[field]; exists {
		if validate(value) {
			return value, true
		}

		addMalformedPrivacyField(malformed, field)
	}

	value, exists := s.facts["geoip"][field]
	if !exists {
		return nil, false
	}

	if !validate(value) {
		addMalformedPrivacyField(malformed, field)

		return nil, false
	}

	return value, true
}

// addMalformedPrivacyField records one bounded field name at most once.
func addMalformedPrivacyField(fields *[]string, field string) {
	for _, existing := range *fields {
		if existing == field {
			return
		}
	}

	*fields = append(*fields, field)
}

// privacyString resolves a strictly typed optional string.
func (s Snapshot) privacyString(fields map[string]any, field string, malformed *[]string) string {
	value, ok := s.privacyValue(fields, field, isString, malformed)
	if !ok {
		return ""
	}

	return strings.TrimSpace(value.(string))
}

// privacyStringList resolves, trims, and stably deduplicates a strict string list.
func (s Snapshot) privacyStringList(fields map[string]any, field string, malformed *[]string) []string {
	value, ok := s.privacyValue(fields, field, isStringList, malformed)
	if !ok {
		return []string{}
	}

	return strictStringList(value)
}

// privacyBool resolves a strictly typed nullable boolean.
func (s Snapshot) privacyBool(fields map[string]any, field string, malformed *[]string) *bool {
	value, ok := s.privacyValue(fields, field, isBool, malformed)
	if !ok {
		return nil
	}

	result := value.(bool)

	return &result
}

// privacyFloat resolves a finite nullable number.
func (s Snapshot) privacyFloat(fields map[string]any, field string, malformed *[]string) *float64 {
	value, ok := s.privacyValue(fields, field, isFiniteNumber, malformed)
	if !ok {
		return nil
	}

	result, _ := finiteNumber(value)

	return &result
}

// privacyAge resolves a non-negative integral nullable age.
func (s Snapshot) privacyAge(fields map[string]any, field string, malformed *[]string) *uint64 {
	value, ok := s.privacyValue(fields, field, isNonNegativeInteger, malformed)
	if !ok {
		return nil
	}

	result, _ := nonNegativeInteger(value)

	return &result
}

// isString reports whether a value is a string.
func isString(value any) bool {
	_, ok := value.(string)

	return ok
}

// isBool reports whether a value is a boolean.
func isBool(value any) bool {
	_, ok := value.(bool)

	return ok
}

// isStringList reports whether every list member is a string.
func isStringList(value any) bool {
	switch typed := value.(type) {
	case []string:
		return true
	case []any:
		for _, item := range typed {
			if _, ok := item.(string); !ok {
				return false
			}
		}

		return true
	default:
		return false
	}
}

// strictStringList returns stable unique non-empty strings from a validated list.
func strictStringList(value any) []string {
	result := []string{}
	seen := make(map[string]struct{})
	add := func(item string) {
		item = strings.TrimSpace(item)
		if item == "" {
			return
		}

		if _, exists := seen[item]; exists {
			return
		}

		seen[item] = struct{}{}
		result = append(result, item)
	}

	switch typed := value.(type) {
	case []string:
		for _, item := range typed {
			add(item)
		}
	case []any:
		for _, item := range typed {
			add(item.(string))
		}
	}

	return result
}

// isFiniteNumber reports whether a value is a supported finite number.
func isFiniteNumber(value any) bool {
	_, ok := finiteNumber(value)

	return ok
}

// finiteNumber converts supported numeric types without accepting strings.
func finiteNumber(value any) (float64, bool) {
	var result float64

	switch typed := value.(type) {
	case float64:
		result = typed
	case float32:
		result = float64(typed)
	case int:
		result = float64(typed)
	case int64:
		result = float64(typed)
	case int32:
		result = float64(typed)
	case uint:
		result = float64(typed)
	case uint64:
		result = float64(typed)
	case uint32:
		result = float64(typed)
	default:
		return 0, false
	}

	if math.IsNaN(result) || math.IsInf(result, 0) {
		return 0, false
	}

	return result, true
}

// isNonNegativeInteger reports whether a number can be represented as UInt64.
func isNonNegativeInteger(value any) bool {
	_, ok := nonNegativeInteger(value)

	return ok
}

// nonNegativeInteger converts supported integral numeric types without overflow.
func nonNegativeInteger(value any) (uint64, bool) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return 0, false
	}

	switch reflected.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflected.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		result := reflected.Int()
		if result >= 0 {
			return uint64(result), true
		}
	case reflect.Float32, reflect.Float64:
		result := reflected.Float()
		if !math.IsNaN(result) && !math.IsInf(result, 0) && result >= 0 && result < math.Exp2(64) && math.Trunc(result) == result {
			return uint64(result), true
		}
	}

	return 0, false
}
