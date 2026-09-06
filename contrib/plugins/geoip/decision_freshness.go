// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"fmt"
	"net/netip"
	"time"
)

const (
	factLookupState            = "lookup_state"
	factDataAge                = "data_age_seconds"
	factDataStale              = "data_stale"
	factInputIP                = "ip"
	factNetwork                = "network"
	lookupStateFresh           = "fresh"
	lookupStateStale           = "stale"
	lookupStateMissing         = "not_found"
	lookupStateUnavailable     = "unavailable"
	defaultDatabaseMaxAge      = 45 * 24 * time.Hour
	defaultDatabaseMaxStaleAge = 90 * 24 * time.Hour
)

type rawDatabaseFreshness struct {
	MaxAge      string `mapstructure:"max_age"`
	MaxStaleAge string `mapstructure:"max_stale_age"`
}

type databaseFreshness struct{ maxAge, maxStaleAge time.Duration }

// compileDatabaseFreshness bounds acceptable source age independently of reload time.
func compileDatabaseFreshness(raw rawDatabaseFreshness) (databaseFreshness, error) {
	maxAge, err := parsePositiveDefaultedDuration("freshness.max_age", raw.MaxAge, defaultDatabaseMaxAge)
	if err != nil {
		return databaseFreshness{}, err
	}

	maxStale, err := parsePositiveDefaultedDuration("freshness.max_stale_age", raw.MaxStaleAge, defaultDatabaseMaxStaleAge)
	if err != nil {
		return databaseFreshness{}, err
	}

	if maxStale < maxAge || maxStale > 365*24*time.Hour {
		return databaseFreshness{}, fmt.Errorf("freshness requires max_age <= max_stale_age <= 365d")
	}

	return databaseFreshness{maxAge: maxAge, maxStaleAge: maxStale}, nil
}

// geoIPFreshnessResult preserves exact address correlation while withholding expired geographic and ASN claims.
func geoIPFreshnessResult(result geoIPLookupResult, record geoRecord, address netip.Addr, matched bool, limits databaseFreshness, now time.Time) (geoIPLookupResult, geoRecord) {
	state, age, stale, unavailable := classifyGeoIPFreshness(record.observedAt, matched, limits, now)
	if unavailable {
		state = lookupStateUnavailable
		result = geoIPLookupResult{}
	} else if matched && record.Prefix.IsValid() && record.Prefix.Contains(address.Unmap()) {
		result.Facts = append(result.Facts, geoIPLookupFact{Name: factNetwork, Value: record.Prefix.Masked().String()})
	}

	result.Facts = append(result.Facts,
		geoIPLookupFact{Name: factLookupState, Value: state},
		geoIPLookupFact{Name: factInputIP, Value: address.Unmap().String()},
		geoIPLookupFact{Name: factDataStale, Value: stale},
	)
	if !record.observedAt.IsZero() && age >= 0 {
		result.Facts = append(result.Facts, geoIPLookupFact{Name: factDataAge, Value: int64(age / time.Second)})
	}

	if unavailable {
		record = geoRecord{}
	}

	return result, record
}

// classifyGeoIPFreshness derives a closed status from source age without granting geographic meaning to missing data.
func classifyGeoIPFreshness(observedAt time.Time, matched bool, limits databaseFreshness, now time.Time) (string, time.Duration, bool, bool) {
	if limits.maxAge == 0 {
		limits = databaseFreshness{maxAge: defaultDatabaseMaxAge, maxStaleAge: defaultDatabaseMaxStaleAge}
	}

	age := now.Sub(observedAt)

	state := lookupStateFresh
	if !matched {
		state = lookupStateMissing
	}

	stale := age > limits.maxAge
	if matched && stale {
		state = lookupStateStale
	}

	unavailable := observedAt.IsZero() || age < 0 || age > limits.maxStaleAge

	return state, age, stale, unavailable
}
