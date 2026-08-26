// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import (
	"slices"
	"strings"
	"time"
)

const conditionMaterialSeparator = "\x00"

// CompiledTimeWindow is immutable catalog-side recurring condition material.
type CompiledTimeWindow struct {
	LocationName string
	Days         []time.Weekday
	Intervals    []CompiledTimeInterval
}

// Contains reports whether one instant falls in the recurring local-time schedule.
func (w CompiledTimeWindow) Contains(instant time.Time) bool {
	location, err := time.LoadLocation(w.LocationName)
	if err != nil {
		return false
	}

	local := instant.In(location)
	if !slices.Contains(w.Days, local.Weekday()) {
		return false
	}

	minute := local.Hour()*60 + local.Minute()
	for _, interval := range w.Intervals {
		if minute >= interval.StartMinute && minute < interval.EndMinute {
			return true
		}
	}

	return false
}

// CompiledTimeInterval contains minute offsets in one local day.
type CompiledTimeInterval struct {
	StartMinute int
	EndMinute   int
}

// ConditionMaterialKey scopes one authored reference to its owning namespace.
func ConditionMaterialKey(namespace string, reference string) string {
	if namespace == "" || reference == "" || strings.Contains(namespace, conditionMaterialSeparator) ||
		strings.Contains(reference, conditionMaterialSeparator) {
		return ""
	}

	return namespace + conditionMaterialSeparator + reference
}

// Clone returns one deeply detached recurring window.
func (w CompiledTimeWindow) Clone() CompiledTimeWindow {
	w.Days = append([]time.Weekday(nil), w.Days...)
	w.Intervals = append([]CompiledTimeInterval(nil), w.Intervals...)

	return w
}
