// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// PrepareConditionMaterial compiles namespace-scoped set operands and time windows for one generation.
func PrepareConditionMaterial(
	configured policyconfig.PolicyConfig,
) (map[string][]decision.Value, map[string]policyruntime.CompiledTimeWindow, error) {
	document := policyconfig.Normalize(policyconfig.Document{Policy: configured})
	if err := policyconfig.Validate(document); err != nil {
		return nil, nil, fmt.Errorf("prepare Policy condition material: %w", err)
	}

	sets := make(map[string][]decision.Value)
	windows := make(map[string]policyruntime.CompiledTimeWindow)

	for _, namespace := range sortedKeys(document.Policy.Namespaces) {
		configuredSets := document.Policy.Namespaces[namespace].ConditionSets

		if err := addConditionValueSets(sets, namespace, "@string.", configuredSets.Strings); err != nil {
			return nil, nil, err
		}

		if err := addConditionValueSets(sets, namespace, "@network.", configuredSets.Networks); err != nil {
			return nil, nil, err
		}

		for _, name := range sortedKeys(configuredSets.TimeWindows) {
			window, err := compileConditionTimeWindow(configuredSets.TimeWindows[name])
			if err != nil {
				return nil, nil, fmt.Errorf("prepare time window %s/%s: %w", namespace, name, err)
			}

			key := policyruntime.ConditionMaterialKey(namespace, "@time_window."+name)
			if key == "" {
				return nil, nil, fmt.Errorf("prepare time window %s/%s: invalid identity", namespace, name)
			}

			windows[key] = window
		}
	}

	return sets, windows, nil
}

// addConditionValueSets compiles one typed string-backed condition-set family.
func addConditionValueSets(
	result map[string][]decision.Value,
	namespace string,
	prefix string,
	configured map[string][]string,
) error {
	for _, name := range sortedKeys(configured) {
		key := policyruntime.ConditionMaterialKey(namespace, prefix+name)
		if key == "" {
			return fmt.Errorf("prepare condition set %s/%s: invalid identity", namespace, name)
		}

		values := make([]decision.Value, 0, len(configured[name]))
		for _, configuredValue := range configured[name] {
			value := configuredValue

			compiled, err := decision.NewValue(decision.ValueInput{String: &value})
			if err != nil {
				return fmt.Errorf("prepare condition set %s/%s: %w", namespace, name, err)
			}

			values = append(values, compiled)
		}

		result[key] = values
	}

	return nil
}

// compileConditionTimeWindow converts one validated authored schedule into minute offsets.
func compileConditionTimeWindow(
	configured policyconfig.TimeWindowConfig,
) (policyruntime.CompiledTimeWindow, error) {
	days := make([]time.Weekday, 0, len(configured.Days))
	for _, day := range configured.Days {
		weekday, ok := conditionWeekday(day)
		if !ok {
			return policyruntime.CompiledTimeWindow{}, fmt.Errorf("invalid weekday %q", day)
		}

		days = append(days, weekday)
	}

	intervals := make([]policyruntime.CompiledTimeInterval, 0, len(configured.Intervals))
	for _, interval := range configured.Intervals {
		start, err := conditionClockMinute(interval.Start)
		if err != nil {
			return policyruntime.CompiledTimeWindow{}, err
		}

		end, err := conditionClockMinute(interval.End)
		if err != nil || end <= start {
			return policyruntime.CompiledTimeWindow{}, fmt.Errorf("invalid time interval")
		}

		intervals = append(intervals, policyruntime.CompiledTimeInterval{
			StartMinute: start,
			EndMinute:   end,
		})
	}

	return policyruntime.CompiledTimeWindow{
		LocationName: configured.Timezone,
		Days:         days,
		Intervals:    intervals,
	}, nil
}

// conditionWeekday maps the validated authored abbreviation to time.Weekday.
func conditionWeekday(input string) (time.Weekday, bool) {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "sun":
		return time.Sunday, true
	case "mon":
		return time.Monday, true
	case "tue":
		return time.Tuesday, true
	case "wed":
		return time.Wednesday, true
	case "thu":
		return time.Thursday, true
	case "fri":
		return time.Friday, true
	case "sat":
		return time.Saturday, true
	default:
		return 0, false
	}
}

// conditionClockMinute parses one validated HH:MM value without retaining text.
func conditionClockMinute(input string) (int, error) {
	parts := strings.Split(strings.TrimSpace(input), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid clock value")
	}

	hour, hourErr := strconv.Atoi(parts[0])

	minute, minuteErr := strconv.Atoi(parts[1])
	if hourErr != nil || minuteErr != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid clock value")
	}

	return hour*60 + minute, nil
}
