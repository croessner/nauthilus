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

package compiler

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func compileSets(configSets config.PolicySetsConfig) (policyruntime.CompiledSets, error) {
	networks, err := compileNetworkSets(configSets.Networks)
	if err != nil {
		return policyruntime.CompiledSets{}, err
	}

	timeWindows, err := compileTimeWindowSets(configSets.TimeWindows)
	if err != nil {
		return policyruntime.CompiledSets{}, err
	}

	return policyruntime.CompiledSets{
		Networks:    networks,
		TimeWindows: timeWindows,
	}, nil
}

func compileNetworkSets(networkSets map[string][]string) (map[string][]netip.Prefix, error) {
	compiled := make(map[string][]netip.Prefix, len(networkSets))
	for name, entries := range networkSets {
		if !simpleIdentifierPattern.MatchString(name) {
			return nil, configPathError(childPath("auth.policy.sets.networks", name), "must use lowercase letters, digits, and underscores")
		}

		prefixes := make([]netip.Prefix, 0, len(entries))
		for index, entry := range entries {
			prefix, err := parseNetworkPrefix(entry)
			if err != nil {
				return nil, configPathError(indexedPath(childPath("auth.policy.sets.networks", name), index), "must be an IP address or CIDR")
			}

			prefixes = append(prefixes, prefix)
		}

		compiled[name] = prefixes
	}

	return compiled, nil
}

func parseNetworkPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("empty network")
	}

	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}

		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}

	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}

	return netip.PrefixFrom(addr, 128), nil
}

func compileTimeWindowSets(
	timeWindowSets map[string]config.PolicyTimeWindowConfig,
) (map[string]policyruntime.CompiledTimeWindow, error) {
	compiled := make(map[string]policyruntime.CompiledTimeWindow, len(timeWindowSets))
	for name, timeWindow := range timeWindowSets {
		path := childPath("auth.policy.sets.time_windows", name)
		if !simpleIdentifierPattern.MatchString(name) {
			return nil, configPathError(path, "must use lowercase letters, digits, and underscores")
		}

		location, err := time.LoadLocation(timeWindow.Timezone)
		if err != nil {
			return nil, configPathError(childPath(path, "timezone"), "must be an IANA timezone name")
		}

		days, err := compileWeekdays(timeWindow.Days, childPath(path, "days"))
		if err != nil {
			return nil, err
		}

		intervals, err := compileTimeIntervals(timeWindow.Intervals, childPath(path, "intervals"))
		if err != nil {
			return nil, err
		}

		compiled[name] = policyruntime.CompiledTimeWindow{
			LocationName: location.String(),
			Days:         days,
			Intervals:    intervals,
		}
	}

	return compiled, nil
}

func compileWeekdays(values []string, path string) ([]time.Weekday, error) {
	days := make([]time.Weekday, 0, len(values))
	for index, value := range values {
		day, ok := parseWeekday(value)
		if !ok {
			return nil, configPathError(indexedPath(path, index), "must be one of mon, tue, wed, thu, fri, sat, or sun")
		}

		days = append(days, day)
	}

	return days, nil
}

func parseWeekday(value string) (time.Weekday, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
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

func compileTimeIntervals(
	values []config.PolicyTimeIntervalConfig,
	path string,
) ([]policyruntime.CompiledTimeInterval, error) {
	intervals := make([]policyruntime.CompiledTimeInterval, 0, len(values))
	for index, value := range values {
		intervalPath := indexedPath(path, index)
		startMinute, err := parseClockMinute(value.Start)
		if err != nil {
			return nil, configPathError(childPath(intervalPath, "start"), "must use HH:MM")
		}

		endMinute, err := parseClockMinute(value.End)
		if err != nil {
			return nil, configPathError(childPath(intervalPath, "end"), "must use HH:MM")
		}

		if endMinute <= startMinute {
			return nil, configPathError(intervalPath, "must not cross midnight")
		}

		intervals = append(intervals, policyruntime.CompiledTimeInterval{
			StartMinute: startMinute,
			EndMinute:   endMinute,
		})
	}

	return intervals, nil
}

func parseClockMinute(value string) (int, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time")
	}

	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}

	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}

	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid time")
	}

	return hour*60 + minute, nil
}
