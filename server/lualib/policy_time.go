// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package lualib

import (
	"fmt"
	"time"

	lua "github.com/yuin/gopher-lua"
)

const (
	policyTimeModuleName = "time"
	policyTimeUTC        = "UTC"
)

// LoaderModPolicyTime exposes request-bounded time operations without live zoneinfo access.
func LoaderModPolicyTime() lua.LGFunction {
	return func(state *lua.LState) int {
		module := state.NewTable()
		state.SetFuncs(module, map[string]lua.LGFunction{
			"unix":      policyTimeUnix,
			"unix_nano": policyTimeUnixNano,
			"sleep":     policyTimeSleep,
			"parse":     policyTimeParse,
			"format":    policyTimeFormat,
		})
		state.Push(module)

		return 1
	}
}

// policyTimeUnix returns the current Unix time with subsecond precision.
func policyTimeUnix(state *lua.LState) int {
	now := float64(time.Now().UnixNano()) / float64(time.Second)
	state.Push(lua.LNumber(now))

	return 1
}

// policyTimeUnixNano returns the current Unix time in nanoseconds.
func policyTimeUnixNano(state *lua.LState) int {
	state.Push(lua.LNumber(time.Now().UnixNano()))

	return 1
}

// policyTimeSleep waits only while the request runtime context remains active.
func policyTimeSleep(state *lua.LState) int {
	seconds := float64(state.CheckNumber(1))
	if seconds < 0 {
		state.ArgError(1, "sleep duration must not be negative")
	}

	ctx := state.Context()
	if ctx == nil {
		state.RaiseError("%s.sleep requires a request runtime context", policyTimeModuleName)
	}

	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		state.RaiseError("%s.sleep requires a bounded request runtime context", policyTimeModuleName)
	}

	timer := time.NewTimer(time.Duration(seconds * float64(time.Second)))
	defer timer.Stop()

	select {
	case <-timer.C:
		return 0
	case <-ctx.Done():
		state.RaiseError("%s.sleep interrupted: %v", policyTimeModuleName, ctx.Err())

		return 0
	}
}

// policyTimeParse parses timestamps exclusively in the embedded UTC location.
func policyTimeParse(state *lua.LState) int {
	value := state.CheckString(1)

	layout := state.CheckString(2)
	if err := validatePolicyTimeLocation(state, 3); err != nil {
		return pushPolicyTimeError(state, err)
	}

	parsed, err := time.ParseInLocation(layout, value, time.UTC)
	if err != nil {
		return pushPolicyTimeError(state, err)
	}

	seconds := float64(parsed.UnixNano()) / float64(time.Second)
	state.Push(lua.LNumber(seconds))
	state.Push(lua.LNil)

	return 2
}

// policyTimeFormat formats timestamps exclusively in the embedded UTC location.
func policyTimeFormat(state *lua.LState) int {
	value := float64(state.CheckNumber(1))

	layout := "Mon Jan 2 15:04:05 -0700 MST 2006"
	if state.GetTop() > 1 {
		layout = state.CheckString(2)
	}

	if err := validatePolicyTimeLocation(state, 3); err != nil {
		return pushPolicyTimeError(state, err)
	}

	seconds := int64(value)
	nanoseconds := int64((value - float64(seconds)) * float64(time.Second))
	state.Push(lua.LString(time.Unix(seconds, nanoseconds).UTC().Format(layout)))
	state.Push(lua.LNil)

	return 2
}

// validatePolicyTimeLocation rejects locations that could require live zoneinfo files.
func validatePolicyTimeLocation(state *lua.LState, index int) error {
	if state.GetTop() < index {
		return nil
	}

	if location := state.CheckString(index); location != policyTimeUTC {
		return fmt.Errorf("time location %q is unavailable in Policy Lua; use UTC", location)
	}

	return nil
}

// pushPolicyTimeError returns the conventional nil-and-error Lua pair.
func pushPolicyTimeError(state *lua.LState, err error) int {
	state.Push(lua.LNil)
	state.Push(lua.LString(err.Error()))

	return 2
}
