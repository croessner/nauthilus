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

// Package subjectschedule classifies policy subject checks around the supported Lua/native boundary.
package subjectschedule

import (
	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// BoundaryGraph provides deterministic dependency queries over compiled subject checks.
type BoundaryGraph struct {
	checks []policyruntime.CompiledCheck
	byName map[string]policyruntime.CompiledCheck
}

// NewBoundaryGraph builds an immutable lookup view over the supplied checks.
func NewBoundaryGraph(checks []policyruntime.CompiledCheck) BoundaryGraph {
	byName := make(map[string]policyruntime.CompiledCheck, len(checks))

	for _, check := range checks {
		byName[check.Name] = check
	}

	return BoundaryGraph{checks: append([]policyruntime.CompiledCheck(nil), checks...), byName: byName}
}

// DeferredLuaChecks returns Lua subject check names with a transitive native subject dependency.
func (g BoundaryGraph) DeferredLuaChecks() map[string]struct{} {
	deferred := make(map[string]struct{})

	for _, check := range g.checks {
		if check.Type != policy.CheckTypeLuaSubjectSource {
			continue
		}

		if g.dependencyChainContainsType(check.Name, policy.CheckTypePluginSubjectSource, make(map[string]bool)) {
			deferred[check.Name] = struct{}{}
		}
	}

	return deferred
}

// SecondNativeBoundary returns a native dependency edge that would execute after deferred Lua.
func (g BoundaryGraph) SecondNativeBoundary() (string, int, bool) {
	deferred := g.DeferredLuaChecks()

	if len(deferred) == 0 {
		return "", 0, false
	}

	for _, check := range g.checks {
		if check.Type != policy.CheckTypePluginSubjectSource {
			continue
		}

		for index, dependencyName := range check.After {
			if g.dependencyChainContainsAny(dependencyName, deferred, make(map[string]bool)) {
				return check.Name, index, true
			}
		}
	}

	return "", 0, false
}

// dependencyChainContainsType reports whether a check transitively depends on the requested check type.
func (g BoundaryGraph) dependencyChainContainsType(checkName string, checkType string, visiting map[string]bool) bool {
	if visiting[checkName] {
		return false
	}

	check, exists := g.byName[checkName]
	if !exists {
		return false
	}

	visiting[checkName] = true
	defer delete(visiting, checkName)

	for _, dependencyName := range check.After {
		dependency, exists := g.byName[dependencyName]
		if !exists {
			continue
		}

		if dependency.Type == checkType || g.dependencyChainContainsType(dependencyName, checkType, visiting) {
			return true
		}
	}

	return false
}

// dependencyChainContainsAny reports whether a dependency chain includes one of the target checks.
func (g BoundaryGraph) dependencyChainContainsAny(
	checkName string,
	targets map[string]struct{},
	visiting map[string]bool,
) bool {
	if _, exists := targets[checkName]; exists {
		return true
	}

	if visiting[checkName] {
		return false
	}

	check, exists := g.byName[checkName]
	if !exists {
		return false
	}

	visiting[checkName] = true
	defer delete(visiting, checkName)

	for _, dependencyName := range check.After {
		if g.dependencyChainContainsAny(dependencyName, targets, visiting) {
			return true
		}
	}

	return false
}
