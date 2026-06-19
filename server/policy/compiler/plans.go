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
	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func buildStagePlans(
	checks []policyruntime.CompiledCheck,
	policies []policyruntime.CompiledPolicy,
) (map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan, error) {
	operations := operationSet(checks, policies)
	stages := stageSet(checks, policies)
	plans := make(map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan, len(operations))

	for operation := range operations {
		for stage := range stages {
			selectedChecks := checksForPlan(checks, operation, stage)
			selectedPolicies := policiesForPlan(policies, operation, stage)
			if len(selectedChecks) == 0 && len(selectedPolicies) == 0 {
				continue
			}

			orderedChecks, err := orderedChecksForPlan(selectedChecks)
			if err != nil {
				return nil, err
			}

			if plans[operation] == nil {
				plans[operation] = make(map[policy.Stage]policyruntime.CompiledStagePlan)
			}

			plans[operation][stage] = policyruntime.CompiledStagePlan{
				Stage:    stage,
				Checks:   orderedChecks,
				Policies: selectedPolicies,
			}
		}
	}

	return plans, nil
}

func operationSet(
	checks []policyruntime.CompiledCheck,
	policies []policyruntime.CompiledPolicy,
) map[policy.Operation]struct{} {
	operations := make(map[policy.Operation]struct{})
	for _, check := range checks {
		for _, operation := range check.Operations {
			operations[operation] = struct{}{}
		}
	}

	for _, compiledPolicy := range policies {
		for _, operation := range compiledPolicy.Operations {
			operations[operation] = struct{}{}
		}
	}

	return operations
}

func stageSet(
	checks []policyruntime.CompiledCheck,
	policies []policyruntime.CompiledPolicy,
) map[policy.Stage]struct{} {
	stages := make(map[policy.Stage]struct{})
	for _, check := range checks {
		stages[check.Stage] = struct{}{}
	}

	for _, compiledPolicy := range policies {
		stages[compiledPolicy.Stage] = struct{}{}
	}

	return stages
}

func policiesForPlan(
	policies []policyruntime.CompiledPolicy,
	operation policy.Operation,
	stage policy.Stage,
) []policyruntime.CompiledPolicy {
	selected := make([]policyruntime.CompiledPolicy, 0)
	for _, compiledPolicy := range policies {
		if compiledPolicy.Stage == stage && operationsContain(compiledPolicy.Operations, operation) {
			selected = append(selected, compiledPolicy)
		}
	}

	return selected
}

func orderedChecksForPlan(checks []policyruntime.CompiledCheck) ([]policyruntime.CompiledCheck, error) {
	temporary := make(map[string]bool, len(checks))
	permanent := make(map[string]bool, len(checks))
	byName := make(map[string]policyruntime.CompiledCheck, len(checks))
	ordered := make([]policyruntime.CompiledCheck, 0, len(checks))
	for _, check := range checks {
		byName[check.Name] = check
	}

	var visit func(policyruntime.CompiledCheck) error
	visit = func(check policyruntime.CompiledCheck) error {
		if permanent[check.Name] {
			return nil
		}

		if temporary[check.Name] {
			return configPathError("auth.policy.checks", "contains cyclic after dependencies")
		}

		temporary[check.Name] = true
		for _, dependencyName := range check.After {
			dependency, ok := byName[dependencyName]
			if !ok {
				continue
			}

			if err := visit(dependency); err != nil {
				return err
			}
		}

		temporary[check.Name] = false
		permanent[check.Name] = true
		ordered = append(ordered, check)

		return nil
	}

	for _, check := range checks {
		if err := visit(check); err != nil {
			return nil, err
		}
	}

	return ordered, nil
}
