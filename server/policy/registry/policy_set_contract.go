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

package registry

import (
	"fmt"
	"slices"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

// DerivePolicySetCapability derives one exact transitive capability from source definitions.
func DerivePolicySetCapability(
	sets map[string]PolicySetDefinition,
	identity string,
) (ExportContract, error) {
	accumulator := policySetCapabilityAccumulator{
		facts:       make(map[string]FactContract),
		effects:     make(map[string]struct{}),
		checkpoints: make(map[string]struct{}),
		visited:     make(map[string]bool),
		active:      make(map[string]bool),
	}

	if err := accumulator.mergeSet(sets, identity); err != nil {
		return ExportContract{}, err
	}

	return accumulator.contract()
}

// policySetCapabilityAccumulator owns exact transitive export derivation.
type policySetCapabilityAccumulator struct {
	facts       map[string]FactContract
	effects     map[string]struct{}
	checkpoints map[string]struct{}
	visited     map[string]bool
	active      map[string]bool
	decisions   []decision.Effect
}

// mergeSet adds one set and its import closure exactly once.
func (a *policySetCapabilityAccumulator) mergeSet(
	sets map[string]PolicySetDefinition,
	identity string,
) error {
	if a.visited[identity] {
		return nil
	}

	if a.active[identity] {
		return fmt.Errorf("%w: cyclic capability derivation at %s", ErrInvalidExportContract, identity)
	}

	set, exists := sets[identity]
	if !exists {
		return fmt.Errorf("%w: capability source %s is unknown", ErrInvalidExportContract, identity)
	}

	a.active[identity] = true

	for _, rule := range set.Rules() {
		if err := a.mergeRule(rule); err != nil {
			return err
		}
	}

	for _, imported := range set.Imports() {
		if err := a.mergeSet(sets, imported.Set().String()); err != nil {
			return err
		}
	}

	delete(a.active, identity)
	a.visited[identity] = true

	return nil
}

// mergeRule adds one rule's complete typed surface.
func (a *policySetCapabilityAccumulator) mergeRule(rule PolicyRule) error {
	a.checkpoints[rule.Checkpoint()] = struct{}{}

	for _, fact := range rule.FactContracts() {
		if current, exists := a.facts[fact.ID()]; exists && current.Kind() != fact.Kind() {
			return fmt.Errorf("%w: fact %s has incompatible transitive kinds", ErrInvalidExportContract, fact.ID())
		}

		a.facts[fact.ID()] = fact
	}

	if !slices.Contains(a.decisions, rule.Decision()) {
		a.decisions = append(a.decisions, rule.Decision())
	}

	for _, use := range append(rule.Effects(), rule.Advice()...) {
		a.effects[use.ID()] = struct{}{}
	}

	return nil
}

// contract constructs one deterministic complete export capability.
func (a *policySetCapabilityAccumulator) contract() (ExportContract, error) {
	if len(a.checkpoints) == 0 || len(a.decisions) == 0 {
		return ExportContract{}, nil
	}

	checkpoints := sortedCapabilityKeys(a.checkpoints)
	factIDs := sortedCapabilityKeys(a.facts)
	facts := make([]FactContract, 0, len(factIDs))

	for _, identity := range factIDs {
		facts = append(facts, a.facts[identity])
	}

	effects := sortedCapabilityKeys(a.effects)

	return NewExportContractForCheckpoints(checkpoints, facts, a.decisions, effects)
}

// sortedCapabilityKeys returns deterministic contract member identities.
func sortedCapabilityKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for identity := range values {
		result = append(result, identity)
	}

	slices.Sort(result)

	return result
}
