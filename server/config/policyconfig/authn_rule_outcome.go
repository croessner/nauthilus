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

package policyconfig

import (
	"fmt"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/policy"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
)

// validateAuthnRuleOutcomes requires every rule an authn target binds at one checkpoint to select a decision the
// authn orchestration can apply at that checkpoint position. An explicit auth FSM event marker must apply to that
// decision at that checkpoint; an omitted marker is derived from checkpoint and decision. Generic targets do not
// drive the authn orchestration or the auth FSM.
func validateAuthnRuleOutcomes(
	policySet PolicySetConfig,
	setNamespace string,
	setName string,
	binding targetCheckpointBinding,
) error {
	target := binding.target
	if target.Namespace != authnNamespace {
		return nil
	}

	for ruleIndex, rule := range boundPolicyRules(policySet, binding.checkpoint, target.Action) {
		rulePath := policySetRulePath(setNamespace, setName, ruleIndex)
		ruleContext := fmt.Sprintf("rule %q bound to target %s/%s", rule.Name, target.Namespace, target.Action)

		if message, ok := authnCheckpointDecisionAllowed(binding, policy.Decision(rule.Then.Decision)); !ok {
			return invalid(rulePath+".then.decision", ruleContext+": "+message)
		}

		err := policyfsm.ValidateRuleMarker(
			policy.Operation(target.Action),
			policy.Stage(binding.checkpoint),
			policy.Decision(rule.Then.Decision),
			rule.Then.FSMEventMarker,
		)
		if err != nil {
			return invalid(rulePath+".then.fsm_event_marker", fmt.Sprintf("%s: %v", ruleContext, err))
		}
	}

	return nil
}

// authnCheckpointDecisionAllowed reports whether the decision is applicable at the binding checkpoint position and
// describes the allowed decisions when it is not.
func authnCheckpointDecisionAllowed(binding targetCheckpointBinding, selected policy.Decision) (string, bool) {
	final := binding.checkpoint == binding.finalCheckpoint
	allowed := policy.AuthnCheckpointDecisions(final)

	if slices.Contains(allowed, selected) {
		return "", true
	}

	names := make([]string, 0, len(allowed))
	for _, decision := range allowed {
		names = append(names, string(decision))
	}

	if final {
		return fmt.Sprintf("decision %s is not supported at final checkpoint %s; allowed decisions: %s",
			selected, binding.checkpoint, strings.Join(names, ", ")), false
	}

	return fmt.Sprintf(
		"decision %s is not supported at intermediate checkpoint %s (final checkpoint is %s); allowed decisions: %s",
		selected, binding.checkpoint, binding.finalCheckpoint, strings.Join(names, ", ")), false
}
