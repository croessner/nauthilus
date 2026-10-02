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

	"github.com/croessner/nauthilus/v4/server/policy"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
)

// validateAuthnRuleFSMMarkers requires every rule an authn target binds at one checkpoint to select an auth FSM
// event marker the orchestration can apply for the rule decision. Generic targets do not drive the auth FSM.
func validateAuthnRuleFSMMarkers(
	policySet PolicySetConfig,
	setNamespace string,
	setName string,
	target TargetConfig,
	checkpoint string,
) error {
	if target.Namespace != authnNamespace {
		return nil
	}

	for ruleIndex, rule := range boundPolicyRules(policySet, checkpoint, target.Action) {
		err := policyfsm.ValidateRuleMarker(
			policy.Operation(target.Action),
			policy.Stage(checkpoint),
			policy.Decision(rule.Then.Decision),
			rule.Then.FSMEventMarker,
		)
		if err != nil {
			return invalid(
				policySetRulePath(setNamespace, setName, ruleIndex)+".then.fsm_event_marker",
				fmt.Sprintf("rule %q bound to target %s/%s: %v", rule.Name, target.Namespace, target.Action, err),
			)
		}
	}

	return nil
}
