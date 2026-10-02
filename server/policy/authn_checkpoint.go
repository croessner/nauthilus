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

package policy

import "slices"

// CompareAuthnCheckpoints orders authn checkpoint names by the established authentication work order. Unknown names
// compare equal to each other and sort after every authn checkpoint, so a stable sort keeps their prior order.
func CompareAuthnCheckpoints(left string, right string) int {
	return authnCheckpointRank(left) - authnCheckpointRank(right)
}

// FinalAuthnCheckpoint returns the checkpoint an authn plan evaluates last, using the same lexical-then-work-order
// sort as plan compilation. It returns an empty string for an empty plan.
func FinalAuthnCheckpoint(checkpoints []string) string {
	if len(checkpoints) == 0 {
		return ""
	}

	ordered := slices.Clone(checkpoints)
	slices.Sort(ordered)
	slices.SortStableFunc(ordered, CompareAuthnCheckpoints)

	return ordered[len(ordered)-1]
}

// authnCheckpointRank returns the position of one checkpoint in the authentication work order.
func authnCheckpointRank(checkpoint string) int {
	switch Stage(checkpoint) {
	case StagePreAuth:
		return 0
	case StageAuthBackend:
		return 1
	case StageSubjectAnalysis:
		return 2
	case StageAccountProvider:
		return 3
	case StageAuthDecision:
		return 4
	default:
		return 5
	}
}

// AuthnCheckpointDecisions returns the rule decisions the authn orchestration can apply at one checkpoint position.
// Every checkpoint before the final one only continues (neutral) or ends the request early (deny, tempfail); the
// final checkpoint must select a terminal outcome because no later checkpoint can decide the request.
func AuthnCheckpointDecisions(final bool) []Decision {
	if final {
		return []Decision{DecisionPermit, DecisionDeny, DecisionTempFail}
	}

	return []Decision{DecisionDeny, DecisionTempFail, DecisionNeutral}
}
