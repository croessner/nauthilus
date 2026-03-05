// Copyright (C) 2025 Christian Rößner
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

package flow

import "testing"

func TestURIBuilderResolve(t *testing.T) {
	builder := NewURIBuilder()

	testCases := []struct {
		name     string
		state    *State
		action   FlowAction
		expected string
	}{
		{
			name:     "nil state fallback",
			action:   FlowActionStart,
			expected: "/login",
		},
		{
			name:     "return target on start",
			state:    &State{ReturnTarget: "/custom"},
			action:   FlowActionStart,
			expected: "/custom",
		},
		{
			name:     "cancel target has precedence",
			state:    &State{CancelTarget: "/cancel-here"},
			action:   FlowActionCancel,
			expected: "/cancel-here",
		},
		{
			name:     "cancel fallback",
			state:    &State{FlowType: FlowTypeSAML, CurrentStep: FlowStepLogin},
			action:   FlowActionCancel,
			expected: "/",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := builder.Resolve(testCase.state, testCase.action)
			if actual != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, actual)
			}
		})
	}
}
