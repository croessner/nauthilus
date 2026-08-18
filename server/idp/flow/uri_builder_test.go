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

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestURIBuilderCarriesCanonicalFlowTicketOnLocalInteractionTargets(t *testing.T) {
	t.Parallel()

	flowID := "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
	state := &State{
		FlowID: flowID, Type: FlowTypeOIDCAuthorization, Protocol: FlowProtocolOIDC,
		CurrentStep: FlowStepStart, ReturnTarget: "/login?language=en",
	}
	target := NewURIBuilder().Resolve(state, FlowActionStart)

	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	if parsed.Query().Get(FlowTicketParameter) != flowID {
		t.Fatalf("flow ticket = %q in %q, want %q", parsed.Query().Get(FlowTicketParameter), target, flowID)
	}

	if parsed.Query().Get("language") != "en" {
		t.Fatalf("existing target query was lost: %q", target)
	}

	external := "https://client.example.test/callback"

	state.ReturnTarget = external
	if target = NewURIBuilder().Resolve(state, FlowActionStart); target != external {
		t.Fatalf("external target was decorated: %q", target)
	}
}

func TestTicketFromRequestAcceptsOnlyCanonicalOpaqueHandle(t *testing.T) {
	t.Parallel()

	valid := "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"
	request := httptest.NewRequest("GET", "/login?flow="+valid, nil)

	ticket, err := TicketFromRequest(request)
	if err != nil || string(ticket) != valid {
		t.Fatalf("canonical ticket: value=%q err=%v", ticket, err)
	}

	request = httptest.NewRequest("GET", "/login?flow=legacy-flow-id", nil)
	if _, err = TicketFromRequest(request); err == nil {
		t.Fatal("legacy flow selector was accepted")
	}
}

func TestURIBuilderResolve(t *testing.T) {
	builder := NewURIBuilder()

	testCases := []struct {
		name     string
		state    *State
		action   Action
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
			state:    &State{Type: FlowTypeSAML, CurrentStep: FlowStepLogin},
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
