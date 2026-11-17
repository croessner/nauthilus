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

package pluginruntime

import (
	"fmt"
	"slices"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestAuthEventLanesKeepMFAEvidenceFromCompletionFloods pins that a burst of OIDC completion events fills only its
// own bounded lane, so second-factor events are still queued and delivered.
func TestAuthEventLanesKeepMFAEvidenceFromCompletionFloods(t *testing.T) {
	mfaProbe := &authEventProbe{outcomes: map[string]int{}}
	completionProbe := &authEventProbe{release: make(chan struct{}), outcomes: map[string]int{}}
	lanes := &authEventLanes{
		mfa:        newAuthEventDispatcher([]string{"clickhouse.events"}, 2, mfaProbe.deliver, mfaProbe.count),
		completion: newAuthEventDispatcher([]string{"clickhouse.events"}, 2, completionProbe.deliver, completionProbe.count),
	}
	lanes.start()

	for index := range 8 {
		lanes.route(pluginapi.AuthEventOIDCCodeIssuance).EmitAuthEvent(t.Context(),
			pluginapi.AuthEvent{EventID: fmt.Sprintf("code-%d", index), Type: pluginapi.AuthEventOIDCCodeIssuance})
	}

	lanes.route(pluginapi.AuthEventMFAVerification).EmitAuthEvent(t.Context(),
		pluginapi.AuthEvent{EventID: "factor", Type: pluginapi.AuthEventMFAVerification})
	close(completionProbe.release)

	if err := lanes.stop(t.Context()); err != nil {
		t.Fatalf("stop() error = %v", err)
	}

	mfaDelivered, _ := mfaProbe.snapshot()
	_, completionOutcomes := completionProbe.snapshot()

	if !slices.Equal(mfaDelivered, []string{"factor"}) {
		t.Fatalf("mfa delivered = %#v, want the factor event despite the completion flood", mfaDelivered)
	}

	if completionOutcomes[authEventOutcomeDropped] == 0 {
		t.Fatalf("completion outcomes = %#v, want overflow dropped in the completion lane", completionOutcomes)
	}
}

// TestAuthEventLanesRouteByType pins the lane of every event type; unknown types stay on the second-factor lane.
func TestAuthEventLanesRouteByType(t *testing.T) {
	lanes := &authEventLanes{mfa: &AuthEventDispatcher{}, completion: &AuthEventDispatcher{}}

	cases := map[pluginapi.AuthEventType]*AuthEventDispatcher{
		pluginapi.AuthEventMFAVerification:    lanes.mfa,
		pluginapi.AuthEventOIDCCodeIssuance:   lanes.completion,
		pluginapi.AuthEventOIDCCodeRedemption: lanes.completion,
		pluginapi.AuthEventType("future"):     lanes.mfa,
	}

	for eventType, want := range cases {
		if got := lanes.route(eventType); got != want {
			t.Fatalf("route(%q) chose the wrong lane", eventType)
		}
	}

	var disabled *authEventLanes
	if disabled.route(pluginapi.AuthEventOIDCCodeIssuance) != nil || disabled.stop(t.Context()) != nil {
		t.Fatal("nil lanes must route nowhere and stop cleanly")
	}
}
