package service

import "testing"

// TestReplaySafePrefixRejectsEarlierUnsafeEffects protects complete-request retries.
func TestReplaySafePrefixRejectsEarlierUnsafeEffects(t *testing.T) {
	safe := plannedEffect{syncProvider: &recordingSyncEffectProvider{replayKey: "resource.workflow.event_id"}}
	unsafe := plannedEffect{syncProvider: &recordingSyncEffectProvider{}}

	for _, test := range []struct {
		name string
		plan []plannedEffect
		want bool
	}{
		{"only idempotent", []plannedEffect{safe}, true},
		{"earlier unsafe", []plannedEffect{unsafe, safe}, false},
		{"all idempotent", []plannedEffect{safe, safe}, true},
		{"unsafe post-action accepted", []plannedEffect{{postProvider: &recordingPostActionProvider{}}, safe}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := replaySafeEffectPrefix(test.plan); got != test.want {
				t.Fatalf("replay safe=%t, want %t", got, test.want)
			}
		})
	}
}
