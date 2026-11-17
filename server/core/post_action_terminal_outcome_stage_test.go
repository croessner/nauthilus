// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestTempFailOutcomeWithoutPresentationNamesItsStage reproduces a terminal completion of an indeterminate evaluation
// without a selected rule: the sealed outcome must still name the checkpoint stage that failed, while a presented
// rule keeps its own stage.
func TestTempFailOutcomeWithoutPresentationNamesItsStage(t *testing.T) {
	cause := authTempFailCause{reason: "policy_indeterminate", checkpoint: "subject_analysis", statusCode: "provider_unavailable"}

	unselected := pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeTempFail}
	applyTempFailCause(&unselected, cause)

	if unselected.Stage != "subject_analysis" || unselected.TempFailCheckpoint != "subject_analysis" {
		t.Fatalf("unselected tempfail stage/checkpoint = %q/%q, want subject_analysis",
			unselected.Stage, unselected.TempFailCheckpoint)
	}

	presented := pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeTempFail, Stage: "auth_decision"}
	applyTempFailCause(&presented, cause)

	if presented.Stage != "auth_decision" {
		t.Fatalf("presented tempfail stage = %q, want the presenting rule's auth_decision", presented.Stage)
	}
}
