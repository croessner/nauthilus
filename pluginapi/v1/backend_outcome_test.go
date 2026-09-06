package pluginapi

import (
	"testing"
	"time"
)

// TestBackendOutcomeViewSeparatesIndependentTruthFromFinalRuntime keeps captured credential results immutable.
func TestBackendOutcomeViewSeparatesIndependentTruthFromFinalRuntime(t *testing.T) {
	now := time.Now().UTC()

	view, err := NewBackendOutcomeView("host-event", "account", BackendOutcomeAuthenticated, now)
	if err != nil {
		t.Fatal(err)
	}

	request := PostActionRequest{BackendOutcome: view, Snapshot: RequestSnapshot{Runtime: RuntimeFlags{Authenticated: false}}}
	if request.BackendOutcome.Status() != BackendOutcomeAuthenticated || request.BackendOutcome.EventID() != "host-event" || request.BackendOutcome.Account() != "account" || !request.BackendOutcome.ObservedAt().Equal(now) {
		t.Fatal("final flags rewrote independent backend truth")
	}

	if (BackendOutcomeView{}).Observed() {
		t.Fatal("pre-backend request invented an outcome")
	}
}

// TestBackendOutcomeViewRejectsInvalidHostMetadata prevents unbounded or incomplete learning identities.
func TestBackendOutcomeViewRejectsInvalidHostMetadata(t *testing.T) {
	for _, id := range []string{"", "event\nforged"} {
		if _, err := NewBackendOutcomeView(id, "account", BackendOutcomeAuthenticated, time.Now()); err == nil {
			t.Fatal("invalid event identity admitted")
		}
	}

	if _, err := NewBackendOutcomeView("event", "account", BackendOutcomeStatus("policy_denied"), time.Now()); err == nil {
		t.Fatal("policy outcome accepted as backend truth")
	}
}
