package core

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy"
)

// TestAuthnBackendOutcomeRetainsOriginalTruth separates verified evidence from later subject and Policy changes.
func TestAuthnBackendOutcomeRetainsOriginalTruth(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		auth, ginCtx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))
		auth.deps.NativeRuntime = &authnNativeTestRuntime{}
		host := &authnCandidateExecution{auth: auth, ginCtx: ginCtx, operation: policy.OperationAuthenticate}
		result := &PassDBResult{Authenticated: authenticated, Account: "original-account"}
		host.captureBackendOutcome(result, result.Account)
		original := host.backendOutcome
		result.Authenticated = !authenticated
		result.Account = "patched-account"
		auth.Runtime.Authenticated = !authenticated

		host.captureBackendOutcome(result, result.Account)

		program := &authnNativePostActionTestProgram{id: authnNativePostActionTestID}

		work, err := host.PrepareAuthnNativePostAction(t.Context(), program, newAuthnNativeTestExecution(t, authnNativePostActionTestID))
		if err != nil {
			t.Fatal(err)
		}

		captured := work.(*authnNativePostActionWork).request.BackendOutcome

		expected := pluginapi.BackendOutcomeBadCredentials
		if authenticated {
			expected = pluginapi.BackendOutcomeAuthenticated
		}

		if captured != original || captured.Status() != expected || captured.Account() != "original-account" || !captured.Observed() {
			t.Fatal("backend truth changed after verification")
		}
	}
}

// TestAuthnBackendOutcomeWithoutVerificationCannotLearn prevents pre-backend denials from becoming credential failures.
func TestAuthnBackendOutcomeWithoutVerificationCannotLearn(t *testing.T) {
	host := &authnCandidateExecution{auth: &AuthState{}}
	host.captureBackendOutcome(nil, "")

	if host.backendOutcome.Observed() {
		t.Fatal("missing backend result invented an outcome")
	}

	host.captureBackendOutcome(&PassDBResult{}, "")

	if host.backendOutcome.Observed() {
		t.Fatal("missing host event identity admitted")
	}
}

// TestAuthnBackendOutcomeSkipsLookupOnlyRequests excludes authenticated user lookups without credential verification.
func TestAuthnBackendOutcomeSkipsLookupOnlyRequests(t *testing.T) {
	auth := &AuthState{}
	auth.Runtime.GUID = "lookup-only"
	auth.Request.NoAuth = true
	host := &authnCandidateExecution{auth: auth, operation: policy.OperationAuthenticate}
	host.captureBackendOutcome(&PassDBResult{Authenticated: true}, "account")

	if host.backendOutcome.Observed() {
		t.Fatal("lookup-only request created trust")
	}
}
