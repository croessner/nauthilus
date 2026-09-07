package core

import (
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
)

// TestCachedBackendOutcomeRetainsCanonicalAccount covers LDAP results whose identity lives in attributes and context.
func TestCachedBackendOutcomeRetainsCanonicalAccount(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	source, sourceCtx := newRequestOwnedContractAuth(t, cfg, "alias@example.test", "credential", "cold-account")

	result := newSemanticPassDBResult(sourceCtx, source)
	defer PutPassDBResultToPool(result)

	result.Account = ""
	result.Attributes["uid"] = []any{"canonical@example.test"}
	source.Runtime.AccountName = ""

	sourceCtx.Set(definitions.CtxAccountKey, "canonical@example.test")

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	if !cache.StoreForRequest(sourceCtx, source, result, time.Minute, source.Request.Username) {
		t.Fatal("canonical backend fixture was not cached")
	}

	auth, ginCtx := newRequestOwnedContractAuth(t, cfg, source.Request.Username, "credential", "warm-account")
	auth.deps.BackendAuthenticationCache = cache

	host := &authnCandidateExecution{auth: auth, ginCtx: ginCtx, operation: policy.OperationAuthenticate}
	if !host.prepareCachedBackendResult(backendExecutionPlan{}) {
		t.Fatal("expected positive backend cache hit")
	}
	defer PutPassDBResultToPool(host.backendResult)

	if !host.backendOutcome.Observed() || host.backendOutcome.Account() != "canonical@example.test" || host.backendAccount != "canonical@example.test" {
		t.Fatal("warm backend outcome lost the verified canonical identity")
	}
}

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
