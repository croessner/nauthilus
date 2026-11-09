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

package core

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/secret"

	lua "github.com/yuin/gopher-lua"
)

// authnLogFieldPattern extracts one space-delimited key=value pair from a slog text record.
var authnLogFieldPattern = regexp.MustCompile(`(?:^| )(authenticated|authz|authn)=(\S+)`)

// authnLogFieldsCase binds one request flow to the final log fields and access decision it must produce.
// wantRuntimeAuthenticated pins the internal Authenticated flag that scheduling, post-actions, and snapshots consume.
type authnLogFieldsCase struct {
	prepare                  func(*testing.T, *authnFSMGuardHarness)
	verifier                 PasswordVerifier
	subject                  CapturedLuaSubject
	name                     string
	operation                policy.Operation
	stage                    policy.Stage
	selected                 policy.Decision
	wantDecision             AuthDecision
	wantAuthenticated        string
	wantAuthz                string
	wantAuthn                string
	wantRuntimeAuthenticated bool
}

// runAuthnLogFieldsLuaSubjectRejection runs the backend checkpoint and one rejecting Lua subject source.
func runAuthnLogFieldsLuaSubjectRejection(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.runBackend(t)

	if _, err := h.execution.prepareLuaSubjectSource("reject", &lua.FunctionProto{}, nil, "", nil); err != nil {
		t.Fatalf("prepareLuaSubjectSource() error = %v", err)
	}

	h.completeSubject()
}

// runAuthnLogFieldsCacheWriteFailure verifies the credential and lets the positive password cache update fail.
func runAuthnLogFieldsCacheWriteFailure(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.execution.auth.deps.HostServices.cache = &failingAuthnFSMGuardCache{}
	h.runBackendPlan(t, backendExecutionPlan{
		positions:                map[definitions.Backend]int{definitions.BackendCache: 0, definitions.BackendLDAP: 1},
		hasPositivePasswordCache: true,
	})
	h.execution.auth.Runtime.UsedPassDBBackend = definitions.BackendLDAP
	h.completeSubject()
}

// runAuthnLogFieldsEmptyPassword runs the backend checkpoint for a request without a password.
func runAuthnLogFieldsEmptyPassword(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	h.execution.auth.Request.Password = secret.Value{}
	h.runBackend(t)
}

// runAuthnLogFieldsNativeSubject runs the backend checkpoint and one native subject source that may reject.
func runAuthnLogFieldsNativeSubject(rejected bool) func(*testing.T, *authnFSMGuardHarness) {
	return func(t *testing.T, h *authnFSMGuardHarness) {
		t.Helper()

		h.runBackend(t)
		h.evaluateNativeSubject(t, rejected)
		h.completeSubject()
	}
}

// runAuthnLogFieldsCachedSubjectRejection serves a positive cache hit and lets a native subject source reject it.
func runAuthnLogFieldsCachedSubjectRejection(t *testing.T, h *authnFSMGuardHarness) {
	t.Helper()

	verified, err := authnFSMGuardVerifier{authenticated: true, userFound: true}.Verify(h.execution.ginCtx, h.execution.auth, nil)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	verified.Backend = definitions.BackendLDAP
	cache := h.execution.auth.backendAuthenticationCache()

	stored := cache.StoreForRequest(h.execution.ginCtx, h.execution.auth, verified, time.Minute, h.execution.auth.Request.Username)
	PutPassDBResultToPool(verified)

	if !stored {
		t.Fatal("positive backend authentication was not cached")
	}

	h.runBackendPlan(t, backendExecutionPlan{passDBs: []*PassDBMap{{backend: definitions.BackendLDAP}}})

	if !h.execution.backendCached {
		t.Fatal("backend checkpoint did not use the positive cache")
	}

	h.evaluateNativeSubject(t, true)
	h.completeSubject()
}

// evaluateNativeSubject runs one native subject source without a backend result patch.
func (h *authnFSMGuardHarness) evaluateNativeSubject(t *testing.T, rejected bool) {
	t.Helper()

	provider := &authnCapturedNativeSubjectSource{id: "authn/plugin.example.subject.protocol", rejected: rejected}

	if _, err := h.execution.prepareNativeSubjectSource(provider.id, provider); err != nil {
		t.Fatalf("prepareNativeSubjectSource() error = %v", err)
	}
}

// authnLogFieldsCases lists the request flows whose final log line must keep authn tied to the credential check.
func authnLogFieldsCases() []authnLogFieldsCase {
	return append(authnLogFieldsSubjectCases(), authnLogFieldsFailureCases()...)
}

// authnLogFieldsSubjectCases lists credential checks followed by subject analysis.
func authnLogFieldsSubjectCases() []authnLogFieldsCase {
	verified := authnFSMGuardVerifier{authenticated: true, userFound: true}
	wrong := authnFSMGuardVerifier{userFound: true}

	return []authnLogFieldsCase{
		{
			name: "verified credential with permitted access", verifier: verified,
			prepare: runAuthnLogFieldsNativeSubject(false), selected: policy.DecisionPermit,
			wantDecision: AuthDecisionOK, wantAuthenticated: "ok", wantAuthz: "true", wantAuthn: "true",
			wantRuntimeAuthenticated: true,
		},
		{
			name: "verified credential rejected by a native subject, e.g. inactive protocol", verifier: verified,
			prepare: runAuthnLogFieldsNativeSubject(true), selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantAuthenticated: "fail", wantAuthz: "false", wantAuthn: "true",
		},
		{
			name: "verified credential rejected by a Lua subject", verifier: verified,
			subject: rejectingLuaSubject{result: definitions.AuthResultFail}, prepare: runAuthnLogFieldsLuaSubjectRejection,
			selected: policy.DecisionDeny, wantDecision: AuthDecisionFail,
			wantAuthenticated: "fail", wantAuthz: "false", wantAuthn: "true",
		},
		{
			name: "positive cache hit rejected by a native subject", verifier: wrong,
			prepare: runAuthnLogFieldsCachedSubjectRejection, selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantAuthenticated: "fail", wantAuthz: "false", wantAuthn: "true",
		},
		{
			name: "wrong credential", verifier: wrong,
			prepare: runAuthnLogFieldsNativeSubject(false), selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantAuthenticated: "fail", wantAuthz: "false", wantAuthn: "false",
		},
		{
			name: "wrong credential rejected by a native subject", verifier: wrong,
			prepare: runAuthnLogFieldsNativeSubject(true), selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantAuthenticated: "fail", wantAuthz: "false", wantAuthn: "false",
		},
		{
			name: "wrong credential raised by a native subject patch", verifier: wrong,
			prepare: runAuthnFSMGuardNativeSubjectPatch, selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantAuthenticated: "fail", wantAuthz: "false", wantAuthn: "false",
		},
		{
			name: "no-auth identity lookup", operation: policy.OperationLookupIdentity, verifier: verified,
			prepare: runAuthnFSMGuardBackendAndSubject, selected: policy.DecisionPermit,
			wantDecision: AuthDecisionOK, wantAuthenticated: "N/A", wantAuthz: "true", wantAuthn: "true",
			wantRuntimeAuthenticated: true,
		},
	}
}

// authnLogFieldsFailureCases lists technical failures and rejections without a verified credential.
func authnLogFieldsFailureCases() []authnLogFieldsCase {
	verified := authnFSMGuardVerifier{authenticated: true, userFound: true}

	return []authnLogFieldsCase{
		{
			name: "backend technical failure", verifier: authnFSMGuardVerifier{err: errors.New("backend unavailable")},
			prepare: runAuthnFSMGuardBackend, selected: policy.DecisionTempFail,
			wantDecision: AuthDecisionTempFail, wantAuthenticated: "tempfail", wantAuthz: "true", wantAuthn: "false",
		},
		{
			name: "verified credential lowered by a failed password cache update", verifier: verified,
			prepare: runAuthnLogFieldsCacheWriteFailure, selected: policy.DecisionTempFail,
			wantDecision: AuthDecisionTempFail, wantAuthenticated: "tempfail", wantAuthz: "true", wantAuthn: "false",
		},
		{
			name: "empty password", verifier: verified,
			prepare: runAuthnLogFieldsEmptyPassword, selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantAuthenticated: "fail", wantAuthz: "true", wantAuthn: "false",
		},
		{
			name: "rejection before the credential check", verifier: verified,
			stage: policy.StagePreAuth, selected: policy.DecisionDeny,
			wantDecision: AuthDecisionFail, wantAuthenticated: "fail", wantAuthz: "true", wantAuthn: "false",
		},
	}
}

// TestAuthnFinalLogFieldsReportCredentialVerdict proves the final log line reports authn as the host-verified
// credential result, so a later authorization rejection keeps authn=true while access stays denied.
func TestAuthnFinalLogFieldsReportCredentialVerdict(t *testing.T) {
	for _, test := range authnLogFieldsCases() {
		t.Run(test.name, func(t *testing.T) {
			runAuthnLogFieldsCase(t, test)
		})
	}
}

// runAuthnLogFieldsCase executes one flow, finalizes its selection, and checks access and the final log fields.
func runAuthnLogFieldsCase(t *testing.T, test authnLogFieldsCase) {
	t.Helper()

	if test.stage == "" {
		test.stage = policy.StageAuthDecision
	}

	if test.operation == "" {
		test.operation = policy.OperationAuthenticate
	}

	if test.subject == nil {
		test.subject = testLuaSubject{}
	}

	harness := newAuthnFSMGuardHarness(t, test.operation, test.verifier, test.subject)
	if test.prepare != nil {
		test.prepare(t, harness)
	}

	result := harness.finalize(t, test.stage, test.selected, "")

	gotDecision, _, _ := authnFSMGuardOutcome(result)
	if gotDecision != test.wantDecision {
		t.Fatalf("decision = %q, want %q", gotDecision, test.wantDecision)
	}

	if aborted := harness.execution.ginCtx.IsAborted(); aborted != (test.wantDecision != AuthDecisionOK) {
		t.Fatalf("request aborted = %t, want %t", aborted, test.wantDecision != AuthDecisionOK)
	}

	if got := harness.execution.auth.Runtime.Authenticated; got != test.wantRuntimeAuthenticated {
		t.Fatalf("internal authenticated flag = %t, want %t", got, test.wantRuntimeAuthenticated)
	}

	fields := authnFinalLogFields(t, harness.logs.String())
	want := map[string]string{
		definitions.LogKeyStatus:            test.wantAuthenticated,
		definitions.LogKeyAuthorized:        test.wantAuthz,
		definitions.LogKeyAuthenticatedBool: test.wantAuthn,
	}

	for key, value := range want {
		if fields[key] != value {
			t.Fatalf("final log %s=%q, want %q: %v", key, fields[key], value, fields)
		}
	}
}

// authnFinalLogFields returns the authenticated, authz, and authn fields of the last final log record.
func authnFinalLogFields(t *testing.T, logs string) map[string]string {
	t.Helper()

	var final string

	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, " authn=") {
			final = line
		}
	}

	if final == "" {
		t.Fatalf("no final log record with authn field: %s", logs)
	}

	fields := make(map[string]string, 3)
	for _, match := range authnLogFieldPattern.FindAllStringSubmatch(final, -1) {
		fields[match[1]] = match[2]
	}

	return fields
}
