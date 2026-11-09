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
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/policy"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// rejectingLuaSubject answers one non-success result the way the Lua subject runner does for a reject result
// (fail) or a script error (tempfail): it marks the request unauthorized and leaves the credential result alone.
type rejectingLuaSubject struct {
	result definitions.AuthResult
}

// AnalyzeSource marks the request unauthorized and answers the configured result.
func (s rejectingLuaSubject) AnalyzeSource(
	_ *gin.Context,
	view *StateView,
	_ *PassDBResult,
	_ string,
	_ *lua.FunctionProto,
	_ *vmpool.Manager,
	_ vmpool.PoolKey,
	_ *luaseal.Modules,
) definitions.AuthResult {
	view.Auth().Runtime.Authorized = false

	return s.result
}

// subjectRejectionStateCase binds one subject source outcome after a verified credential to the request state that
// later providers, post-actions, and request snapshots must observe.
type subjectRejectionStateCase struct {
	subject           CapturedLuaSubject
	run               func(*testing.T, *authnFSMGuardHarness) bool
	name              string
	wantAuthenticated bool
	wantAuthorized    bool
	wantTerminal      bool
}

// runSubjectRejectionLua runs one Lua subject source and returns whether it ends the subject checkpoint.
func runSubjectRejectionLua(t *testing.T, h *authnFSMGuardHarness) bool {
	t.Helper()

	terminal, err := h.execution.prepareLuaSubjectSource("subject", &lua.FunctionProto{}, nil, "", nil)
	if err != nil {
		t.Fatalf("prepareLuaSubjectSource() error = %v", err)
	}

	return terminal
}

// runSubjectRejectionNative returns a runner for one native subject source that may reject the request.
func runSubjectRejectionNative(rejected bool) func(*testing.T, *authnFSMGuardHarness) bool {
	return func(t *testing.T, h *authnFSMGuardHarness) bool {
		t.Helper()

		provider := &authnCapturedNativeSubjectSource{id: "authn/plugin.example.subject.protocol", rejected: rejected}

		terminal, err := h.execution.prepareNativeSubjectSource(provider.id, provider)
		if err != nil {
			t.Fatalf("prepareNativeSubjectSource() error = %v", err)
		}

		return terminal
	}
}

// subjectRejectionStateCases lists Lua and native subject outcomes that must leave the same request state.
func subjectRejectionStateCases() []subjectRejectionStateCase {
	return []subjectRejectionStateCase{
		{
			name: "Lua subject permits", subject: testLuaSubject{}, run: runSubjectRejectionLua,
			wantAuthenticated: true, wantAuthorized: true,
		},
		{
			name: "native subject permits", run: runSubjectRejectionNative(false),
			wantAuthenticated: true, wantAuthorized: true,
		},
		{
			name: "Lua subject rejects", subject: rejectingLuaSubject{result: definitions.AuthResultFail},
			run: runSubjectRejectionLua, wantTerminal: true,
		},
		{
			name: "Lua subject fails temporarily", subject: rejectingLuaSubject{result: definitions.AuthResultTempFail},
			run: runSubjectRejectionLua, wantTerminal: true,
		},
		{
			name: "native subject rejects", run: runSubjectRejectionNative(true), wantTerminal: true,
		},
	}
}

// TestAuthnSubjectRejectionLeavesRequestUnauthenticated proves that Lua and native subject sources update the
// request state the same way: once a subject source does not permit a verified credential, the request is no longer
// authenticated, so run_if=authenticated providers, post-actions, and snapshots see the failed outcome.
func TestAuthnSubjectRejectionLeavesRequestUnauthenticated(t *testing.T) {
	for _, test := range subjectRejectionStateCases() {
		t.Run(test.name, func(t *testing.T) {
			subject := test.subject
			if subject == nil {
				subject = testLuaSubject{}
			}

			harness := newAuthnFSMGuardHarness(
				t, policy.OperationAuthenticate, authnFSMGuardVerifier{authenticated: true, userFound: true}, subject,
			)
			harness.runBackend(t)

			auth := harness.execution.auth
			auth.Runtime.StatusCodeOK = http.StatusOK
			auth.Runtime.StatusCodeFail = http.StatusForbidden

			if terminal := test.run(t, harness); terminal != test.wantTerminal {
				t.Fatalf("subject source terminal = %t, want %t", terminal, test.wantTerminal)
			}

			assertSubjectRejectionState(t, auth, test)
		})
	}
}

// assertSubjectRejectionState checks the request flags and the post-action request projection after one subject.
func assertSubjectRejectionState(t *testing.T, auth *AuthState, test subjectRejectionStateCase) {
	t.Helper()

	if got := auth.Runtime.Authenticated; got != test.wantAuthenticated {
		t.Fatalf("Runtime.Authenticated = %t, want %t", got, test.wantAuthenticated)
	}

	if got := auth.Runtime.Authorized; got != test.wantAuthorized {
		t.Fatalf("Runtime.Authorized = %t, want %t", got, test.wantAuthorized)
	}

	if !auth.Runtime.authnLogValue() {
		t.Fatal("authn log value = false, want the verified credential to stay reported")
	}

	request := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(request)

	auth.FillCommonRequest(request)

	wantStatus := auth.Runtime.StatusCodeFail
	if test.wantAuthenticated {
		wantStatus = auth.Runtime.StatusCodeOK
	}

	if request.Authenticated != test.wantAuthenticated || request.HTTPStatus != wantStatus {
		t.Fatalf(
			"common request authenticated=%t http_status=%d, want authenticated=%t http_status=%d",
			request.Authenticated, request.HTTPStatus, test.wantAuthenticated, wantStatus,
		)
	}
}
