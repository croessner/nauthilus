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
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	policycollection "github.com/croessner/nauthilus/v4/server/policy/collection"
	"github.com/croessner/nauthilus/v4/server/rediscli"
)

// TestUndecidedRWPVerdictDoesNotCountAsBruteForce covers the failure mode found
// in the 2026-09-22 benchmark. The load group authenticated with correct
// passwords, yet its own /64 was banned: under pressure the sliding-window
// scripts failed with "context canceled", and the counter treated that silence
// as a verdict of "not a repeat".
//
// An unreachable store must leave the verdict unknown. Nothing is weakened by
// declining to count, because the caller answers a temporary failure, which
// never grants access — see
// TestUndecidedRWPVerdictAnswersTemporaryFailure.
func TestUndecidedRWPVerdictDoesNotCountAsBruteForce(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	logs := &bytes.Buffer{}
	auth.deps.Logger = slog.New(slog.NewTextHandler(logs, nil))
	auth.Runtime.AccountName = auth.Request.Username

	ctx.Set(definitions.CtxRWPResultKey, false)

	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()

	// The RWP commit cannot decide. No bucket expectation is registered, so any
	// attempt to write one fails this test as an unexpected command.
	mock.ExpectScriptLoad(rediscli.LuaScripts["RWPSlidingWindowCommit"]).SetVal("sha-rwp-commit")
	mock.Regexp().ExpectEvalSha(
		"sha-rwp-commit",
		[]string{".*bf:rwp:allow:.*"},
		".*", ".*", ".*", ".*", ".*",
	).SetErr(errors.New("context canceled"))

	auth.UpdateBruteForceBucketsCounter(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}

	if !auth.Runtime.BruteForceError {
		t.Fatal("a failed RWP commit must mark brute-force protection as unavailable")
	}

	if auth.Runtime.BFRWP {
		t.Fatal("an undecided verdict must not be reported as a confirmed repeat")
	}

	if !strings.Contains(logs.String(), "RWP verdict unavailable") {
		t.Fatalf("the undecided verdict was not recorded: %s", logs.String())
	}
}

// TestUndecidedRWPVerdictAnswersTemporaryFailure is the other half of the
// contract: declining to count is only safe because the request does not come
// back as a credential rejection.
//
// The assertion deliberately targets the policy attribute rather than
// authnCandidateExecution.authResult. The candidate runtime hands the terminal
// decision to the auth_decision checkpoint, where standard_auth_failure has
// priority 50 and standard_backend_tempfail has priority 30. Only
// auth.backend.tempfail being true lets the temporary failure win, so an
// assertion on authResult alone would pass while production still denied.
func TestUndecidedRWPVerdictAnswersTemporaryFailure(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	auth.Runtime.AccountName = auth.Request.Username

	policyCtx := policycollection.NewDecisionContext(auth.policyOperation(), nil, 0)
	ctx.Set(policyCollectionContextKey, policyCtx)

	// The flag is deliberately not pre-set: the failing commit has to raise it,
	// so the test covers counter -> flag -> attribute rather than only the last
	// link. No bucket expectation is registered, so counting would fail here too.
	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	mock.ExpectScriptLoad(rediscli.LuaScripts["RWPSlidingWindowCommit"]).SetVal("sha-rwp-commit")
	mock.Regexp().ExpectEvalSha(
		"sha-rwp-commit",
		[]string{".*bf:rwp:allow:.*"},
		".*", ".*", ".*", ".*", ".*",
	).SetErr(errors.New("context canceled"))

	auth.applyBackendResult(ctx, &PassDBResult{Authenticated: false})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}

	if !auth.Runtime.BruteForceError {
		t.Fatal("the failed commit must mark brute-force protection as unavailable")
	}

	attribute, ok := policyCtx.Report().Attributes[policy.AttributeBackendTempFail]
	if !ok {
		t.Fatalf("no %s attribute was recorded: %#v", policy.AttributeBackendTempFail, policyCtx.Report().Attributes)
	}

	if attribute.Value != true {
		t.Fatalf("an undecided verdict must be reported to the policy as a temporary failure, got %v", attribute.Value)
	}
}

// TestDecidedAuthFailureStillDeniesNormally guards the other direction: with
// accounting healthy, a wrong password must stay a credential rejection.
func TestDecidedAuthFailureStillDeniesNormally(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	auth.Runtime.AccountName = auth.Request.Username

	policyCtx := policycollection.NewDecisionContext(auth.policyOperation(), nil, 0)
	ctx.Set(policyCollectionContextKey, policyCtx)

	// Healthy accounting: the commit answers "not a repeat", so the counter runs
	// and the failure stays a credential rejection.
	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	mock.ExpectScriptLoad(rediscli.LuaScripts["RWPSlidingWindowCommit"]).SetVal("sha-rwp-commit")
	mock.Regexp().ExpectEvalSha(
		"sha-rwp-commit",
		[]string{".*bf:rwp:allow:.*"},
		".*", ".*", ".*", ".*", ".*",
	).SetVal(int64(0))
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-bucket")
	mock.Regexp().ExpectEvalSha(
		"sha-bucket",
		[]string{".*bf:.*", ".*bf:.*"},
		".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*",
	).SetVal(int64(1))

	auth.applyBackendResult(ctx, &PassDBResult{Authenticated: false})

	if auth.Runtime.BruteForceError {
		t.Fatal("healthy accounting must not mark protection as unavailable")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the healthy path did not exercise Redis as expected: %v", err)
	}

	attribute, ok := policyCtx.Report().Attributes[policy.AttributeBackendTempFail]
	if !ok {
		t.Fatalf("no %s attribute was recorded: %#v", policy.AttributeBackendTempFail, policyCtx.Report().Attributes)
	}

	if attribute.Value != false {
		t.Fatalf("a decided authentication failure must be reported as not temporary, got %v", attribute.Value)
	}
}
