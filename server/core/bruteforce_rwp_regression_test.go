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
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/gin-gonic/gin"
)

type rwpPrecheckFixture struct {
	auth *AuthState
	ctx  *gin.Context
	logs *bytes.Buffer
}

func TestSuccessfulAuthenticationClearsRWPPrecheckCandidate(t *testing.T) {
	fixture := newRWPPrecheckFixture(t)

	if !fixture.auth.Runtime.BFRWP {
		t.Fatal("expected the pre-auth RWP candidate to be cached")
	}

	fixture.auth.applyBackendResult(fixture.ctx, &PassDBResult{Authenticated: true})

	if fixture.auth.Runtime.BFRWP {
		t.Fatal("successful authentication must not be logged as a repeating wrong password")
	}
}

func TestRWPPrecheckDoesNotLogActiveAllowanceBeforeAuthentication(t *testing.T) {
	fixture := newRWPPrecheckFixture(t)

	if strings.Contains(fixture.logs.String(), "RWP allowance active") {
		t.Fatalf("pre-auth log unexpectedly confirmed an RWP allowance: %s", fixture.logs.String())
	}
}

func TestFailedRWPAllowanceCommitsSlidingWindowWithoutIncrementingBuckets(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	logs := &bytes.Buffer{}
	auth.deps.Logger = slog.New(slog.NewTextHandler(logs, nil))
	auth.Runtime.AccountName = auth.Request.Username

	ctx.Set(definitions.CtxRWPResultKey, false)

	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	mock.Regexp().ExpectSIsMember(".*pw_hist_ips.*", auth.Request.ClientIP).SetVal(true)
	mock.ExpectScriptLoad(rediscli.LuaScripts["RWPSlidingWindowCommit"]).SetVal("sha-rwp-commit")
	mock.Regexp().ExpectEvalSha(
		"sha-rwp-commit",
		[]string{".*bf:rwp:allow:.*"},
		".*", ".*", ".*", ".*",
	).SetVal(int64(1))

	auth.UpdateBruteForceBucketsCounter(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}

	if !strings.Contains(logs.String(), "RWP allowance active") {
		t.Fatalf("confirmed failed request did not log the active RWP allowance: %s", logs.String())
	}
}

// newRWPPrecheckFixture creates a known-account request whose empty RWP window qualifies for allowance.
func newRWPPrecheckFixture(t *testing.T) rwpPrecheckFixture {
	t.Helper()

	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	logs := &bytes.Buffer{}
	auth.deps.Logger = slog.New(slog.NewTextHandler(logs, nil))

	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	mock.Regexp().ExpectHGet(".*", ".*").SetVal(auth.Request.Username)
	mock.ExpectScriptLoad(rediscli.LuaScripts["RWPSlidingWindowCheck"]).SetVal("sha-rwp-check")
	mock.Regexp().ExpectEvalSha(
		"sha-rwp-check",
		[]string{".*bf:rwp:allow:.*"},
		".*", ".*", ".*", ".*",
	).SetVal(int64(1))

	bm := auth.newBruteForceBucketManager(ctx)
	auth.cacheBruteForceRWPDecision(ctx, bm)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}

	return rwpPrecheckFixture{
		auth: auth,
		ctx:  ctx,
		logs: logs,
	}
}
