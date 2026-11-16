// Copyright (C) 2026 Christian Roessner
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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/lualib/cacheflush"
	"github.com/croessner/nauthilus/v4/server/model/admin"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

// mapLogin stores one synthetic login-name to account mapping exactly as authentication writes it.
func (f *accountHistoryFixture) mapLogin(t *testing.T, username, protocol, oidcClientID, account string) {
	t.Helper()

	key := rediscli.GetUserHashKey(f.prefix, username)
	field := accountcache.GetAccountMappingField(username, protocol, oidcClientID)

	f.server.HSet(key, field, account)
}

// expectAccountMappingScan declares the shared resolver's single HSCAN step for one login name.
func expectAccountMappingScan(mock redismock.ClientMock, shardKey string, username string, pairs ...string) {
	mock.ExpectHScan(shardKey, 0, username+"|*", 512).SetVal(pairs, 0)
}

// shardSibling returns a username that starts with base+"|" and shares base's user-hash shard.
func shardSibling(t *testing.T, base string) string {
	t.Helper()

	want := rediscli.GetShardID(base)

	for index := range 100000 {
		candidate := fmt.Sprintf("%s|x%d", base, index)
		if rediscli.GetShardID(candidate) == want {
			return candidate
		}
	}

	t.Fatalf("no shard sibling found for %q", base)

	return ""
}

func TestCacheFlushScopeIgnoresMappingsOfUsernamesWithSeparatorPrefix(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	user := "carol"
	sibling := shardSibling(t, user)

	fixture.mapLogin(t, user, "imap", "", "carol-account")
	fixture.mapLogin(t, sibling, "imap", "", "foreign-account")

	scope, err := resolveUserCacheFlushScope(context.Background(), fixture.deps, user, "guid", nil)
	if err != nil {
		t.Fatalf("resolve flush scope: %v", err)
	}

	if slices.Contains(scope.cleanupAccountNames, "foreign-account") {
		t.Fatalf("flush scope for %q captured a foreign account: %v", user, scope.cleanupAccountNames)
	}

	if !slices.Equal(scope.cleanupAccountNames, []string{"carol", "carol-account"}) {
		t.Fatalf("cleanup accounts = %v", scope.cleanupAccountNames)
	}

	foreignField := accountcache.GetAccountMappingField(sibling, "imap", "")
	if slices.Contains(scope.hashFields.GetStringSlice(), foreignField) {
		t.Fatalf("flush scope would delete the foreign mapping field %q", foreignField)
	}
}

// failingAccountMappingReader reports a technical failure for every requested name.
type failingAccountMappingReader struct{}

// ReadMany returns a synthetic Redis failure for each name.
func (failingAccountMappingReader) ReadMany(_ context.Context, usernames []string) []backend.AccountMappingLookup {
	lookups := make([]backend.AccountMappingLookup, len(usernames))
	for index, username := range usernames {
		lookups[index] = backend.AccountMappingLookup{Username: username, Err: errors.New("synthetic outage")}
	}

	return lookups
}

func TestCacheFlushFailsVisiblyWhenAccountMappingsCannotBeRead(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.mapLogin(t, "dave@example.test", "imap", "", "dave")
	fixture.markAffected(t, "dave")

	tokens := &recordingTokenFlusher{}
	fixture.deps.TokenFlusher = tokens
	fixture.deps.CacheFlushRunner = fixedUserCacheFlushScriptRunner{}
	fixture.deps.AccountMappings = failingAccountMappingReader{}

	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(recorder)
	engine.ContextWithFallback = true
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/cache/flush", bytes.NewBufferString(`{"user":"dave@example.test"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	fixture.deps.HandleUserFlush(ctx)

	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "Account mapping lookup failed") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	if !errors.Is(ctx.Errors.Last().Err, errAccountMappingLookup) {
		t.Fatalf("flush error = %v", ctx.Errors.Last().Err)
	}

	if member, _ := fixture.server.SIsMember(rediscli.GetAffectedAccountsKey(fixture.prefix), "dave"); !member || len(tokens.users) != 0 {
		t.Fatalf("failed flush must not partially clean state: member=%v tokens=%v", member, tokens.users)
	}
}

func TestAsyncCacheFlushJobFailsWhenAccountMappingsCannotBeRead(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.deps.CacheFlushRunner = fixedUserCacheFlushScriptRunner{}
	fixture.deps.AccountMappings = failingAccountMappingReader{}

	ginCtx := &gin.Context{Request: httptest.NewRequest(http.MethodDelete, "/api/v1/cache/flush/async", nil)}
	removedKeys, _ := processFlushCache(ginCtx, fixture.deps, &admin.FlushUserCmd{User: "dave"}, "guid")

	// The async starter returns gctx.Errors.Last() as the job error, so the job is marked failed.
	if len(removedKeys) != 0 || len(ginCtx.Errors) == 0 || !errors.Is(ginCtx.Errors.Last().Err, errAccountMappingLookup) {
		t.Fatalf("removed=%v errors=%v", removedKeys, ginCtx.Errors)
	}
}

func TestCacheFlushKeepsLuaAccountPrecedenceWithoutMappingRead(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.deps.AccountMappings = failingAccountMappingReader{}

	scope, err := resolveUserCacheFlushScope(context.Background(), fixture.deps, "erin@example.test", "guid",
		&cacheflush.Result{AccountName: "erin"})
	if err != nil {
		t.Fatalf("Lua-provided account must not depend on the mapping read: %v", err)
	}

	if !slices.Equal(scope.cleanupAccountNames, []string{"erin", "erin@example.test"}) || !slices.Equal(scope.tokenAccountNames, []string{"erin"}) {
		t.Fatalf("scope = %+v", scope)
	}
}
