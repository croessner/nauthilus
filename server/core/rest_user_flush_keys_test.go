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
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib/cacheflush"
	"github.com/croessner/nauthilus/v4/server/model/admin"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
)

const (
	userFlushKeysLogin   = "alice@example.test"
	userFlushKeysAccount = "alice"
)

// userFlushRWPKey builds an RWP allowance key exactly as the brute-force writer formats it, kept independent
// of the production builder so the test detects a writer/flush format drift.
func userFlushRWPKey(prefix string, scopedIP string, identity string) string {
	return prefix + definitions.RedisBFRWPAllowPrefix + scopedIP + ":" + identity
}

// runUserFlush executes the synchronous user flush core for one login name and returns the removed keys.
func (f *accountHistoryFixture) runUserFlush(t *testing.T, username string) []string {
	t.Helper()

	ginCtx := &gin.Context{Request: httptest.NewRequest(http.MethodDelete, "/api/v1/cache/flush", nil)}
	removedKeys, _ := processFlushCache(ginCtx, f.deps, &admin.FlushUserCmd{User: username}, "guid")

	if len(ginCtx.Errors) > 0 {
		t.Fatalf("user flush failed: %v", ginCtx.Errors)
	}

	return removedKeys
}

// seedRWPWindow stores one RWP allowance window with a synthetic password hash.
func (f *accountHistoryFixture) seedRWPWindow(t *testing.T, key string) {
	t.Helper()

	if _, err := f.server.ZAdd(key, 1, "synthetic-hash"); err != nil {
		t.Fatalf("seed RWP window %q: %v", key, err)
	}
}

// assertKeysFlushed checks that every key is gone from Redis and reported as removed.
func (f *accountHistoryFixture) assertKeysFlushed(t *testing.T, removedKeys []string, keys ...string) {
	t.Helper()

	for _, key := range keys {
		if f.server.Exists(key) {
			t.Errorf("key %q survived the user flush", key)
		}

		if !slices.Contains(removedKeys, key) {
			t.Errorf("key %q missing from removed keys %v", key, removedKeys)
		}
	}
}

func TestUserFlushRemovesRWPWindowsOfNamedLogins(t *testing.T) {
	cases := []struct {
		name     string
		clientIP string
		scopedIP string
		rwpCIDR  uint
	}{
		{name: "ipv4", clientIP: "198.51.100.7", scopedIP: "198.51.100.7"},
		{name: "scoped ipv6", clientIP: "2001:db8:1:2::7", scopedIP: "2001:db8:1::/48", rwpCIDR: 48},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAccountHistoryFixture(t)
			fixture.deps.CacheFlushRunner = fixedUserCacheFlushScriptRunner{}
			fixture.deps.Cfg.(*config.FileSettings).BruteForce.IPScoping.RepeatingWrongPasswordIPv6CIDR = tc.rwpCIDR

			fixture.mapLogin(t, userFlushKeysLogin, "imap", "", userFlushKeysAccount)
			fixture.mapLogin(t, userFlushKeysLogin, "oidc", "client-a", userFlushKeysAccount)
			fixture.markAffected(t, userFlushKeysAccount, tc.clientIP)

			keys := []string{
				userFlushRWPKey(fixture.prefix, tc.scopedIP, accountcache.GetAccountMappingField(userFlushKeysLogin, "imap", "")),
				userFlushRWPKey(fixture.prefix, tc.scopedIP, accountcache.GetAccountMappingField(userFlushKeysLogin, "oidc", "client-a")),
				userFlushRWPKey(fixture.prefix, tc.scopedIP, userFlushKeysAccount),
			}

			for _, key := range keys {
				fixture.seedRWPWindow(t, key)
			}

			removedKeys := fixture.runUserFlush(t, userFlushKeysLogin)

			fixture.assertKeysFlushed(t, removedKeys, keys...)
		})
	}
}

func TestUserFlushKeepsRWPWindowsOfOtherLogins(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.deps.CacheFlushRunner = fixedUserCacheFlushScriptRunner{}

	const clientIP = "198.51.100.8"

	fixture.mapLogin(t, userFlushKeysLogin, "imap", "", userFlushKeysAccount)
	fixture.markAffected(t, userFlushKeysAccount, clientIP)

	foreign := userFlushRWPKey(fixture.prefix, clientIP, accountcache.GetAccountMappingField("bob@example.test", "imap", ""))
	fixture.seedRWPWindow(t, foreign)

	fixture.runUserFlush(t, userFlushKeysLogin)

	if !fixture.server.Exists(foreign) {
		t.Fatalf("user flush of %q removed the RWP window of another login", userFlushKeysLogin)
	}
}

func TestUserFlushWithLuaAccountRemovesOwnedMappingFields(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	fixture.deps.CacheFlushRunner = fixedUserCacheFlushScriptRunner{result: &cacheflush.Result{AccountName: userFlushKeysAccount}}

	const clientIP = "198.51.100.9"

	fixture.mapLogin(t, userFlushKeysLogin, "imap", "", "stale-account")
	fixture.mapLogin(t, userFlushKeysLogin, "oidc", "client-a", "stale-account")
	fixture.markAffected(t, userFlushKeysAccount, clientIP)

	rwpKey := userFlushRWPKey(fixture.prefix, clientIP, accountcache.GetAccountMappingField(userFlushKeysLogin, "imap", ""))
	fixture.seedRWPWindow(t, rwpKey)

	removedKeys := fixture.runUserFlush(t, userFlushKeysLogin)

	shardKey := rediscli.GetUserHashKey(fixture.prefix, userFlushKeysLogin)

	for _, field := range []string{
		accountcache.GetAccountMappingField(userFlushKeysLogin, "imap", ""),
		accountcache.GetAccountMappingField(userFlushKeysLogin, "oidc", "client-a"),
	} {
		if fixture.server.HGet(shardKey, field) != "" {
			t.Errorf("mapping field %q survived the Lua-scoped user flush", field)
		}
	}

	fixture.assertKeysFlushed(t, removedKeys, rwpKey)
}
