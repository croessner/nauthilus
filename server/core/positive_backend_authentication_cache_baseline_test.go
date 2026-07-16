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
	"context"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/secret"

	"github.com/gin-gonic/gin"
)

// storeBackendAuthenticationForCacheMechanics seeds raw storage only for storage/index tests.
func storeBackendAuthenticationForCacheMechanics(
	cache *PositiveBackendAuthenticationCache,
	key BackendAuthenticationCacheKey,
	decision *CachedBackendAuthentication,
	ttl time.Duration,
	identities ...string,
) bool {
	return cache.storeOwned(key, decision, ttl, identities...)
}

// mustBuildBackendAuthenticationCacheKey builds a key from complete test request dependencies.
func mustBuildBackendAuthenticationCacheKey(t *testing.T, auth *AuthState) BackendAuthenticationCacheKey {
	t.Helper()

	key, ok := buildBackendAuthenticationCacheKey(auth)
	if !ok {
		t.Fatal("backend authentication cache key construction failed")
	}

	return key
}

func TestBackendAuthenticationCacheKeyDoesNotContainCleartextCredential(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, _ := newRequestOwnedContractAuth(t, cfg, "key-user@example.test", "baseline-clear-credential", "baseline-key")

	if key := mustBuildBackendAuthenticationCacheKey(t, auth).storageKey(); strings.Contains(key, "baseline-clear-credential") {
		t.Fatal("local authentication key contains the clear credential")
	}
}

func TestCachedBackendAuthenticationCaptureIgnoresFinalAuthorityState(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "unauthorized@example.test", "credential", "baseline-gate")

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	auth.Runtime.Authorized = false
	auth.Runtime.AuthFSMTerminalState = string(authFSMStateAuthOK)

	if _, ok := captureCachedBackendAuthentication(ctx, auth, result); !ok {
		t.Fatal("complete backend success depended on final authority state")
	}
}

func TestCachedBackendAuthenticationOwnsNestedMutableValues(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "copy@example.test", "credential", "baseline-copy")
	result := newSemanticPassDBResult(ctx, auth)

	defer PutPassDBResultToPool(result)

	nested := []any{"original"}
	result.AdditionalAttributes = map[string]any{
		"nested": nested,
		"groups": []string{"one", "two"},
		"bytes":  []byte{1, 2, 3},
	}
	auth.Runtime.AuthFSMTerminalState = string(authFSMStateAuthOK)
	decision, ok := captureCachedBackendAuthentication(ctx, auth, result)

	if !ok {
		t.Fatal("final positive decision was not captured")
	}

	clone, ok := decision.materialize()

	if !ok {
		t.Fatal("decision clone failed")
	}

	clone.additionalAttributes["nested"].([]any)[0] = definitions.AuthResultFail
	if _, ok := clone.additionalAttributes["groups"].([]string); !ok {
		t.Fatalf("typed slice changed to %T", clone.additionalAttributes["groups"])
	}

	if _, ok := clone.additionalAttributes["bytes"].([]byte); !ok {
		t.Fatalf("byte slice changed to %T", clone.additionalAttributes["bytes"])
	}

	if got := nested[0]; got != "original" {
		t.Fatalf("source nested value was mutated through cached clone: %v", got)
	}
}

type backendAuthenticationOwnershipFixture struct {
	cache  *PositiveBackendAuthenticationCache
	source *AuthState
	key    BackendAuthenticationCacheKey
	nested []any
}

// newBackendAuthenticationOwnershipFixture stores one decision containing a nested mutable value.
func newBackendAuthenticationOwnershipFixture(t *testing.T) backendAuthenticationOwnershipFixture {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	cache := NewPositiveBackendAuthenticationCache(time.Now)
	source, ctx := newRequestOwnedContractAuth(t, cfg, "ownership@example.test", "credential", "ownership")
	result := newSemanticPassDBResult(ctx, source)
	nested := []any{"original"}
	result.AdditionalAttributes = map[string]any{"nested": nested}

	if !cache.StoreForRequest(ctx, source, result, time.Minute, source.Request.Username) {
		PutPassDBResultToPool(result)
		t.Fatal("decision store failed")
	}

	PutPassDBResultToPool(result)

	return backendAuthenticationOwnershipFixture{
		cache: cache, source: source,
		key: mustBuildBackendAuthenticationCacheKey(t, source), nested: nested,
	}
}

// loadBackendAuthenticationForOwnership returns one independently owned cached decision.
func loadBackendAuthenticationForOwnership(t *testing.T, cache *PositiveBackendAuthenticationCache, key BackendAuthenticationCacheKey) *appliedBackendAuthentication {
	t.Helper()

	decision, found := cache.load(key)
	if !found {
		t.Fatal("cached decision missed")
	}

	return decision
}

// loadedBackendAuthenticationNestedOwnershipValue returns the nested marker from one owned load.
func loadedBackendAuthenticationNestedOwnershipValue(t *testing.T, cache *PositiveBackendAuthenticationCache, key BackendAuthenticationCacheKey) (*appliedBackendAuthentication, any) {
	t.Helper()

	decision := loadBackendAuthenticationForOwnership(t, cache, key)

	return decision, decision.additionalAttributes["nested"].([]any)[0]
}

func TestPositiveBackendAuthenticationCacheOwnsSourceAfterStore(t *testing.T) {
	fixture := newBackendAuthenticationOwnershipFixture(t)
	fixture.nested[0] = "source-mutated"
	fixture.source.Runtime.AdditionalAttributes = map[string]any{"nested": []any{"runtime-mutated"}}

	_, got := loadedBackendAuthenticationNestedOwnershipValue(t, fixture.cache, fixture.key)

	if got != "original" {
		t.Fatalf("source mutation changed stored decision: %v", got)
	}
}

func TestPositiveBackendAuthenticationCacheRepeatedLoadsAreIsolated(t *testing.T) {
	fixture := newBackendAuthenticationOwnershipFixture(t)
	first, _ := loadedBackendAuthenticationNestedOwnershipValue(t, fixture.cache, fixture.key)
	first.additionalAttributes["nested"].([]any)[0] = "first-load-mutated"
	_, got := loadedBackendAuthenticationNestedOwnershipValue(t, fixture.cache, fixture.key)

	if got != "original" {
		t.Fatalf("first load mutation changed later load: %v", got)
	}
}

func TestPositiveBackendAuthenticationCacheWarmRequestsAreIsolated(t *testing.T) {
	fixture := newBackendAuthenticationOwnershipFixture(t)
	first, firstCtx := newRequestOwnedContractAuth(t, fixture.source.Cfg().(*config.FileSettings), fixture.source.Request.Username, "credential", "warm-first")
	second, secondCtx := newRequestOwnedContractAuth(t, fixture.source.Cfg().(*config.FileSettings), fixture.source.Request.Username, "credential", "warm-second")

	if !fixture.cache.ApplyForRequest(firstCtx, first) {
		t.Fatal("first warm apply missed")
	}

	first.Runtime.AdditionalAttributes["nested"].([]any)[0] = "first-warm-mutated"

	if !fixture.cache.ApplyForRequest(secondCtx, second) {
		t.Fatal("second warm apply missed")
	}

	if got := second.Runtime.AdditionalAttributes["nested"].([]any)[0]; got != "original" {
		t.Fatalf("first warm mutation changed second warm result: %v", got)
	}
}

func TestPositiveBackendAuthenticationCacheSurvivesPassDBResultPoolResetAndReuse(t *testing.T) {
	fixture := newBackendAuthenticationOwnershipFixture(t)
	pooled := GetPassDBResultFromPool()
	pooled.AdditionalAttributes = map[string]any{"nested": []any{"pooled-mutated"}}
	pooled.Attributes = bktype.AttributeMapping{"uid": {"pooled-mutated"}}
	PutPassDBResultToPool(pooled)

	_, got := loadedBackendAuthenticationNestedOwnershipValue(t, fixture.cache, fixture.key)

	if got != "original" {
		t.Fatalf("pooled result reset/reuse changed stored decision: %v", got)
	}
}

func TestPositiveBackendAuthenticationCacheStoresOwnedPluginPolicyFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cache := NewPositiveBackendAuthenticationCache(time.Now)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "plugin-facts@example.test", "credential", "plugin-facts")
	result := newSemanticPassDBResult(ctx, auth)

	defer PutPassDBResultToPool(result)

	factValue := map[string]any{"roles": []string{"reader", "writer"}}
	result.Backend = definitions.BackendPlugin
	result.AdditionalAttributes = map[string]any{
		PassDBAdditionalAttributePluginFacts: []pluginapi.PolicyFact{
			{Attribute: "auth.plugin.risk", Value: factValue},
		},
	}

	if !cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
		t.Fatal("complete plugin backend authentication with policy facts was not stored")
	}

	factValue["roles"].([]string)[0] = "source-mutated"

	loaded, found := cache.load(mustBuildBackendAuthenticationCacheKey(t, auth))
	if !found {
		t.Fatal("stored plugin backend authentication missed")
	}

	facts, ok := loaded.additionalAttributes[PassDBAdditionalAttributePluginFacts].([]pluginapi.PolicyFact)
	if !ok || len(facts) != 1 {
		t.Fatalf("plugin policy facts type = %T, want []pluginapi.PolicyFact", loaded.additionalAttributes[PassDBAdditionalAttributePluginFacts])
	}

	roles := facts[0].Value.(map[string]any)["roles"].([]string)
	if roles[0] != "reader" {
		t.Fatalf("source mutation crossed cache ownership boundary: %#v", roles)
	}

	roles[0] = "loaded-mutated"
	reloaded, _ := cache.load(mustBuildBackendAuthenticationCacheKey(t, auth))
	reloadedFacts := reloaded.additionalAttributes[PassDBAdditionalAttributePluginFacts].([]pluginapi.PolicyFact)
	reloadedRoles := reloadedFacts[0].Value.(map[string]any)["roles"].([]string)

	if reloadedRoles[0] != "reader" {
		t.Fatalf("loaded mutation crossed cache ownership boundary: %#v", reloadedRoles)
	}
}

func TestBackendAuthenticationCacheKeySeparatesDimensions(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	base, _ := newRequestOwnedContractAuth(t, cfg, "key@example.test", "credential", "key-base")
	base.Request.Service = "smtp"
	base.Request.Protocol.Set("smtp")
	base.Request.ClientIP = "192.0.2.1"
	baseKey := mustBuildBackendAuthenticationCacheKey(t, base)

	cases := []func(*AuthState){
		func(auth *AuthState) { auth.Request.Username = "other@example.test" },
		func(auth *AuthState) { auth.Request.Service = "imap" },
		func(auth *AuthState) { auth.Request.Protocol.Set("imap") },
		func(auth *AuthState) { auth.Request.ClientIP = "192.0.2.2" },
		func(auth *AuthState) { auth.Request.Password = base.Request.Password },
	}
	for index, mutate := range cases {
		candidate, _ := newRequestOwnedContractAuth(t, cfg, "key@example.test", "credential", "key-candidate")
		candidate.Request.Service = "smtp"
		candidate.Request.Protocol.Set("smtp")
		candidate.Request.ClientIP = "192.0.2.1"
		mutate(candidate)

		if index == len(cases)-1 {
			candidate.Request.Password = secret.New("different")
		}

		if reflect.DeepEqual(mustBuildBackendAuthenticationCacheKey(t, candidate), baseKey) {
			t.Fatalf("dimension case %d did not change key", index)
		}
	}
}

func TestPositiveBackendAuthenticationCacheExpiryAndIdentityInvalidation(t *testing.T) {
	now := time.Unix(100, 0)
	cache := NewPositiveBackendAuthenticationCache(func() time.Time { return now })
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "alias@example.test", "credential", "cache-lifecycle")
	result := newSemanticPassDBResult(ctx, auth)

	defer PutPassDBResultToPool(result)

	auth.Runtime.AuthFSMTerminalState = string(authFSMStateAuthOK)

	key := mustBuildBackendAuthenticationCacheKey(t, auth)
	if !cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username, auth.GetAccount()) {
		t.Fatal("store failed")
	}

	if _, found := cache.load(key); !found {
		t.Fatal("fresh decision missed")
	}

	if removed := cache.InvalidateIdentities(auth.Request.Username); removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	if _, found := cache.load(key); found {
		t.Fatal("invalidated decision hit")
	}

	if !cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
		t.Fatal("second store failed")
	}

	now = now.Add(time.Minute)

	if _, found := cache.load(key); found {
		t.Fatal("expired decision hit")
	}
}

type backendAuthenticationStoreCase struct {
	name                string
	monitoring          bool
	master              bool
	canceled            bool
	noAuth              bool
	nilResult           bool
	resultAuthenticated bool
	resultUserFound     bool
	emptyCredential     bool
	wantStore           bool
}

// backendAuthenticationStoreCases defines the complete positive-only admission contract.
func backendAuthenticationStoreCases() []backendAuthenticationStoreCase {
	return []backendAuthenticationStoreCase{
		{name: "complete positive backend", resultAuthenticated: true, resultUserFound: true, wantStore: true},
		{name: "later unauthorized state is irrelevant", resultAuthenticated: true, resultUserFound: true, wantStore: true},
		{name: "backend failure", resultUserFound: true},
		{name: "identity not found", resultAuthenticated: true},
		{name: "nil result", nilResult: true},
		{name: "actual empty credential", resultAuthenticated: true, resultUserFound: true, emptyCredential: true},
		{name: "no auth", resultAuthenticated: true, resultUserFound: true, noAuth: true},
		{name: "canceled", resultAuthenticated: true, resultUserFound: true, canceled: true},
		{name: "monitoring", resultAuthenticated: true, resultUserFound: true, monitoring: true},
		{name: "master user", resultAuthenticated: true, resultUserFound: true, master: true},
	}
}

// runBackendAuthenticationStoreCase exercises one admission-gate scenario.
func runBackendAuthenticationStoreCase(t *testing.T, testCase backendAuthenticationStoreCase) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	username := "gate@example.test"

	if testCase.master {
		cfg.Server.MasterUser = config.MasterUser{Enabled: true, UserFormat: config.DefaultMasterUserFormat}
		username += "*admin@example.test"
	}

	credential := "credential"

	if testCase.emptyCredential {
		credential = ""
	}

	auth, ctx := newRequestOwnedContractAuth(t, cfg, username, credential, "gate")
	auth.deps.BackendAuthenticationCache = NewPositiveBackendAuthenticationCache(time.Now)
	result := newSemanticPassDBResult(ctx, auth)
	result.Authenticated = testCase.resultAuthenticated
	result.UserFound = testCase.resultUserFound

	if testCase.nilResult {
		PutPassDBResultToPool(result)
		result = nil
	} else {
		defer PutPassDBResultToPool(result)
	}

	auth.Request.NoAuth = testCase.noAuth

	if testCase.canceled {
		requestContext, cancel := context.WithCancel(context.Background())
		attachContractContext(requestContext, auth, ctx)
		cancel()
	}

	if testCase.monitoring {
		auth.Runtime.MonitoringFlags = []definitions.Monitoring{definitions.MonInMemory}
	}

	if got := auth.storePositiveBackendAuthentication(ctx, result); got != testCase.wantStore {
		t.Fatalf("store = %v, want %v", got, testCase.wantStore)
	}
}

func TestPositiveBackendAuthenticationCacheStoresOnlyCompletePositiveBackendAuthentication(t *testing.T) {
	for _, testCase := range backendAuthenticationStoreCases() {
		t.Run(testCase.name, func(t *testing.T) {
			runBackendAuthenticationStoreCase(t, testCase)
		})
	}
}

// cancelBackendAuthenticationContext cancels exactly one request-context source.
func cancelBackendAuthenticationContext(t *testing.T, source string, auth *AuthState, ctx *gin.Context) {
	t.Helper()

	ctx.Request = ctx.Request.WithContext(context.Background())
	auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(context.Background())
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	switch source {
	case "gin":
		ctx.Request = ctx.Request.WithContext(canceledContext)
	case "auth":
		auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(canceledContext)
	default:
		t.Fatalf("unknown context source %q", source)
	}
}

func TestPositiveBackendAuthenticationCacheStoreBoundaryRejectsCanceledRequests(t *testing.T) {
	for _, source := range []string{"gin", "auth"} {
		t.Run(source, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			auth, ctx := newRequestOwnedContractAuth(t, cfg, "store-canceled@example.test", "credential", "store-canceled")

			result := newSemanticPassDBResult(ctx, auth)
			defer PutPassDBResultToPool(result)

			cancelBackendAuthenticationContext(t, source, auth, ctx)

			cache := NewPositiveBackendAuthenticationCache(time.Now)

			if cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
				t.Fatal("canceled request crossed the store boundary")
			}
		})
	}
}

func TestPositiveBackendAuthenticationCacheApplyBoundaryRejectsCanceledRequests(t *testing.T) {
	for _, source := range []string{"gin", "auth"} {
		t.Run(source, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			cache := NewPositiveBackendAuthenticationCache(time.Now)
			auth, ctx := newRequestOwnedContractAuth(t, cfg, "apply-canceled@example.test", "credential", "apply-canceled")

			result := newSemanticPassDBResult(ctx, auth)
			defer PutPassDBResultToPool(result)

			if !cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
				t.Fatal("failed to seed decision")
			}

			cancelBackendAuthenticationContext(t, source, auth, ctx)

			if cache.ApplyForRequest(ctx, auth) {
				t.Fatal("canceled request crossed the apply boundary")
			}
		})
	}
}

func TestPositiveBackendAuthenticationCacheBoundariesRejectOtherIneligibleRequests(t *testing.T) {
	for _, gate := range []string{"zero credential", "monitoring", "master"} {
		t.Run(gate, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			username := "boundary@example.test"

			if gate == "master" {
				cfg.Server.MasterUser = config.MasterUser{Enabled: true, UserFormat: config.DefaultMasterUserFormat}
				username += "*admin@example.test"
			}

			auth, ctx := newRequestOwnedContractAuth(t, cfg, username, "credential", "boundary")

			result := newSemanticPassDBResult(ctx, auth)

			defer PutPassDBResultToPool(result)

			decision, ok := captureCachedBackendAuthentication(ctx, auth, result)
			if !ok {
				t.Fatal("capture failed")
			}

			key := mustBuildBackendAuthenticationCacheKey(t, auth)

			switch gate {
			case "zero credential":
				auth.Request.Password = secret.New("")
			case "monitoring":
				auth.Runtime.MonitoringFlags = []definitions.Monitoring{definitions.MonInMemory}
			}

			cache := NewPositiveBackendAuthenticationCache(time.Now)

			if cache.StoreForRequest(ctx, auth, result, time.Minute, username) {
				t.Fatal("ineligible request crossed the store boundary")
			}

			if !storeBackendAuthenticationForCacheMechanics(cache, key, decision, time.Minute, username) {
				t.Fatal("failed to seed raw boundary fixture")
			}

			if cache.ApplyForRequest(ctx, auth) {
				t.Fatal("ineligible request crossed the apply boundary")
			}
		})
	}
}

type nilBackendAuthenticationBoundaryCase struct {
	name        string
	nilContext  bool
	nilAuth     bool
	nilGinReq   bool
	nilAuthReq  bool
	wantAllowed bool
}

// nilBackendAuthenticationBoundaryCases defines safe behavior for missing request holders.
func nilBackendAuthenticationBoundaryCases() []nilBackendAuthenticationBoundaryCase {
	return []nilBackendAuthenticationBoundaryCase{
		{name: "nil context", nilContext: true},
		{name: "nil auth", nilAuth: true},
		{name: "nil gin request", nilGinReq: true, wantAllowed: true},
		{name: "nil auth http request", nilAuthReq: true, wantAllowed: true},
		{name: "both request sources nil", nilGinReq: true, nilAuthReq: true},
	}
}

func TestPositiveBackendAuthenticationCacheNilRequestBoundaries(t *testing.T) {
	for _, testCase := range nilBackendAuthenticationBoundaryCases() {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			cache := NewPositiveBackendAuthenticationCache(time.Now)
			auth, ctx := newRequestOwnedContractAuth(t, cfg, "nil-boundary@example.test", "credential", "nil-boundary")

			result := newSemanticPassDBResult(ctx, auth)
			defer PutPassDBResultToPool(result)

			if testCase.nilGinReq {
				ctx.Request = nil
			}

			if testCase.nilAuthReq {
				auth.Request.HTTPClientRequest = nil
			}

			storeCtx := ctx
			storeAuth := auth

			if testCase.nilContext {
				storeCtx = nil
			}

			if testCase.nilAuth {
				storeAuth = nil
			}

			if got := cache.StoreForRequest(storeCtx, storeAuth, result, time.Minute, auth.Request.Username); got != testCase.wantAllowed {
				t.Fatalf("store allowed = %v, want %v", got, testCase.wantAllowed)
			}

			if got := cache.ApplyForRequest(storeCtx, storeAuth); got != testCase.wantAllowed {
				t.Fatalf("apply allowed = %v, want %v", got, testCase.wantAllowed)
			}
		})
	}
}

func TestPositiveBackendAuthenticationCacheMissingRequestKeyDependenciesMissesWithoutFallback(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cache := NewPositiveBackendAuthenticationCache(time.Now)
	source, sourceCtx := newRequestOwnedContractAuth(t, cfg, "missing-key-deps@example.test", "credential", "missing-key-source")
	result := newSemanticPassDBResult(sourceCtx, source)

	defer PutPassDBResultToPool(result)

	if !cache.StoreForRequest(sourceCtx, source, result, time.Minute, source.Request.Username) {
		t.Fatal("seed store failed")
	}

	missingConfig, missingConfigCtx := newRequestOwnedContractAuth(t, cfg, source.Request.Username, "credential", "missing-config")
	missingConfig.deps.BackendAuthenticationCache = cache
	missingConfig.deps.Cfg = nil

	if missingConfig.GetFromLocalCache(missingConfigCtx) {
		t.Fatal("missing request config used a fallback cache key")
	}

	if cache.StoreForRequest(missingConfigCtx, missingConfig, result, time.Minute, source.Request.Username) {
		t.Fatal("missing request config admitted a cache store")
	}

	if missingConfig.storePositiveBackendAuthentication(missingConfigCtx, result) {
		t.Fatal("missing request config crossed the production store boundary")
	}

	missingEnvironment, missingEnvironmentCtx := newRequestOwnedContractAuth(t, cfg, source.Request.Username, "credential", "missing-environment")
	missingEnvironment.deps.BackendAuthenticationCache = cache
	missingEnvironment.deps.Env = nil

	if !missingEnvironment.GetFromLocalCache(missingEnvironmentCtx) {
		t.Fatal("missing request environment changed the configuration-owned cache key")
	}

	if !cache.StoreForRequest(missingEnvironmentCtx, missingEnvironment, result, time.Minute, source.Request.Username) {
		t.Fatal("missing request environment blocked an otherwise eligible cache store")
	}

	if !missingEnvironment.storePositiveBackendAuthentication(missingEnvironmentCtx, result) {
		t.Fatal("missing request environment blocked the production store boundary")
	}

	if cache.storage.Len() != 1 {
		t.Fatalf("missing dependency boundary changed storage size to %d, want 1", cache.storage.Len())
	}
}

func TestCachedBackendAuthenticationRejectsCyclicMutableState(t *testing.T) {
	testCases := map[string]func() any{
		"map": func() any {
			value := make(map[string]any)
			value["self"] = value

			return value
		},
		"slice": func() any {
			value := make([]any, 1)
			value[0] = value

			return value
		},
	}

	for name, cyclicValue := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			auth, ctx := newRequestOwnedContractAuth(t, cfg, "cycle@example.test", "credential", "cycle")

			result := newSemanticPassDBResult(ctx, auth)
			defer PutPassDBResultToPool(result)

			result.AdditionalAttributes = map[string]any{"cyclic": cyclicValue()}

			if _, ok := captureCachedBackendAuthentication(ctx, auth, result); ok {
				t.Fatal("cyclic mutable state was captured")
			}

			if !auth.Runtime.Authenticated || !auth.Runtime.Authorized {
				t.Fatal("safe cache skip changed the successful authentication decision")
			}
		})
	}
}

func TestPositiveBackendAuthenticationCacheRejectsPathologicalValueBudgets(t *testing.T) {
	testCases := map[string]func() any{
		"depth": func() any {
			var value any = "leaf"

			for range backendAuthenticationMaxValueDepth + 1 {
				value = map[string]any{"next": value}
			}

			return value
		},
		"nodes": func() any {
			values := make([]any, backendAuthenticationMaxValueNodes)

			for index := range values {
				values[index] = index
			}

			return values
		},
	}

	for name, pathologicalValue := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			cache := NewPositiveBackendAuthenticationCache(time.Now)
			auth, ctx := newRequestOwnedContractAuth(t, cfg, "budget@example.test", "credential", "budget")
			result := newSemanticPassDBResult(ctx, auth)

			defer PutPassDBResultToPool(result)

			result.AdditionalAttributes = map[string]any{"pathological": pathologicalValue()}

			if cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
				t.Fatal("pathological backend value crossed the bounded cache contract")
			}

			if cache.storage.Len() != 0 {
				t.Fatal("rejected backend value left cache state behind")
			}
		})
	}
}

func TestPositiveBackendAuthenticationCacheTransfersOwnershipWithoutRedundantCopies(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cache := NewPositiveBackendAuthenticationCache(time.Now)
	source, sourceCtx := newRequestOwnedContractAuth(t, cfg, "copy-count@example.test", "credential", "copy-count-source")
	result := newSemanticPassDBResult(sourceCtx, source)

	defer PutPassDBResultToPool(result)

	result.AdditionalAttributes = map[string]any{
		"nested": map[string]any{"groups": []string{"reader", "writer"}},
	}

	snapshot, ok := captureCachedBackendAuthentication(sourceCtx, source, result)
	if !ok {
		t.Fatal("positive backend authentication was not captured")
	}

	key := mustBuildBackendAuthenticationCacheKey(t, source)
	if !cache.storeOwned(key, snapshot, time.Minute, source.Request.Username) {
		t.Fatal("positive backend authentication was not stored")
	}

	stored, found := cache.loadSnapshot(key)
	if !found || stored != snapshot {
		t.Fatal("store boundary copied instead of transferring immutable snapshot ownership")
	}

	warm, warmCtx := newRequestOwnedContractAuth(t, cfg, source.Request.Username, "credential", "copy-count-warm")
	if !cache.ApplyForRequest(warmCtx, warm) {
		t.Fatal("positive backend authentication warm apply missed")
	}

	requestOwned, found := cachedBackendAuthenticationForRequest(warmCtx)
	if !found {
		t.Fatal("warm request did not retain its materialized snapshot")
	}

	projected, ok := requestOwned.passDBResult()
	if !ok {
		t.Fatal("warm request snapshot did not project to a backend result")
	}
	defer PutPassDBResultToPool(projected)

	projected.AdditionalAttributes["nested"].(map[string]any)["groups"].([]string)[0] = "request-mutated"
	groups := warm.Runtime.AdditionalAttributes["nested"].(map[string]any)["groups"].([]string)

	if groups[0] != "request-mutated" {
		t.Fatal("request-local projection introduced a redundant deep copy")
	}

	loaded, found := cache.load(key)
	if !found {
		t.Fatal("cache missed after request-owned mutation")
	}

	storedGroups := loaded.additionalAttributes["nested"].(map[string]any)["groups"].([]string)
	if storedGroups[0] != "reader" {
		t.Fatalf("warm request exposed cache-owned memory: %#v", storedGroups)
	}
}

// storeSharedAcyclicBranches stores the same acyclic container under sibling branches.
func storeSharedAcyclicBranches(t *testing.T, shared any) (*PositiveBackendAuthenticationCache, BackendAuthenticationCacheKey) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	cache := NewPositiveBackendAuthenticationCache(time.Now)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "shared@example.test", "credential", "shared")

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	result.AdditionalAttributes = map[string]any{"left": shared, "right": shared}

	if !cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
		t.Fatal("shared acyclic decision was not stored")
	}

	return cache, mustBuildBackendAuthenticationCacheKey(t, auth)
}

func TestPositiveBackendAuthenticationCacheAcceptsSharedAcyclicMapBranches(t *testing.T) {
	source := map[string]any{"marker": "original"}
	cache, key := storeSharedAcyclicBranches(t, source)
	loaded := loadBackendAuthenticationForOwnership(t, cache, key)
	left := loaded.additionalAttributes["left"].(map[string]any)
	right := loaded.additionalAttributes["right"].(map[string]any)
	left["marker"] = "mutated"

	if source["marker"] != "original" || right["marker"] != "original" {
		t.Fatal("shared map branches or source remained aliased")
	}

	next := loadBackendAuthenticationForOwnership(t, cache, key)

	if next.additionalAttributes["left"].(map[string]any)["marker"] != "original" ||
		next.additionalAttributes["right"].(map[string]any)["marker"] != "original" {
		t.Fatal("shared map mutation crossed into a later load")
	}
}

func TestPositiveBackendAuthenticationCacheAcceptsSharedAcyclicSliceBranches(t *testing.T) {
	source := []any{"original"}
	cache, key := storeSharedAcyclicBranches(t, source)
	loaded := loadBackendAuthenticationForOwnership(t, cache, key)
	left := loaded.additionalAttributes["left"].([]any)
	right := loaded.additionalAttributes["right"].([]any)
	left[0] = "mutated"

	if source[0] != "original" || right[0] != "original" {
		t.Fatal("shared slice branches or source remained aliased")
	}

	next := loadBackendAuthenticationForOwnership(t, cache, key)

	if next.additionalAttributes["left"].([]any)[0] != "original" ||
		next.additionalAttributes["right"].([]any)[0] != "original" {
		t.Fatal("shared slice mutation crossed into a later load")
	}
}

func TestPositiveBackendAuthenticationCacheStoreRejectsCraftedIncompleteSnapshots(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*CachedBackendAuthentication)
	}{
		{name: "nil snapshot"},
		{name: "unauthenticated", mutate: func(decision *CachedBackendAuthentication) { decision.authenticated = false }},
		{name: "user not found", mutate: func(decision *CachedBackendAuthentication) { decision.userFound = false }},
		{name: "unknown backend", mutate: func(decision *CachedBackendAuthentication) { decision.sourceBackend = definitions.BackendUnknown }},
	}

	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "crafted@example.test", "credential", "crafted")

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	decision, ok := captureCachedBackendAuthentication(ctx, auth, result)
	if !ok {
		t.Fatal("capture failed")
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var candidate *CachedBackendAuthentication

			if testCase.mutate == nil {
				candidate = nil
			} else {
				candidateValue := *decision
				candidate = &candidateValue
				testCase.mutate(candidate)
			}

			cache := NewPositiveBackendAuthenticationCache(time.Now)
			if storeBackendAuthenticationForCacheMechanics(cache, mustBuildBackendAuthenticationCacheKey(t, auth), candidate, time.Minute, auth.Request.Username) {
				t.Fatal("crafted non-positive decision was stored")
			}
		})
	}
}

// assertCapturedBackendAuthenticationFields verifies every reusable backend field.
func assertCapturedBackendAuthenticationFields(t *testing.T, source *AuthState, authentication *CachedBackendAuthentication) {
	t.Helper()

	fieldChecks := map[string]bool{
		"source backend":     authentication.sourceBackend == definitions.BackendLDAP,
		"backend name":       authentication.backendName == "ldap-primary",
		"backend ref":        !authentication.backendRef.IsZero(),
		"backend address":    authentication.backendAddress == "192.0.2.10",
		"backend port":       authentication.backendPort == 389,
		"account":            authentication.account == source.Request.Username,
		"context account":    authentication.contextAccount == source.Request.Username,
		"account field":      authentication.accountField == "uid",
		"totp field":         authentication.totpSecretField == "totpSecret",
		"recovery field":     authentication.totpRecoveryField == "recoveryCodes",
		"unique id field":    authentication.uniqueUserIDField == "entryUUID",
		"display name field": authentication.displayNameField == "displayName",
		"attributes":         len(authentication.attributes) > 0,
		"groups":             len(authentication.groups) == 2,
		"group dns":          len(authentication.groupDistinguishedNames) == 2,
		"additional":         len(authentication.additionalAttributes) == 2,
		"user found":         authentication.userFound,
		"authenticated":      authentication.authenticated,
	}

	for field, valid := range fieldChecks {
		if !valid {
			t.Errorf("captured field %q is incomplete", field)
		}
	}
}

// assertAppliedBackendAuthenticationFields compares the complete backend state only.
func assertAppliedBackendAuthenticationFields(t *testing.T, source, target *AuthState) {
	t.Helper()

	sourceResult := newPassDBResultFromAuthStateForTest(source)
	targetResult := newPassDBResultFromAuthStateForTest(target)
	sourceSnapshot := snapshotPassDBResult(sourceResult)
	targetSnapshot := snapshotPassDBResult(targetResult)

	PutPassDBResultToPool(sourceResult)
	PutPassDBResultToPool(targetResult)

	if !reflect.DeepEqual(targetSnapshot, sourceSnapshot) {
		t.Fatalf("applied backend fields differ: got %#v want %#v", targetSnapshot, sourceSnapshot)
	}
}

func TestCachedBackendAuthenticationCapturesAndAppliesCompleteFieldContract(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	source, sourceCtx := newRequestOwnedContractAuth(t, cfg, "fields@example.test", "credential", "fields-source")

	result := newSemanticPassDBResult(sourceCtx, source)
	defer PutPassDBResultToPool(result)

	source.Runtime.ResponseLanguage = "de"

	decision, ok := captureCachedBackendAuthentication(sourceCtx, source, result)
	if !ok {
		t.Fatal("capture failed")
	}

	assertCapturedBackendAuthenticationFields(t, source, decision)

	target, targetCtx := newRequestOwnedContractAuth(t, cfg, "fields@example.test", "credential", "fields-target")

	applied, ok := decision.materialize()
	if !ok || !applied.apply(targetCtx, target) {
		t.Fatal("apply failed")
	}

	assertAppliedBackendAuthenticationFields(t, source, target)
}

func TestBackendAuthenticationCacheKeyEqualDimensionsHit(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cache := NewPositiveBackendAuthenticationCache(time.Now)
	source, sourceCtx := newRequestOwnedContractAuth(t, cfg, "equal@example.test", "credential", "equal-source")

	result := newSemanticPassDBResult(sourceCtx, source)
	defer PutPassDBResultToPool(result)

	if !cache.StoreForRequest(sourceCtx, source, result, time.Minute, source.Request.Username) {
		t.Fatal("failed to seed equal-key decision")
	}

	equal, _ := newRequestOwnedContractAuth(t, cfg, "equal@example.test", "credential", "equal-target")
	if !reflect.DeepEqual(mustBuildBackendAuthenticationCacheKey(t, equal), mustBuildBackendAuthenticationCacheKey(t, source)) {
		t.Fatal("equal dimensions produced different keys")
	}

	if _, found := cache.load(mustBuildBackendAuthenticationCacheKey(t, equal)); !found {
		t.Fatal("equal dimensions missed cached decision")
	}
}

func TestPositiveBackendAuthenticationCacheReplacementCleansStaleIdentityIndex(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "replace@example.test", "credential", "replace")

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	cache := NewPositiveBackendAuthenticationCache(time.Now)

	key := mustBuildBackendAuthenticationCacheKey(t, auth)
	if !cache.StoreForRequest(ctx, auth, result, time.Minute, "old-alias@example.test") ||
		!cache.StoreForRequest(ctx, auth, result, time.Minute, "new-alias@example.test") {
		t.Fatal("replacement store failed")
	}

	if removed := cache.InvalidateIdentities("old-alias@example.test"); removed != 0 {
		t.Fatalf("stale identity removed %d entries, want 0", removed)
	}

	if _, found := cache.load(key); !found {
		t.Fatal("stale identity invalidation removed replacement")
	}

	if removed := cache.InvalidateIdentities("new-alias@example.test"); removed != 1 {
		t.Fatalf("replacement identity removed %d entries, want 1", removed)
	}

	if len(cache.index) != 0 || len(cache.owners) != 0 || cache.storage.Len() != 0 {
		t.Fatalf("replacement residue: index=%d owners=%d storage=%d", len(cache.index), len(cache.owners), cache.storage.Len())
	}
}

func TestPositiveBackendAuthenticationCacheInvalidatesAllVariantsAndPreservesUnrelatedUser(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cache := NewPositiveBackendAuthenticationCache(time.Now)
	owner, ownerCtx := newRequestOwnedContractAuth(t, cfg, "owner@example.test", "credential", "variants-owner")

	ownerResult := newSemanticPassDBResult(ownerCtx, owner)
	defer PutPassDBResultToPool(ownerResult)

	variantKeys := make([]BackendAuthenticationCacheKey, 0, 4)

	for index := range 4 {
		owner.Request.Service = "service-" + strconv.Itoa(index)
		owner.Request.Protocol.Set("protocol-" + strconv.Itoa(index))
		owner.Request.ClientIP = "192.0.2." + strconv.Itoa(index+1)
		owner.Request.Password = secret.New("credential-" + strconv.Itoa(index))
		key := mustBuildBackendAuthenticationCacheKey(t, owner)
		variantKeys = append(variantKeys, key)

		if !cache.StoreForRequest(ownerCtx, owner, ownerResult, time.Minute, owner.Request.Username, "owner-alias@example.test") {
			t.Fatalf("variant %d store failed", index)
		}
	}

	unrelated, unrelatedCtx := newRequestOwnedContractAuth(t, cfg, "unrelated@example.test", "credential", "variants-unrelated")

	unrelatedResult := newSemanticPassDBResult(unrelatedCtx, unrelated)
	defer PutPassDBResultToPool(unrelatedResult)

	unrelatedKey := mustBuildBackendAuthenticationCacheKey(t, unrelated)
	if !cache.StoreForRequest(unrelatedCtx, unrelated, unrelatedResult, time.Minute, unrelated.Request.Username) {
		t.Fatal("unrelated store failed")
	}

	if removed := cache.InvalidateIdentities("owner-alias@example.test"); removed != len(variantKeys) {
		t.Fatalf("removed variants = %d, want %d", removed, len(variantKeys))
	}

	for index, key := range variantKeys {
		if _, found := cache.load(key); found {
			t.Fatalf("variant %d survived alias invalidation", index)
		}
	}

	if _, found := cache.load(unrelatedKey); !found {
		t.Fatal("unrelated user was removed")
	}
}

func TestPositiveBackendAuthenticationCacheReadBypassesMonitoringAndMasterUsers(t *testing.T) {
	testCases := []struct {
		name       string
		monitoring bool
		master     bool
	}{
		{name: "monitoring", monitoring: true},
		{name: "master", master: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			username := "bypass@example.test"

			if testCase.master {
				cfg.Server.MasterUser = config.MasterUser{Enabled: true, UserFormat: config.DefaultMasterUserFormat}
				username += "*admin@example.test"
			}

			auth, ctx := newRequestOwnedContractAuth(t, cfg, username, "credential", "bypass")
			cache := NewPositiveBackendAuthenticationCache(time.Now)
			auth.deps.BackendAuthenticationCache = cache

			result := newSemanticPassDBResult(ctx, auth)
			defer PutPassDBResultToPool(result)

			decision, ok := captureCachedBackendAuthentication(ctx, auth, result)
			if !ok || !storeBackendAuthenticationForCacheMechanics(cache, mustBuildBackendAuthenticationCacheKey(t, auth), decision, time.Minute, username) {
				t.Fatal("failed to seed decision")
			}

			if testCase.monitoring {
				auth.Runtime.MonitoringFlags = []definitions.Monitoring{definitions.MonInMemory}
			}

			if auth.GetFromLocalCache(ctx) {
				t.Fatal("bypassed request read a local decision")
			}
		})
	}
}

type concurrentBackendAuthenticationRequest struct {
	auth *AuthState
	ctx  *gin.Context
	key  BackendAuthenticationCacheKey
}

// seedConcurrentBackendAuthenticationRequests creates independently keyed requests owned by one identity.
func seedConcurrentBackendAuthenticationRequests(
	t *testing.T,
	cfg *config.FileSettings,
	cache *PositiveBackendAuthenticationCache,
	decision *CachedBackendAuthentication,
	username string,
) []concurrentBackendAuthenticationRequest {
	t.Helper()

	requests := make([]concurrentBackendAuthenticationRequest, 8)

	for index := range requests {
		auth, ctx := newRequestOwnedContractAuth(t, cfg, username, "credential-"+strconv.Itoa(index), "concurrent-"+strconv.Itoa(index))
		auth.Request.Service = "service-" + strconv.Itoa(index)
		auth.Request.Protocol.Set("protocol-" + strconv.Itoa(index))
		auth.Request.ClientIP = "192.0.2." + strconv.Itoa(index+1)
		auth.deps.BackendAuthenticationCache = cache
		requests[index] = concurrentBackendAuthenticationRequest{auth: auth, ctx: ctx, key: mustBuildBackendAuthenticationCacheKey(t, auth)}

		if !storeBackendAuthenticationForCacheMechanics(cache, requests[index].key, decision, time.Minute, username, "alias@example.test") {
			t.Fatalf("seed variant %d failed", index)
		}
	}

	return requests
}

// runConcurrentBackendAuthenticationLifecycle races replay, identity invalidation, and expiry cleanup.
func runConcurrentBackendAuthenticationLifecycle(
	cache *PositiveBackendAuthenticationCache,
	requests []concurrentBackendAuthenticationRequest,
	clockNanos *atomic.Int64,
) {
	start := make(chan struct{})

	var workers sync.WaitGroup

	for index := range requests {
		workers.Add(1)

		go func(worker int) {
			defer workers.Done()

			<-start

			for range 100 {
				if cache.ApplyForRequest(requests[worker].ctx, requests[worker].auth) {
					requests[worker].auth.Runtime.AdditionalAttributes = map[string]any{"worker": worker}
				}
			}
		}(index)
	}

	workers.Add(2)

	go func() {
		defer workers.Done()

		<-start
		cache.InvalidateIdentities("alias@example.test")
	}()

	go func() {
		defer workers.Done()

		<-start
		clockNanos.Store(time.Unix(100, 0).Add(time.Minute).UnixNano())

		for _, request := range requests {
			cache.load(request.key)
		}
	}()

	close(start)
	workers.Wait()
}

// assertPositiveBackendAuthenticationCacheEmpty verifies storage and both index layers are clean.
func assertPositiveBackendAuthenticationCacheEmpty(t *testing.T, cache *PositiveBackendAuthenticationCache) {
	t.Helper()

	if len(cache.index) != 0 || len(cache.owners) != 0 || cache.storage.Len() != 0 {
		t.Fatalf("lifecycle residue: index=%d owners=%d storage=%d", len(cache.index), len(cache.owners), cache.storage.Len())
	}
}

func TestPositiveBackendAuthenticationCacheConcurrentLifecycle(t *testing.T) {
	var clockNanos atomic.Int64

	clockNanos.Store(time.Unix(100, 0).UnixNano())

	cache := NewPositiveBackendAuthenticationCache(func() time.Time { return time.Unix(0, clockNanos.Load()) })
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "concurrent@example.test", "credential", "concurrent")

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	decision, ok := captureCachedBackendAuthentication(ctx, auth, result)

	if !ok {
		t.Fatal("capture failed")
	}

	requests := seedConcurrentBackendAuthenticationRequests(t, cfg, cache, decision, auth.Request.Username)
	runConcurrentBackendAuthenticationLifecycle(cache, requests, &clockNanos)
	cache.InvalidateIdentities(auth.Request.Username, "alias@example.test")

	for _, request := range requests {
		cache.load(request.key)
	}

	assertPositiveBackendAuthenticationCacheEmpty(t, cache)
}

type deterministicBackendAuthenticationSweepRunner struct {
	trigger chan chan struct{}
	started chan struct{}
	stopped chan struct{}
}

// newDeterministicBackendAuthenticationSweepRunner creates an acknowledged test runner without timing dependencies.
func newDeterministicBackendAuthenticationSweepRunner() *deterministicBackendAuthenticationSweepRunner {
	return &deterministicBackendAuthenticationSweepRunner{
		trigger: make(chan chan struct{}),
		started: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// Run executes acknowledged sweep requests until cache closure.
func (r *deterministicBackendAuthenticationSweepRunner) Run(stop <-chan struct{}, sweep func()) {
	close(r.started)
	defer close(r.stopped)

	for {
		select {
		case acknowledged := <-r.trigger:
			sweep()
			close(acknowledged)
		case <-stop:
			return
		}
	}
}

// Sweep executes one deterministic background sweep and waits for completion.
func (r *deterministicBackendAuthenticationSweepRunner) Sweep() {
	acknowledged := make(chan struct{})
	r.trigger <- acknowledged

	<-acknowledged
}

func TestPositiveBackendAuthenticationCacheSweepExpiresIdleEntriesWithoutLoad(t *testing.T) {
	now := time.Unix(200, 0)
	cache := NewPositiveBackendAuthenticationCache(func() time.Time { return now })
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "sweep@example.test", "credential", "sweep")

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	snapshot, ok := captureCachedBackendAuthentication(ctx, auth, result)
	if !ok {
		t.Fatal("capture failed")
	}

	for index := range 3 {
		variant, _ := newRequestOwnedContractAuth(t, cfg, auth.Request.Username, "credential-"+strconv.Itoa(index), "sweep-variant")
		key := mustBuildBackendAuthenticationCacheKey(t, variant)

		if !storeBackendAuthenticationForCacheMechanics(cache, key, snapshot, time.Minute, auth.Request.Username, "sweep-alias@example.test") {
			t.Fatalf("store variant %d failed", index)
		}
	}

	now = now.Add(time.Minute)

	if removed := cache.SweepExpired(); removed != 3 {
		t.Fatalf("expired entries removed = %d, want 3", removed)
	}

	assertPositiveBackendAuthenticationCacheEmpty(t, cache)
}

func TestPositiveBackendAuthenticationCacheCloseIsIdempotentAndJoinsLifecycle(t *testing.T) {
	now := time.Unix(300, 0)
	runner := newDeterministicBackendAuthenticationSweepRunner()
	cache := newPositiveBackendAuthenticationCache(func() time.Time { return now }, runner)
	<-runner.started

	cfg := newCurrentBehaviorConfig(t)
	auth, ctx := newRequestOwnedContractAuth(t, cfg, "close@example.test", "credential", "close")

	result := newSemanticPassDBResult(ctx, auth)
	defer PutPassDBResultToPool(result)

	if !cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
		t.Fatal("store before close failed")
	}

	now = now.Add(time.Minute)

	runner.Sweep()
	assertPositiveBackendAuthenticationCacheEmpty(t, cache)

	now = now.Add(-time.Minute)
	if !cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
		t.Fatal("store before concurrent close failed")
	}

	closePositiveBackendAuthenticationCacheConcurrently(cache, mustBuildBackendAuthenticationCacheKey(t, auth), auth.Request.Username)
	<-runner.stopped
	cache.Close()

	if cache.StoreForRequest(ctx, auth, result, time.Minute, auth.Request.Username) {
		t.Fatal("closed cache admitted a new entry")
	}

	assertPositiveBackendAuthenticationCacheEmpty(t, cache)
}

// closePositiveBackendAuthenticationCacheConcurrently races lifecycle operations with repeated Close calls.
func closePositiveBackendAuthenticationCacheConcurrently(cache *PositiveBackendAuthenticationCache, key BackendAuthenticationCacheKey, identity string) {
	const closers = 16

	var workers sync.WaitGroup

	workers.Add(closers + 3)
	go func() {
		defer workers.Done()

		cache.load(key)
	}()
	go func() {
		defer workers.Done()

		cache.SweepExpired()
	}()
	go func() {
		defer workers.Done()

		cache.InvalidateIdentities(identity)
	}()

	for range closers {
		go func() {
			defer workers.Done()

			cache.Close()
		}()
	}

	workers.Wait()
}

var _ backendAuthenticationSweepRunner = (*deterministicBackendAuthenticationSweepRunner)(nil)
