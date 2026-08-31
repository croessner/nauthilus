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
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	internalpasswordhash "github.com/croessner/nauthilus/v4/server/internal/passwordhash"
	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/util"

	"github.com/gin-gonic/gin"
)

type fullHashContractNamedMap map[string]any
type fullHashContractNamedSlice []any

type fullHashContractVerifier struct {
	calls              *atomic.Int32
	acceptedCredential string
	unsupportedValue   func() any
}

// Verify records backend work and optionally injects an unsupported named container.
func (v fullHashContractVerifier) Verify(ctx *gin.Context, auth *AuthState, passDBs []*PassDBMap) (*PassDBResult, error) {
	result, err := (backendAuthenticationContractVerifier{calls: v.calls}).Verify(ctx, auth, passDBs)
	if err != nil {
		return nil, err
	}

	authenticated := false

	auth.Request.Password.WithString(func(value string) {
		authenticated = value == v.acceptedCredential
	})

	result.Authenticated = authenticated

	if authenticated && v.unsupportedValue != nil {
		result.AdditionalAttributes["unsupported"] = v.unsupportedValue()
	}

	return result, nil
}

// installFullHashContractVerifier installs deterministic backend and subject behavior.
func installFullHashContractVerifier(t *testing.T, verifier PasswordVerifier) {
	t.Helper()

	previousVerifier := getPasswordVerifier()
	previousSubject := getLuaSubject()

	RegisterPasswordVerifier(verifier)
	RegisterLuaSubject(testLuaSubject{})

	t.Cleanup(func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterLuaSubject(previousSubject)
	})
}

// runFullHashContractRequest drives the admitted candidate backend boundary.
func runFullHashContractRequest(t *testing.T, auth *AuthState, ctx *gin.Context) {
	t.Helper()
	bindRegisteredAuthnHostServicesForTest(auth)

	if auth.PreproccessAuthRequest(ctx) {
		t.Fatal("request was rejected during preprocessing")
	}

	execution := &authnCandidateExecution{auth: auth, ginCtx: ctx}

	terminal, err := execution.prepareBackendPlan(auth.buildBackendExecutionPlan())
	if err != nil {
		t.Fatalf("prepareBackendPlan() error = %v", err)
	}

	if !terminal {
		if _, err = execution.prepareBuiltinSubjectProvider(); err != nil {
			t.Fatalf("prepareBuiltinSubjectProvider() error = %v", err)
		}
	}

	terminalMarker := policy.FSMEventMarkerAuthTempFail

	switch execution.authResult {
	case definitions.AuthResultOK:
		terminalMarker = policy.FSMEventMarkerAuthPermit
	case definitions.AuthResultFail, definitions.AuthResultEmptyPassword:
		terminalMarker = policy.FSMEventMarkerAuthDeny
	}

	if err = auth.applyAuthFSMMarkers([]string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerPreAuthOK,
		policy.FSMEventMarkerAuthEvaluated,
		terminalMarker,
	}); err != nil {
		t.Fatalf("applyAuthFSMMarkers() error = %v", err)
	}

	switch execution.authResult {
	case definitions.AuthResultOK:
		auth.AuthOK(ctx)
	case definitions.AuthResultFail, definitions.AuthResultEmptyPassword:
		auth.AuthFail(ctx)
	default:
		auth.AuthTempFail(ctx, definitions.TempFailDefault)
	}

	execution.release()
}

// emptyNonceLegacyCandidate derives the bounded Redis legacy candidate explicitly.
func emptyNonceLegacyCandidate(auth *AuthState) string {
	legacy := ""

	auth.Request.Password.WithBytes(func(value []byte) {
		prepared, ok := util.PreparePasswordBytesWithConfig(value, auth.Cfg())
		if !ok {
			return
		}

		defer clear(prepared)

		legacy = internalpasswordhash.DeriveRedisCompatibilityCandidates(prepared).Legacy()
	})

	return legacy
}

// assertFullHashContractDimensions verifies that only the credential dimension differs.
func assertFullHashContractDimensions(t *testing.T, first *AuthState, second *AuthState) {
	t.Helper()

	if first.Request.Username != second.Request.Username ||
		first.Request.Service != second.Request.Service ||
		first.Request.Protocol.Get() != second.Request.Protocol.Get() ||
		first.Request.ClientIP != second.Request.ClientIP {
		t.Fatal("collision requests differ outside the allowed dimension")
	}
}

// assertLegacyCollisionContract verifies the fixed bounded Redis compatibility collision.
func assertLegacyCollisionContract(t *testing.T, first *AuthState, second *AuthState) {
	t.Helper()

	const legacyCollision = "593c55ae"

	if emptyNonceLegacyCandidate(first) != legacyCollision || emptyNonceLegacyCandidate(second) != legacyCollision {
		t.Fatal("fixed inputs do not satisfy the legacy compatibility collision contract")
	}
}

// assertFullHashContractOutcome checks one terminal normal-flow outcome without exposing secrets.
func assertFullHashContractOutcome(
	t *testing.T,
	phase string,
	auth *AuthState,
	ctx *gin.Context,
	wantAuthenticated bool,
	wantTerminal authFSMState,
	wantCacheHit bool,
	wantBackendCalls int32,
	verifierCalls *atomic.Int32,
) {
	t.Helper()

	if auth.Runtime.Authenticated != wantAuthenticated {
		t.Fatalf("%s authenticated = %t, want %t", phase, auth.Runtime.Authenticated, wantAuthenticated)
	}

	if auth.Runtime.AuthFSMTerminalState != string(wantTerminal) {
		t.Fatalf("%s terminal = %q, want %q", phase, auth.Runtime.AuthFSMTerminalState, wantTerminal)
	}

	if ctx.GetBool(definitions.CtxLocalCacheAuthKey) != wantCacheHit {
		t.Fatalf("%s cache hit = %t, want %t", phase, ctx.GetBool(definitions.CtxLocalCacheAuthKey), wantCacheHit)
	}

	if verifierCalls.Load() != wantBackendCalls {
		t.Fatalf("%s backend calls = %d, want %d", phase, verifierCalls.Load(), wantBackendCalls)
	}
}

// assertNoFullHashContractSnapshot verifies that no cache-owned value reached the request.
func assertNoFullHashContractSnapshot(t *testing.T, phase string, ctx *gin.Context) {
	t.Helper()

	if _, found := ctx.Get(cachedBackendAuthenticationContextKey); found {
		t.Fatalf("%s retained an unsupported cached snapshot", phase)
	}
}

func TestPositiveBackendAuthenticationCacheCredentialDigestSeparatesShortHashCollision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	cfg.Server.Redis.PasswordNonce = secret.Value{}

	if !cfg.Server.Redis.GetPasswordNonce().IsZero() || cfg.Server.GetEnvironment().GetDevMode() {
		t.Fatal("fixed collision contract requires an empty nonce and disabled developer mode")
	}

	verifierCalls := &atomic.Int32{}
	installFullHashContractVerifier(t, fullHashContractVerifier{
		calls:              verifierCalls,
		acceptedCredential: "collision-38455",
	})

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	first, firstCtx := newRequestOwnedContractAuth(t, cfg, "collision@example.test", "collision-38455", "collision-first")
	second, secondCtx := newRequestOwnedContractAuth(t, cfg, "collision@example.test", "collision-50148", "collision-second")
	first.deps.BackendAuthenticationCache = cache
	second.deps.BackendAuthenticationCache = cache

	assertFullHashContractDimensions(t, first, second)
	assertLegacyCollisionContract(t, first, second)

	runFullHashContractRequest(t, first, firstCtx)

	assertFullHashContractOutcome(t, "first request", first, firstCtx, true, authFSMStateAuthOK, false, 1, verifierCalls)

	runFullHashContractRequest(t, second, secondCtx)

	assertFullHashContractOutcome(t, "second request", second, secondCtx, false, authFSMStateAuthFail, false, 2, verifierCalls)
	assertNoFullHashContractSnapshot(t, "second request", secondCtx)

	replay, replayCtx := newRequestOwnedContractAuth(t, cfg, first.Request.Username, "collision-38455", "collision-replay")
	replay.deps.BackendAuthenticationCache = cache
	runFullHashContractRequest(t, replay, replayCtx)

	assertFullHashContractOutcome(t, "replay request", replay, replayCtx, true, authFSMStateAuthOK, true, 2, verifierCalls)
}

func TestPositiveBackendAuthenticationCacheRejectsUnsupportedNamedContainers(t *testing.T) {
	testCases := []struct {
		name  string
		value func() any
	}{
		{name: "named map", value: func() any { return fullHashContractNamedMap{"value": "first"} }},
		{name: "named slice", value: func() any { return fullHashContractNamedSlice{"first"} }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			cfg.Server.Redis.AccountLocalCache.Enabled = true

			verifierCalls := &atomic.Int32{}
			installFullHashContractVerifier(t, fullHashContractVerifier{
				calls:              verifierCalls,
				acceptedCredential: "named-container-credential",
				unsupportedValue:   testCase.value,
			})

			cache := NewPositiveBackendAuthenticationCache(time.Now)
			terminalSuccesses := 0

			for requestNumber := range 2 {
				auth, ctx := newRequestOwnedContractAuth(t, cfg, "named-container@example.test", "named-container-credential", fmt.Sprintf("named-container-%d", requestNumber))
				auth.deps.BackendAuthenticationCache = cache
				runFullHashContractRequest(t, auth, ctx)

				if !auth.Runtime.Authenticated || auth.Runtime.AuthFSMTerminalState != string(authFSMStateAuthOK) {
					t.Fatalf("request %d outcome = authenticated:%t terminal:%q, want live success", requestNumber, auth.Runtime.Authenticated, auth.Runtime.AuthFSMTerminalState)
				}

				if ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
					t.Fatalf("request %d materialized an unsupported cached snapshot", requestNumber)
				}

				assertNoFullHashContractSnapshot(t, fmt.Sprintf("request %d", requestNumber), ctx)

				terminalSuccesses++
			}

			if verifierCalls.Load() != 2 || terminalSuccesses != 2 {
				t.Fatalf("flow counts = backend:%d terminal successes:%d, want 2 and 2", verifierCalls.Load(), terminalSuccesses)
			}
		})
	}
}

func TestPositivePasswordCacheReadsLegacyShortHashAndWritesFullHash(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, _ := newRequestOwnedContractAuth(t, cfg, "redis-cache@example.test", "credential", "redis-cache")
	candidates := auth.cachePasswordHashCandidates()
	hash := auth.CreatePositivePasswordCache().Password

	if len(hash) != 64 || strings.ToLower(hash) != hash {
		t.Fatalf("new positive password-cache hash = %q, want lowercase 64-hex", hash)
	}

	for _, stored := range []string{candidates.Legacy(), candidates.Full()} {
		if !positivePasswordCacheHashMatches(stored, candidates) {
			t.Fatalf("valid positive password-cache value %q did not match its exact candidate", stored)
		}
	}

	readCases := []struct {
		name          string
		stored        string
		wantFound     bool
		wantValidated bool
	}{
		{name: "legacy", stored: candidates.Legacy(), wantFound: true, wantValidated: true},
		{name: "canonical", stored: candidates.Full(), wantFound: true, wantValidated: true},
		{name: "malformed uppercase", stored: strings.ToUpper(candidates.Legacy())},
		{name: "malformed length", stored: candidates.Full()[:63]},
	}

	for index, testCase := range readCases {
		t.Run(testCase.name, func(t *testing.T) {
			readAuth, _, mock := newCurrentBehaviorAuthState(t, cfg)
			readAuth.Request.Username = auth.Request.Username
			readAuth.Request.Password = auth.Request.Password
			cacheName := fmt.Sprintf("contract-%d", index)
			key := readAuth.positivePasswordCacheKey(cacheName, readAuth.Request.Username)
			mock.ExpectHGetAll(key).SetVal(map[string]string{
				"backend":  fmt.Sprint(int(definitions.BackendLDAP)),
				"password": testCase.stored,
			})

			_, found, validated, err := readAuth.readPositivePasswordCache(monittrace.New("test/password-cache"), cacheName, readAuth.Request.Username)
			if err != nil {
				t.Fatalf("readPositivePasswordCache() error = %v", err)
			}

			if found != testCase.wantFound || validated != testCase.wantValidated {
				t.Fatalf("read boundary = (found=%t, authenticated=%t), want (%t, %t)", found, validated, testCase.wantFound, testCase.wantValidated)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("Redis expectations = %v", err)
			}
		})
	}
}

func TestPositivePasswordCacheRejectsMalformedStoredPasswordHash(t *testing.T) {
	malformed := []string{"", "ABCDEF12", "gggggggg", "1234567", strings.Repeat("a", 63), strings.Repeat("a", 65)}
	cfg := newCurrentBehaviorConfig(t)
	auth, _ := newRequestOwnedContractAuth(t, cfg, "malformed@example.test", "credential", "malformed")
	candidates := auth.cachePasswordHashCandidates()

	for _, value := range malformed {
		if positivePasswordCacheHashMatches(value, candidates) {
			t.Fatalf("malformed positive password-cache hash %q was accepted", value)
		}
	}
}
