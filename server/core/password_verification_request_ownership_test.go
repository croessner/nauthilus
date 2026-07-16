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
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/localcache"
	"github.com/croessner/nauthilus/v3/server/secret"

	"github.com/gin-gonic/gin"
)

const requestOwnedContractRequests = 32

type semanticPassDBSnapshot struct {
	Attributes              bktype.AttributeMapping
	AdditionalAttributes    map[string]any
	Groups                  []string
	GroupDistinguishedNames []string
	BackendName             string
	AccountField            string
	Account                 string
	TOTPSecretField         string
	TOTPRecoveryField       string
	UniqueUserIDField       string
	DisplayNameField        string
	BackendRef              RemoteBackendRef
	Backend                 definitions.Backend
	Authenticated           bool
	UserFound               bool
}

type semanticAuthenticationSnapshot struct {
	Result                  semanticPassDBSnapshot
	Attributes              bktype.AttributeMapping
	AdditionalAttributes    map[string]any
	Groups                  []string
	GroupDistinguishedNames []string
	ResponseHeaders         http.Header
	Account                 string
	ContextAccount          string
	BackendName             string
	UsedBackendIP           string
	StatusMessage           string
	StatusMessageI18NKey    string
	AuthFSMTerminalState    string
	RemoteBackendRef        RemoteBackendRef
	SourcePassDBBackend     definitions.Backend
	Decision                definitions.AuthResult
	UsedBackendPort         int
	Authenticated           bool
	Authorized              bool
	UserFound               bool
}

type verificationOutcome struct {
	result *PassDBResult
	err    error
}

type verificationObservation struct {
	auth         *AuthState
	requestCtx   context.Context
	authStateCtx context.Context
}

type verificationReady struct {
	auth   *AuthState
	result *PassDBResult
}

type verificationRequest struct {
	auth    *AuthState
	ctx     *gin.Context
	outcome <-chan verificationOutcome
	cancel  context.CancelFunc
}

type verificationBarrier struct {
	release chan struct{}
	once    sync.Once
}

type controlledDecisionVerifier struct {
	arrivals            chan verificationObservation
	ready               chan verificationReady
	sharedBarrier       *verificationBarrier
	requestBarriers     map[string]*verificationBarrier
	calls               atomic.Int32
	createBeforeRelease bool
}

type countingDecisionVerifier struct {
	calls atomic.Int32
}

type successfulDecisionSubject struct{}

// newVerificationBarrier creates an idempotently releasable synchronization point.
func newVerificationBarrier() *verificationBarrier {
	return &verificationBarrier{release: make(chan struct{})}
}

// Release lets every verifier waiting at this barrier continue.
func (b *verificationBarrier) Release() {
	b.once.Do(func() {
		close(b.release)
	})
}

// newRequestOwnedContractAuth creates one request with explicit credentials and correlation data.
func newRequestOwnedContractAuth(t *testing.T, cfg *config.FileSettings, username string, password string, guid string) (*AuthState, *gin.Context) {
	t.Helper()

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Username = username
	auth.Request.Password = secret.New(password)
	auth.Runtime.GUID = guid
	auth.AccountCache().Set(cfg, username, auth.Request.Protocol.Get(), "", username)

	return auth, ctx
}

// installRequestOwnedContractVerifier replaces the password verifier for one test.
func installRequestOwnedContractVerifier(t *testing.T, verifier PasswordVerifier) {
	t.Helper()

	previous := getPasswordVerifier()

	RegisterPasswordVerifier(verifier)
	t.Cleanup(func() {
		RegisterPasswordVerifier(previous)
	})
}

// Verify records request ownership and releases one complete request-local decision.
func (v *controlledDecisionVerifier) Verify(ctx *gin.Context, auth *AuthState, _ []*PassDBMap) (*PassDBResult, error) {
	v.calls.Add(1)

	v.arrivals <- verificationObservation{
		auth:         auth,
		requestCtx:   ctx.Request.Context(),
		authStateCtx: auth.Ctx(),
	}

	var result *PassDBResult

	if v.createBeforeRelease {
		result = newSemanticPassDBResult(ctx, auth)
		v.ready <- verificationReady{auth: auth, result: result}
	}

	barrier := v.sharedBarrier
	if requestBarrier, found := v.requestBarriers[auth.Runtime.GUID]; found {
		barrier = requestBarrier
	}

	select {
	case <-barrier.release:
	case <-ctx.Request.Context().Done():
		if result != nil {
			PutPassDBResultToPool(result)
		}

		return nil, ctx.Request.Context().Err()
	}

	if result == nil {
		result = newSemanticPassDBResult(ctx, auth)
	}

	return result, nil
}

// Verify counts cache-fill executions and returns a complete decision.
func (v *countingDecisionVerifier) Verify(ctx *gin.Context, auth *AuthState, _ []*PassDBMap) (*PassDBResult, error) {
	v.calls.Add(1)

	return newSemanticPassDBResult(ctx, auth), nil
}

// Analyze preserves a successful authentication decision without adding request variance.
func (successfulDecisionSubject) Analyze(_ *gin.Context, _ *StateView, _ *PassDBResult) definitions.AuthResult {
	return definitions.AuthResultOK
}

// newSemanticPassDBResult creates a complete backend result and matching request-owned state.
func newSemanticPassDBResult(ctx *gin.Context, auth *AuthState) *PassDBResult {
	account := auth.Request.Username
	result := GetPassDBResultFromPool()
	result.Authenticated = true
	result.UserFound = true
	result.BackendName = "ldap-primary"
	result.AccountField = "uid"
	result.Account = account
	result.TOTPSecretField = "totpSecret"
	result.TOTPRecoveryField = "recoveryCodes"
	result.UniqueUserIDField = "entryUUID"
	result.DisplayNameField = "displayName"
	result.Backend = definitions.BackendLDAP
	result.BackendRef = RemoteBackendRef{
		Type:      "ldap",
		Name:      "primary",
		Protocol:  auth.Request.Protocol.Get(),
		Authority: "authority.example.test",
	}
	result.Attributes = bktype.AttributeMapping{
		"uid":         {account},
		"displayName": {"Request Ownership Contract User"},
	}
	result.Groups = []string{"mail-users", "staff"}
	result.GroupDistinguishedNames = []string{"cn=mail-users,dc=example,dc=test", "cn=staff,dc=example,dc=test"}
	result.AdditionalAttributes = map[string]any{"tenant": "example", "quota": "10G"}
	updateAuthentication(ctx, auth, result, nil)
	populateSemanticRequestRuntime(auth, result)

	return result
}

// populateSemanticRequestRuntime records backend and policy facts not represented by PassDBResult alone.
func populateSemanticRequestRuntime(auth *AuthState, result *PassDBResult) {
	auth.Runtime.Authenticated = result.Authenticated
	auth.Runtime.Authorized = true
	auth.Runtime.StatusMessage = "authentication accepted"
	auth.Runtime.StatusMessageI18NKey = "auth.success"
	auth.Runtime.AuthFSMTerminalState = "auth_ok"
	auth.Runtime.UsedBackendIP = "192.0.2.10"
	auth.Runtime.UsedBackendPort = 389
	auth.Runtime.AdditionalAttributes = maps.Clone(result.AdditionalAttributes)
}

// snapshotAuthentication extracts semantic decision and response fields from one request.
func snapshotAuthentication(auth *AuthState, ctx *gin.Context, result *PassDBResult, decision definitions.AuthResult) semanticAuthenticationSnapshot {
	additional, _ := ctx.Get(definitions.CtxAdditionalAttributesKey)
	additionalAttributes, _ := additional.(map[string]any)

	return semanticAuthenticationSnapshot{
		Result:                  snapshotPassDBResult(result),
		Attributes:              auth.GetAttributesCopy(),
		AdditionalAttributes:    maps.Clone(additionalAttributes),
		Groups:                  auth.GetGroups(),
		GroupDistinguishedNames: auth.GetGroupDistinguishedNames(),
		ResponseHeaders:         ctx.Writer.Header().Clone(),
		Account:                 auth.GetAccount(),
		ContextAccount:          ctx.GetString(definitions.CtxAccountKey),
		BackendName:             auth.Runtime.BackendName,
		UsedBackendIP:           auth.Runtime.UsedBackendIP,
		StatusMessage:           auth.Runtime.StatusMessage,
		StatusMessageI18NKey:    auth.Runtime.StatusMessageI18NKey,
		AuthFSMTerminalState:    auth.Runtime.AuthFSMTerminalState,
		RemoteBackendRef:        auth.Runtime.RemoteBackendRef,
		SourcePassDBBackend:     auth.Runtime.SourcePassDBBackend,
		Decision:                decision,
		UsedBackendPort:         auth.Runtime.UsedBackendPort,
		Authenticated:           auth.Runtime.Authenticated,
		Authorized:              auth.Runtime.Authorized,
		UserFound:               auth.Runtime.UserFound,
	}
}

// snapshotPassDBResult deep-copies the semantic fields of a pooled backend result.
func snapshotPassDBResult(result *PassDBResult) semanticPassDBSnapshot {
	if result == nil {
		return semanticPassDBSnapshot{}
	}

	return semanticPassDBSnapshot{
		Attributes:              result.Attributes.Clone(),
		AdditionalAttributes:    maps.Clone(result.AdditionalAttributes),
		Groups:                  slices.Clone(result.Groups),
		GroupDistinguishedNames: slices.Clone(result.GroupDistinguishedNames),
		BackendName:             result.BackendName,
		AccountField:            result.AccountField,
		Account:                 result.Account,
		TOTPSecretField:         result.TOTPSecretField,
		TOTPRecoveryField:       result.TOTPRecoveryField,
		UniqueUserIDField:       result.UniqueUserIDField,
		DisplayNameField:        result.DisplayNameField,
		BackendRef:              result.BackendRef,
		Backend:                 result.Backend,
		Authenticated:           result.Authenticated,
		UserFound:               result.UserFound,
	}
}

// differingSemanticFields names every normalized decision field whose value is not preserved.
func differingSemanticFields(got semanticAuthenticationSnapshot, want semanticAuthenticationSnapshot) []string {
	gotValue := reflect.ValueOf(got)
	wantValue := reflect.ValueOf(want)
	snapshotType := gotValue.Type()
	differences := make([]string, 0)

	for index := 0; index < gotValue.NumField(); index++ {
		if !reflect.DeepEqual(gotValue.Field(index).Interface(), wantValue.Field(index).Interface()) {
			differences = append(differences, snapshotType.Field(index).Name)
		}
	}

	return differences
}

// attachContractContext installs one bounded request context on both request holders.
func attachContractContext(requestContext context.Context, auth *AuthState, ctx *gin.Context) {
	ctx.Request = ctx.Request.WithContext(requestContext)
	auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(requestContext)
}

// startVerification starts one direct request-owned verification call.
func startVerification(auth *AuthState, ctx *gin.Context) <-chan verificationOutcome {
	outcome := make(chan verificationOutcome, 1)

	go func() {
		result, err := auth.processVerifyPassword(ctx, []*PassDBMap{{backend: definitions.BackendLDAP}})
		outcome <- verificationOutcome{result: result, err: err}
	}()

	return outcome
}

// awaitObservation waits for a verifier call without relying on scheduler timing.
func awaitObservation(deadline context.Context, t *testing.T, arrivals <-chan verificationObservation) verificationObservation {
	t.Helper()

	select {
	case observation := <-arrivals:
		return observation
	case <-deadline.Done():
		t.Fatalf("timed out waiting for verifier arrival: %v", deadline.Err())

		return verificationObservation{}
	}
}

// awaitVerification waits for one verification result within the test deadline.
func awaitVerification(deadline context.Context, t *testing.T, outcomes <-chan verificationOutcome) verificationOutcome {
	t.Helper()

	select {
	case outcome := <-outcomes:
		return outcome
	case <-deadline.Done():
		t.Fatalf("timed out waiting for verification outcome: %v", deadline.Err())

		return verificationOutcome{}
	}
}

// awaitReadyResult waits until a verifier has allocated its request-owned result.
func awaitReadyResult(deadline context.Context, t *testing.T, ready <-chan verificationReady) verificationReady {
	t.Helper()

	select {
	case result := <-ready:
		return result
	case <-deadline.Done():
		t.Fatalf("timed out waiting for allocated verification result: %v", deadline.Err())

		return verificationReady{}
	}
}

// startParallelVerificationRequests starts the fixed-size semantic parity request set.
func startParallelVerificationRequests(deadline context.Context, t *testing.T, cfg *config.FileSettings) ([]*AuthState, []*gin.Context, []<-chan verificationOutcome) {
	t.Helper()

	authStates := make([]*AuthState, requestOwnedContractRequests)
	contexts := make([]*gin.Context, requestOwnedContractRequests)
	outcomes := make([]<-chan verificationOutcome, requestOwnedContractRequests)

	for index := range requestOwnedContractRequests {
		authStates[index], contexts[index] = newRequestOwnedContractAuth(
			t,
			cfg,
			"parallel@example.test",
			"parallel-secret",
			"parallel-guid-"+strconv.Itoa(index),
		)
		contexts[index].Request.Header.Set(idempotencyHeaderName, "parallel-decision")
		attachContractContext(deadline, authStates[index], contexts[index])
		outcomes[index] = startVerification(authStates[index], contexts[index])
	}

	return authStates, contexts, outcomes
}

// requireParallelRequestOwnership verifies that every request reached the verifier with its own state and context.
func requireParallelRequestOwnership(deadline context.Context, t *testing.T, arrivals <-chan verificationObservation) {
	t.Helper()

	seen := make(map[*AuthState]struct{}, requestOwnedContractRequests)

	for range requestOwnedContractRequests {
		observation := awaitObservation(deadline, t, arrivals)
		seen[observation.auth] = struct{}{}

		if observation.requestCtx.Done() != observation.authStateCtx.Done() {
			t.Fatal("verifier request and AuthState contexts do not share request ownership")
		}
	}

	if len(seen) != requestOwnedContractRequests {
		t.Fatalf("verifier observed %d request states, want %d", len(seen), requestOwnedContractRequests)
	}
}

// collectSemanticSnapshots consumes and releases every independently owned request result.
func collectSemanticSnapshots(deadline context.Context, t *testing.T, authStates []*AuthState, contexts []*gin.Context, outcomes []<-chan verificationOutcome) []semanticAuthenticationSnapshot {
	t.Helper()

	snapshots := make([]semanticAuthenticationSnapshot, len(outcomes))

	for index := range outcomes {
		outcome := awaitVerification(deadline, t, outcomes[index])

		if outcome.err != nil {
			t.Fatalf("request %d verification error: %v", index, outcome.err)
		}

		snapshots[index] = snapshotAuthentication(authStates[index], contexts[index], outcome.result, definitions.AuthResultOK)
		PutPassDBResultToPool(outcome.result)
	}

	return snapshots
}

type orderedVerificationContract struct {
	first         verificationRequest
	second        verificationRequest
	firstBarrier  *verificationBarrier
	secondBarrier *verificationBarrier
	verifier      *controlledDecisionVerifier
}

// newOrderedVerificationContract starts two requests whose allocated results have independent release gates.
func newOrderedVerificationContract(deadline context.Context, t *testing.T, cfg *config.FileSettings) *orderedVerificationContract {
	t.Helper()

	contract := &orderedVerificationContract{
		firstBarrier:  newVerificationBarrier(),
		secondBarrier: newVerificationBarrier(),
	}
	contract.first.auth, contract.first.ctx = newRequestOwnedContractAuth(t, cfg, "ordered@example.test", "ordered-secret", "completion-first")
	contract.second.auth, contract.second.ctx = newRequestOwnedContractAuth(t, cfg, "ordered@example.test", "ordered-secret", "completion-second")
	attachContractContext(deadline, contract.first.auth, contract.first.ctx)
	attachContractContext(deadline, contract.second.auth, contract.second.ctx)
	t.Cleanup(contract.firstBarrier.Release)
	t.Cleanup(contract.secondBarrier.Release)

	contract.verifier = &controlledDecisionVerifier{
		arrivals: make(chan verificationObservation, 2),
		ready:    make(chan verificationReady, 2),
		requestBarriers: map[string]*verificationBarrier{
			contract.first.auth.Runtime.GUID:  contract.firstBarrier,
			contract.second.auth.Runtime.GUID: contract.secondBarrier,
		},
		createBeforeRelease: true,
	}
	installRequestOwnedContractVerifier(t, contract.verifier)
	contract.first.outcome = startVerification(contract.first.auth, contract.first.ctx)
	contract.second.outcome = startVerification(contract.second.auth, contract.second.ctx)

	return contract
}

// requireDistinctAllocatedResults proves both request-owned pool objects exist before either request is released.
func (c *orderedVerificationContract) requireDistinctAllocatedResults(deadline context.Context, t *testing.T) {
	t.Helper()

	firstReady := awaitReadyResult(deadline, t, c.verifier.ready)
	secondReady := awaitReadyResult(deadline, t, c.verifier.ready)
	results := map[*AuthState]*PassDBResult{
		firstReady.auth:  firstReady.result,
		secondReady.auth: secondReady.result,
	}

	if len(results) != 2 || results[c.first.auth] == nil || results[c.second.auth] == nil {
		t.Fatal("both requests did not allocate a result before release")
	}

	if results[c.first.auth] == results[c.second.auth] {
		t.Fatal("concurrent requests allocated the same pooled result object")
	}
}

type cancellationVerificationContract struct {
	requests [2]verificationRequest
	barrier  *verificationBarrier
	verifier *controlledDecisionVerifier
}

// newCancellationVerificationContract starts two independently cancelable request-owned verifications.
func newCancellationVerificationContract(deadline context.Context, t *testing.T, cfg *config.FileSettings) *cancellationVerificationContract {
	t.Helper()

	contract := &cancellationVerificationContract{barrier: newVerificationBarrier()}
	t.Cleanup(contract.barrier.Release)
	contract.verifier = &controlledDecisionVerifier{
		arrivals:      make(chan verificationObservation, len(contract.requests)),
		sharedBarrier: contract.barrier,
	}
	installRequestOwnedContractVerifier(t, contract.verifier)

	for index := range contract.requests {
		request := &contract.requests[index]
		request.auth, request.ctx = newRequestOwnedContractAuth(
			t,
			cfg,
			"cancel@example.test",
			"cancel-secret",
			"cancel-guid-"+strconv.Itoa(index),
		)
		requestContext, cancelRequest := context.WithCancel(deadline)
		request.cancel = cancelRequest
		attachContractContext(requestContext, request.auth, request.ctx)
		request.outcome = startVerification(request.auth, request.ctx)

		t.Cleanup(cancelRequest)
	}

	return contract
}

// requireCancellationIsolation verifies one cancellation direction without affecting the surviving request.
func (c *cancellationVerificationContract) requireCancellationIsolation(deadline context.Context, t *testing.T, canceledIndex int) {
	t.Helper()

	for range c.requests {
		awaitObservation(deadline, t, c.verifier.arrivals)
	}

	c.requests[canceledIndex].cancel()
	canceled := awaitVerification(deadline, t, c.requests[canceledIndex].outcome)

	if !errors.Is(canceled.err, context.Canceled) || canceled.result != nil {
		t.Fatalf("canceled request result=%v error=%v, want nil and context canceled", canceled.result, canceled.err)
	}

	survivingIndex := 1 - canceledIndex

	c.barrier.Release()

	surviving := awaitVerification(deadline, t, c.requests[survivingIndex].outcome)

	if surviving.err != nil {
		t.Fatalf("surviving request verification error: %v", surviving.err)
	}

	if !surviving.result.Authenticated || !c.requests[survivingIndex].auth.Runtime.Authorized {
		PutPassDBResultToPool(surviving.result)

		t.Fatal("surviving request lost its authentication decision")
	}

	PutPassDBResultToPool(surviving.result)

	if c.requests[canceledIndex].auth.Runtime.Authenticated || c.requests[canceledIndex].auth.Runtime.Authorized {
		t.Fatal("canceled request inherited another request's decision")
	}

	if got := c.verifier.calls.Load(); got != 2 {
		t.Fatalf("verifier calls = %d, want 2", got)
	}
}

func TestPasswordVerificationSameIdempotencyKeyKeepsCredentialsIsolated(t *testing.T) {
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDeadline()

	cfg := newCurrentBehaviorConfig(t)
	requests := []struct {
		auth *AuthState
		ctx  *gin.Context
	}{
		{},
		{},
	}
	requests[0].auth, requests[0].ctx = newRequestOwnedContractAuth(t, cfg, "alice@example.test", "alice-secret", "guid-alice")
	requests[1].auth, requests[1].ctx = newRequestOwnedContractAuth(t, cfg, "bob@example.test", "bob-secret", "guid-bob")

	for index := range requests {
		requests[index].ctx.Request.Header.Set(idempotencyHeaderName, "credential-collision")
		attachContractContext(deadline, requests[index].auth, requests[index].ctx)
	}

	barrier := newVerificationBarrier()
	t.Cleanup(barrier.Release)
	verifier := &controlledDecisionVerifier{
		arrivals:      make(chan verificationObservation, len(requests)),
		sharedBarrier: barrier,
	}
	installRequestOwnedContractVerifier(t, verifier)

	outcomes := make([]<-chan verificationOutcome, len(requests))
	for index := range requests {
		outcomes[index] = startVerification(requests[index].auth, requests[index].ctx)
	}

	for range requests {
		awaitObservation(deadline, t, verifier.arrivals)
	}

	barrier.Release()

	for index := range requests {
		outcome := awaitVerification(deadline, t, outcomes[index])

		if outcome.err != nil {
			t.Fatalf("request %d verification error: %v", index, outcome.err)
		}

		t.Cleanup(func() { PutPassDBResultToPool(outcome.result) })

		wantAccount := requests[index].auth.Request.Username

		if outcome.result.Account != wantAccount || requests[index].auth.GetAccount() != wantAccount {
			t.Fatalf("request %d account result=%q runtime=%q, want %q", index, outcome.result.Account, requests[index].auth.GetAccount(), wantAccount)
		}
	}

	if got := verifier.calls.Load(); got != int32(len(requests)) {
		t.Fatalf("verifier calls = %d, want %d", got, len(requests))
	}
}

func TestPasswordVerificationParallelRequestsReceiveCompleteSemanticDecision(t *testing.T) {
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelDeadline()

	cfg := newCurrentBehaviorConfig(t)
	barrier := newVerificationBarrier()
	t.Cleanup(barrier.Release)
	verifier := &controlledDecisionVerifier{
		arrivals:      make(chan verificationObservation, requestOwnedContractRequests),
		sharedBarrier: barrier,
	}
	installRequestOwnedContractVerifier(t, verifier)

	authStates, contexts, outcomes := startParallelVerificationRequests(deadline, t, cfg)
	requireParallelRequestOwnership(deadline, t, verifier.arrivals)

	barrier.Release()

	snapshots := collectSemanticSnapshots(deadline, t, authStates, contexts, outcomes)

	if got := verifier.calls.Load(); got != requestOwnedContractRequests {
		t.Fatalf("verifier calls = %d, want %d", got, requestOwnedContractRequests)
	}

	for index := 1; index < len(snapshots); index++ {
		if !reflect.DeepEqual(snapshots[index], snapshots[0]) {
			t.Fatalf("request %d semantic decision differs in fields %v", index, differingSemanticFields(snapshots[index], snapshots[0]))
		}
	}
}

func TestPasswordVerificationResultsRemainOwnedAcrossCompletionOrder(t *testing.T) {
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDeadline()

	cfg := newCurrentBehaviorConfig(t)
	contract := newOrderedVerificationContract(deadline, t, cfg)
	contract.requireDistinctAllocatedResults(deadline, t)
	contract.firstBarrier.Release()
	completedFirst := awaitVerification(deadline, t, contract.first.outcome)

	if completedFirst.err != nil {
		t.Fatalf("first request verification error: %v", completedFirst.err)
	}

	want := snapshotAuthentication(contract.first.auth, contract.first.ctx, completedFirst.result, definitions.AuthResultOK)
	firstResultAddress := completedFirst.result
	PutPassDBResultToPool(completedFirst.result)

	contract.secondBarrier.Release()
	completedSecond := awaitVerification(deadline, t, contract.second.outcome)

	if completedSecond.err != nil {
		t.Fatalf("second request verification error: %v", completedSecond.err)
	}

	if completedSecond.result == firstResultAddress {
		PutPassDBResultToPool(completedSecond.result)
		t.Fatal("concurrent requests received the same pooled result object")
	}

	got := snapshotAuthentication(contract.second.auth, contract.second.ctx, completedSecond.result, definitions.AuthResultOK)
	PutPassDBResultToPool(completedSecond.result)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("later-consumed request lost semantic fields %v", differingSemanticFields(got, want))
	}

	if got := contract.verifier.calls.Load(); got != 2 {
		t.Fatalf("verifier calls = %d, want 2", got)
	}
}

func TestPasswordVerificationCancellationIsRequestLocal(t *testing.T) {
	for _, canceledIndex := range []int{0, 1} {
		t.Run("request_"+strconv.Itoa(canceledIndex+1)+"_canceled", func(t *testing.T) {
			deadline, cancelDeadline := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelDeadline()

			cfg := newCurrentBehaviorConfig(t)
			contract := newCancellationVerificationContract(deadline, t, cfg)

			contract.requireCancellationIsolation(deadline, t, canceledIndex)
		})
	}
}

func TestDeferredLocalCacheReplayPreservesCompleteTerminalDecision(t *testing.T) {
	t.Skip("deferred: the local cache does not yet preserve the complete terminal authentication decision")

	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	first, firstCtx := newRequestOwnedContractAuth(t, cfg, "cached@example.test", "cached-secret", "cache-first")
	cacheKey := first.generateLocalCacheKey()
	localCacheDeleteForContract(t, cacheKey)

	verifier := &countingDecisionVerifier{}
	restore := replaceBackendPlanTestServices(t, verifier, nil, nil, successfulDecisionSubject{}, nil)
	t.Cleanup(restore)

	plan := backendExecutionPlan{passDBs: []*PassDBMap{{backend: definitions.BackendLDAP}}}
	firstDecision := first.authenticateUser(firstCtx, plan)
	firstSnapshot := snapshotAuthentication(first, firstCtx, nil, firstDecision)

	second, secondCtx := newRequestOwnedContractAuth(t, cfg, "cached@example.test", "cached-secret", "cache-second")

	if found := second.GetFromLocalCache(secondCtx); !found {
		t.Fatal("request starting after completion did not find the local decision cache")
	}

	secondDecision := second.handleLocalCache(secondCtx)
	secondSnapshot := snapshotAuthentication(second, secondCtx, nil, secondDecision)

	if got := verifier.calls.Load(); got != 1 {
		t.Errorf("backend calls = %d, want 1 within local-cache TTL", got)
	}

	if !reflect.DeepEqual(secondSnapshot, firstSnapshot) {
		t.Fatalf("local-cache replay did not preserve the complete semantic decision; fields differ: %v", differingSemanticFields(secondSnapshot, firstSnapshot))
	}
}

// localCacheDeleteForContract isolates a cache key before and after a contract test.
func localCacheDeleteForContract(t *testing.T, key string) {
	t.Helper()

	localcache.LocalCache.Delete(key)
	t.Cleanup(func() {
		localcache.LocalCache.Delete(key)
	})
}
