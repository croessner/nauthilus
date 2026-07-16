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
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
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

// newPassDBResultFromAuthStateForTest projects request state for semantic test comparisons.
func newPassDBResultFromAuthStateForTest(auth *AuthState) *PassDBResult {
	result := GetPassDBResultFromPool()
	result.Authenticated = true
	result.UserFound = true
	result.AccountField = auth.Runtime.AccountField
	result.Account = auth.GetAccount()
	result.TOTPSecretField = auth.Runtime.TOTPSecretField
	result.TOTPRecoveryField = auth.Runtime.TOTPRecoveryField
	result.UniqueUserIDField = auth.Runtime.UniqueUserIDField
	result.DisplayNameField = auth.Runtime.DisplayNameField
	result.Backend = auth.Runtime.SourcePassDBBackend
	result.BackendName = auth.Runtime.BackendName
	result.BackendRef = auth.Runtime.RemoteBackendRef
	result.Attributes = auth.GetAttributesCopy()
	result.Groups = auth.GetGroups()
	result.GroupDistinguishedNames = auth.GetGroupDistinguishedNames()
	result.AdditionalAttributes = maps.Clone(auth.Runtime.AdditionalAttributes)

	return result
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
	AccountField            string
	TOTPSecretField         string
	TOTPRecoveryField       string
	UniqueUserIDField       string
	DisplayNameField        string
	BackendName             string
	UsedBackendIP           string
	StatusMessage           string
	StatusMessageI18NKey    string
	ResponseLanguage        string
	AuthFSMTerminalState    string
	RemoteBackendRef        RemoteBackendRef
	SourcePassDBBackend     definitions.Backend
	UsedPassDBBackend       definitions.Backend
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
		AccountField:            auth.Runtime.AccountField,
		TOTPSecretField:         auth.Runtime.TOTPSecretField,
		TOTPRecoveryField:       auth.Runtime.TOTPRecoveryField,
		UniqueUserIDField:       auth.Runtime.UniqueUserIDField,
		DisplayNameField:        auth.Runtime.DisplayNameField,
		BackendName:             auth.Runtime.BackendName,
		UsedBackendIP:           auth.Runtime.UsedBackendIP,
		StatusMessage:           auth.Runtime.StatusMessage,
		StatusMessageI18NKey:    auth.Runtime.StatusMessageI18NKey,
		ResponseLanguage:        auth.Runtime.ResponseLanguage,
		AuthFSMTerminalState:    auth.Runtime.AuthFSMTerminalState,
		RemoteBackendRef:        auth.Runtime.RemoteBackendRef,
		SourcePassDBBackend:     auth.Runtime.SourcePassDBBackend,
		UsedPassDBBackend:       auth.Runtime.UsedPassDBBackend,
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

// runPositiveBackendAuthenticationRequest executes one normal password-FSM request.
func runPositiveBackendAuthenticationRequest(
	t *testing.T,
	cfg *config.FileSettings,
	cache *PositiveBackendAuthenticationCache,
	guid string,
	wantHit bool,
) (*AuthState, *gin.Context, semanticAuthenticationSnapshot) {
	t.Helper()

	auth, ctx := newRequestOwnedContractAuth(t, cfg, "cached@example.test", "cached-secret", guid)
	auth.deps.BackendAuthenticationCache = cache

	if rejected := auth.PreproccessAuthRequest(ctx); rejected {
		t.Fatalf("%s request was rejected during preprocessing", guid)
	}

	if ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		t.Fatalf("%s applied local backend state before the password phase", guid)
	}

	auth.runPasswordFSMPhase(ctx, authFSMStatePreAuthChecked)

	if got := ctx.GetBool(definitions.CtxLocalCacheAuthKey); got != wantHit {
		t.Fatalf("%s local backend hit = %v, want %v after password phase", guid, got, wantHit)
	}

	result := newPassDBResultFromAuthStateForTest(auth)
	snapshot := snapshotAuthentication(auth, ctx, result, definitions.AuthResultOK)
	PutPassDBResultToPool(result)

	return auth, ctx, snapshot
}

// backendAuthenticationExpiry returns the fixed expiry of one stored decision.
func backendAuthenticationExpiry(t *testing.T, cache *PositiveBackendAuthenticationCache, auth *AuthState) time.Time {
	t.Helper()

	value, found := cache.storage.Get(mustBuildBackendAuthenticationCacheKey(t, auth).storageKey())

	if !found {
		t.Fatalf("stored decision missing: authenticated=%v authorized=%v terminal=%q", auth.Runtime.Authenticated, auth.Runtime.Authorized, auth.Runtime.AuthFSMTerminalState)
	}

	return value.(*backendAuthenticationCacheEntry).expiresAt
}

// assertPositiveBackendAuthenticationWorkCounts proves backend-only warm reuse.
func assertPositiveBackendAuthenticationWorkCounts(
	t *testing.T,
	verifierCalls, subjectCalls *atomic.Int32,
	policyBridge *backendAuthenticationPolicyBridge,
) {
	t.Helper()

	checks := map[string]struct {
		got  int32
		want int32
	}{
		"backend verification":    {got: verifierCalls.Load(), want: 1},
		"subject decision":        {got: subjectCalls.Load(), want: 2},
		"configured final-policy": {got: policyBridge.effectCalls.Load(), want: 2},
		"post decision":           {got: policyBridge.postCalls.Load(), want: 2},
	}

	for name, check := range checks {
		if check.got != check.want {
			t.Fatalf("%s calls = %d, want %d across cold and warm requests", name, check.got, check.want)
		}
	}
}

func TestPositiveBackendAuthenticationCacheColdWarmReevaluatesCompleteTerminalDecision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePositiveBackendAuthenticationPolicy(t)

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}

	restoreServices := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)
	defer restoreServices()

	backendAuthenticationCache := NewPositiveBackendAuthenticationCache(time.Now)
	first, _, firstSnapshot := runPositiveBackendAuthenticationRequest(t, cfg, backendAuthenticationCache, "cache-first", false)
	expiresAt := backendAuthenticationExpiry(t, backendAuthenticationCache, first)
	_, _, secondSnapshot := runPositiveBackendAuthenticationRequest(t, cfg, backendAuthenticationCache, "cache-second", true)
	warmExpiresAt := backendAuthenticationExpiry(t, backendAuthenticationCache, first)

	if !warmExpiresAt.Equal(expiresAt) {
		t.Fatalf("warm replay refreshed fixed TTL from %v to %v", expiresAt, warmExpiresAt)
	}

	normalizeCacheSpecificSnapshot(&firstSnapshot)
	normalizeCacheSpecificSnapshot(&secondSnapshot)

	if !reflect.DeepEqual(secondSnapshot, firstSnapshot) {
		t.Fatalf("local-cache replay did not preserve the complete semantic decision; fields differ: %v; cold additional=%#v warm additional=%#v; cold headers=%v warm headers=%v", differingSemanticFields(secondSnapshot, firstSnapshot), firstSnapshot.AdditionalAttributes, secondSnapshot.AdditionalAttributes, firstSnapshot.ResponseHeaders, secondSnapshot.ResponseHeaders)
	}

	assertPositiveBackendAuthenticationWorkCounts(t, verifierCalls, subjectCalls, policyBridge)
}

type panickingSetIPAddressTolerate struct {
	tolerate.Tolerate
}

// SetIPAddress simulates a terminal success side-effect panic.
func (panickingSetIPAddressTolerate) SetIPAddress(context.Context, string, string, bool) {
	panic("terminal tolerate panic")
}

// runPasswordFSMPhaseRecovering captures a terminal-outcome panic for cache assertions.
func runPasswordFSMPhaseRecovering(auth *AuthState, ctx *gin.Context) (recovered any) {
	defer func() {
		recovered = recover()
	}()

	auth.runPasswordFSMPhase(ctx, authFSMStatePreAuthChecked)

	return nil
}

func TestPositiveBackendAuthenticationCacheRetainsBackendSnapshotAcrossTerminalOutcomePanic(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePositiveBackendAuthenticationPolicy(t)

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}

	restoreServices := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)
	defer restoreServices()

	testCases := map[string]func(*AuthState){
		"response writer": func(auth *AuthState) { auth.deps.Resp = panicResponseWriter{} },
		"tolerate":        func(auth *AuthState) { auth.deps.Tolerate = panickingSetIPAddressTolerate{} },
	}

	for name, installPanic := range testCases {
		t.Run(name, func(t *testing.T) {
			cache := NewPositiveBackendAuthenticationCache(time.Now)
			auth, ctx := newRequestOwnedContractAuth(t, cfg, "panic@example.test", "cached-secret", "panic-outcome")
			auth.deps.BackendAuthenticationCache = cache

			if rejected := auth.PreproccessAuthRequest(ctx); rejected {
				t.Fatal("cold request was rejected during preprocessing")
			}

			installPanic(auth)

			if recovered := runPasswordFSMPhaseRecovering(auth, ctx); recovered == nil {
				t.Fatal("terminal outcome did not panic")
			}

			if _, found := cache.load(mustBuildBackendAuthenticationCacheKey(t, auth)); !found {
				t.Fatal("valid backend snapshot was lost after terminal outcome panic")
			}
		})
	}
}

type cancelingOKResponseWriter struct {
	cancel context.CancelFunc
}

// OK cancels one request-context source during terminal outcome application.
func (w cancelingOKResponseWriter) OK(*gin.Context, *StateView) {
	w.cancel()
}

// Fail rejects an unexpected failure outcome.
func (cancelingOKResponseWriter) Fail(*gin.Context, *StateView) {
	panic("unexpected failure outcome")
}

// TempFail rejects an unexpected temporary-failure outcome.
func (cancelingOKResponseWriter) TempFail(*gin.Context, *StateView, string) {
	panic("unexpected temporary-failure outcome")
}

func TestPositiveBackendAuthenticationCacheRetainsSnapshotAfterTerminalOutcomeCancellation(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePositiveBackendAuthenticationPolicy(t)

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	policyBridge := &backendAuthenticationPolicyBridge{}

	restoreServices := installPositiveBackendAuthenticationServices(t, verifierCalls, subjectCalls, policyBridge)
	defer restoreServices()

	for _, source := range []string{"gin", "auth"} {
		t.Run(source, func(t *testing.T) {
			cache := NewPositiveBackendAuthenticationCache(time.Now)
			auth, ctx := newRequestOwnedContractAuth(t, cfg, "cancel-after-outcome@example.test", "cached-secret", "cancel-after-outcome")
			auth.deps.BackendAuthenticationCache = cache

			if rejected := auth.PreproccessAuthRequest(ctx); rejected {
				t.Fatal("cold request was rejected during preprocessing")
			}

			requestContext, cancel := context.WithCancel(context.Background())
			ctx.Request = ctx.Request.WithContext(context.Background())
			auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(context.Background())

			if source == "gin" {
				ctx.Request = ctx.Request.WithContext(requestContext)
			} else {
				auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(requestContext)
			}

			auth.deps.Resp = cancelingOKResponseWriter{cancel: cancel}
			auth.runPasswordFSMPhase(ctx, authFSMStatePreAuthChecked)

			if _, found := cache.load(mustBuildBackendAuthenticationCacheKey(t, auth)); !found {
				t.Fatal("backend snapshot was lost after later terminal cancellation")
			}
		})
	}
}

func TestPositiveBackendAuthenticationCacheWarmReevaluatesDefaultFinalPolicy(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    212,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	cache := NewPositiveBackendAuthenticationCache(time.Now)
	source, sourceCtx := newRequestOwnedContractAuth(t, cfg, "default-policy@example.test", "credential", "default-policy-source")

	result := newSemanticPassDBResult(sourceCtx, source)
	defer PutPassDBResultToPool(result)

	if !cache.StoreForRequest(sourceCtx, source, result, time.Minute, source.Request.Username) {
		t.Fatal("failed to seed default-policy decision")
	}

	warm, warmCtx := newRequestOwnedContractAuth(t, cfg, source.Request.Username, "credential", "default-policy-warm")
	warm.deps.BackendAuthenticationCache = cache

	if rejected := warm.PreproccessAuthRequest(warmCtx); rejected || warmCtx.GetBool(definitions.CtxLocalCacheAuthKey) {
		t.Fatal("warm request consumed backend state during preprocessing")
	}

	if got := warm.HandlePassword(warmCtx); got != definitions.AuthResultOK {
		t.Fatalf("warm password result = %v, want %v", got, definitions.AuthResultOK)
	}

	if !warmCtx.GetBool(definitions.CtxLocalCacheAuthKey) {
		t.Fatal("warm request missed at backend verification boundary")
	}

	policyCtx, ok := policyDecisionContext(warmCtx)
	if !ok {
		t.Fatal("warm request did not complete policy-stage reporting")
	}

	if policyCtx.Report().Final == nil {
		t.Fatal("default final policy was not reevaluated on warm backend-cache hit")
	}
}

// normalizeCacheSpecificSnapshot removes intentionally request-local response metadata.
func normalizeCacheSpecificSnapshot(snapshot *semanticAuthenticationSnapshot) {
	snapshot.ResponseHeaders.Del("X-Nauthilus-Memory-Cache")
	snapshot.ResponseHeaders.Del("X-Nauthilus-Session")
	snapshot.UsedPassDBBackend = snapshot.SourcePassDBBackend
	snapshot.Result.Backend = snapshot.SourcePassDBBackend
}

// backendAuthenticationContractVerifier returns one complete request-owned backend result.
type backendAuthenticationContractVerifier struct {
	calls *atomic.Int32
}

// Verify records backend execution and returns meaningful final-decision fields.
func (v backendAuthenticationContractVerifier) Verify(ctx *gin.Context, auth *AuthState, passDBs []*PassDBMap) (*PassDBResult, error) {
	v.calls.Add(1)

	result := GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = true
	result.BackendName = "ldap-primary"
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.TOTPSecretField = "totpSecret"
	result.TOTPRecoveryField = "recoveryCodes"
	result.UniqueUserIDField = "entryUUID"
	result.DisplayNameField = "displayName"
	result.Backend = definitions.BackendLDAP
	result.BackendRef = RemoteBackendRef{Type: "ldap", Name: "primary", Protocol: auth.Request.Protocol.Get(), Authority: "ldap.example.test"}
	result.Attributes = bktype.AttributeMapping{"uid": {auth.Request.Username}, "displayName": {"Cache Contract User"}}
	result.Groups = []string{"mail-users", "staff"}
	result.GroupDistinguishedNames = []string{"cn=mail-users,dc=example,dc=test", "cn=staff,dc=example,dc=test"}
	result.AdditionalAttributes = map[string]any{"tenant": "example", "quota": "10G"}

	passDB := &PassDBMap{backend: definitions.BackendLDAP}
	if len(passDBs) > 0 {
		passDB = passDBs[0]
	}

	if err := ProcessPassDBResult(ctx, result, auth, passDB); err != nil {
		PutPassDBResultToPool(result)

		return nil, err
	}

	return result, nil
}

// backendAuthenticationContractSubject records one complete subject decision.
type backendAuthenticationContractSubject struct {
	calls *atomic.Int32
}

// Analyze records subject work and installs response-relevant semantic fields.
func (s backendAuthenticationContractSubject) Analyze(_ *gin.Context, view *StateView, result *PassDBResult) definitions.AuthResult {
	s.calls.Add(1)

	auth := view.Auth()
	auth.Runtime.Authorized = true
	auth.Runtime.UsedBackendIP = "192.0.2.10"
	auth.Runtime.UsedBackendPort = 389
	auth.Runtime.StatusMessage = "authentication accepted"
	auth.Runtime.StatusMessageI18NKey = "auth.success"
	auth.Runtime.ResponseLanguage = "de"
	auth.Runtime.AdditionalAttributes = maps.Clone(result.AdditionalAttributes)

	return definitions.AuthResultOK
}

// backendAuthenticationPolicyBridge counts selected final-policy effects and post plans.
type backendAuthenticationPolicyBridge struct {
	effectCalls atomic.Int32
	postCalls   atomic.Int32
}

// IsPostActionEffect leaves native effects on the synchronous path.
func (*backendAuthenticationPolicyBridge) IsPostActionEffect(report.EffectRequest) bool {
	return false
}

// EnqueuePostActionPlan records and releases one selected post-decision plan.
func (b *backendAuthenticationPolicyBridge) EnqueuePostActionPlan(_ *gin.Context, _ *StateView, steps []PostActionPlanStep) (bool, bool) {
	b.postCalls.Add(1)
	ReleasePostActionPlanSteps(steps)

	return true, true
}

// ExecutePolicyEffect records one synchronous configured final-policy effect.
func (b *backendAuthenticationPolicyBridge) ExecutePolicyEffect(_ *gin.Context, _ *StateView, _ report.EffectRequest) (bool, bool) {
	b.effectCalls.Add(1)

	return true, true
}

// activatePositiveBackendAuthenticationPolicy selects an unconditional permit with observable obligations.
func activatePositiveBackendAuthenticationPolicy(t *testing.T) {
	t.Helper()

	snapshot := customEnforceAuthSnapshotForTest()
	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision]
	compiled.Policies[0].Root = policyruntime.CompiledExpr{Kind: policyruntime.ExprKindAlways}
	compiled.Policies[0].Then.Decision = policy.DecisionPermit
	compiled.Policies[0].Then.FSMEventMarker = policy.FSMEventMarkerAuthPermit
	compiled.Policies[0].Then.ResponseMarker = policy.ResponseMarkerOK
	compiled.Policies[0].Then.Obligations = []policyruntime.EffectRequest{
		{ID: policyAuthorityPluginEffectID},
		{ID: policy.ObligationLuaPostActionEnqueue},
	}
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = compiled
	activatePolicySnapshotForTest(t, snapshot)
}

// installPositiveBackendAuthenticationServices installs deterministic decision-work counters.
func installPositiveBackendAuthenticationServices(
	t *testing.T,
	verifierCalls *atomic.Int32,
	subjectCalls *atomic.Int32,
	policyBridge *backendAuthenticationPolicyBridge,
) func() {
	t.Helper()

	previousVerifier := getPasswordVerifier()
	previousSubject := getLuaSubject()
	previousPost := getPostAction()
	previousBridge := getPluginEffectBridge()

	RegisterPasswordVerifier(backendAuthenticationContractVerifier{calls: verifierCalls})
	RegisterLuaSubject(backendAuthenticationContractSubject{calls: subjectCalls})
	RegisterPostAction(recordingPlanPostAction{})
	RegisterPluginEffectBridge(policyBridge)

	return func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterLuaSubject(previousSubject)
		RegisterPostAction(previousPost)
		RegisterPluginEffectBridge(previousBridge)
	}
}
