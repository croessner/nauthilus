// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v4/server/core"
	coreauth "github.com/croessner/nauthilus/v4/server/core/auth"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/security"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// canonicalMFACacheFixture models a cache-first lookup independently of LDAP writes.
type canonicalMFACacheFixture struct {
	*recordingBackendDataApplication
	coreauth.DefaultCacheService
	mu     sync.Mutex
	stored bktype.AttributeMapping
	cached *core.AuthOutcome
	purged []string
}

// LookupIdentity returns the cached snapshot until the account is explicitly purged.
func (f *canonicalMFACacheFixture) LookupIdentity(_ context.Context, _ core.AuthInput) (*core.AuthOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cached == nil {
		snapshot := *f.outcome
		snapshot.Attributes = maps.Clone(f.stored)
		f.cached = &snapshot
	}

	return f.cached, nil
}

// Purge invalidates only the canonical account, which differs from the login alias.
func (f *canonicalMFACacheFixture) Purge(_ *core.AuthState, username string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.purged = append(f.purged, username)
	if username == backendDataUsername {
		f.cached = nil
	}
}

// serve handles real manager requests against an independently mutable LDAP image.
func (f *canonicalMFACacheFixture) serve(pool string, done chan<- struct{}) {
	defer close(done)

	for {
		req := priorityqueue.LDAPQueue.Pop(pool)
		if req == nil || req.LDAPReplyChan == nil {
			return
		}

		f.mu.Lock()

		reply := &bktype.LDAPReply{}
		if req.Command == definitions.LDAPSearch {
			reply.Result = maps.Clone(f.stored)
		} else {
			for field, values := range req.ModifyAttributes {
				switch req.SubCommand {
				case definitions.LDAPModifyDelete:
					reply.Err = f.deleteValues(field, values)

				default:
					replaced := make([]any, len(values))
					for i, value := range values {
						replaced[i] = value
					}

					f.stored[field] = replaced
				}
			}
		}
		f.mu.Unlock()

		req.LDAPReplyChan <- reply
	}
}

// deleteValues models LDAP exact-value deletion without permissive modify semantics.
func (f *canonicalMFACacheFixture) deleteValues(field string, values []string) error {
	remaining := []any{}
	found := len(values) == 0

	for _, old := range f.stored[field] {
		matched := len(values) == 0
		for _, value := range values {
			matched = matched || old == value
		}

		if matched {
			found = true
		} else {
			remaining = append(remaining, old)
		}
	}

	if !found {
		return ldap.NewError(ldap.LDAPResultNoSuchAttribute, nil)
	}

	f.stored[field] = remaining

	return nil
}

// newCanonicalMFACacheFixture binds canonical handlers to cached identity reads and LDAP writes.
func newCanonicalMFACacheFixture(t *testing.T) (*FrontendHandler, *gin.Context, canonicalEnrollmentSelectionState, *canonicalMFACacheFixture) {
	t.Helper()
	base := newBackendDataLDAPFixture(t)
	application := base.application.(*recordingBackendDataApplication)
	f := &canonicalMFACacheFixture{recordingBackendDataApplication: application, stored: maps.Clone(application.outcome.Attributes)}
	delete(f.stored, backendDataAttrTOTPSecret)
	delete(f.stored, backendDataAttrRecoveryCode)
	base.application = f
	h := newBackendDataFrontendHandler(base.backendDataBaseFixture)
	h.deps.HostServices = newMFACacheHostServices(t, f)

	runtime, browser, _ := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	session := openCanonicalFixture(t, runtime, browser)
	assert.NoError(t, session.CommitIdentity(context.Background(), cookie.IdentityUpdate{
		Reference: backendDataUniqueUserID, Account: backendDataUsername, Subject: backendDataUniqueUserID, Protocol: definitions.ProtoIDP,
	}))
	identity, _ := session.Identity()
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/register", nil)
	ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	// Backend data may probe the optional WebAuthn cache on every lookup.
	base.mock.MatchExpectationsInOrder(false)

	for range 20 {
		base.expectEmptyWebAuthnCache(backendDataUniqueUserID)
	}

	done := make(chan struct{})
	go f.serve(base.poolName, done)

	t.Cleanup(func() { priorityqueue.LDAPQueue.Push(&bktype.LDAPRequest{PoolName: base.poolName}, 0); <-done })

	return h, ctx, canonicalEnrollmentSelectionState{session: session, identity: identity, parent: &flowdomain.State{Protocol: flowdomain.FlowProtocolInternal}}, f
}

// TestCanonicalEnrollmentInvalidatesCachedFactors reproduces the required-MFA enrollment loop.
func TestCanonicalEnrollmentInvalidatesCachedFactors(t *testing.T) {
	for _, method := range []string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes} {
		t.Run(method, func(t *testing.T) {
			h, ctx, selection, f := newCanonicalMFACacheFixture(t)
			missing, err := h.canonicalMissingRequiredMFA(ctx, selection.session, selection.parent, selection.identity, []string{method})
			assert.NoError(t, err)
			assert.Equal(t, []string{method}, missing)

			if method == definitions.MFAMethodTOTP {
				code, codeErr := totp.GenerateCode(backendDataTOTPSecret, time.Now())
				assert.NoError(t, codeErr)

				valid, finishErr := h.finishCanonicalTOTPEnrollment(ctx, selection, canonicalTOTPEnrollmentPending{Secret: backendDataTOTPSecret}, "operation", code)
				assert.NoError(t, finishErr)
				assert.True(t, valid)
			} else {
				assert.NoError(t, h.persistCanonicalRecoveryEnrollment(ctx, selection, "operation", []string{"single-use-code"}))
			}

			missing, err = h.canonicalMissingRequiredMFA(ctx, selection.session, selection.parent, selection.identity, []string{method})
			assert.NoError(t, err)
			assert.Empty(t, missing, "successful enrollment must be visible to the next required-MFA check")
			assert.Contains(t, f.purged, selection.identity.Account)
		})
	}
}

// TestCanonicalRecoveryRejectsCachedReplay consumes a code in separate verification attempts.
func TestCanonicalRecoveryRejectsCachedReplay(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		name := "encrypted"
		if duplicate {
			name = "duplicate_ciphertexts"
		}

		t.Run(name, func(t *testing.T) {
			h, ctx, enrollment, f := newCanonicalMFACacheFixture(t)

			f.stored[backendDataAttrRecoveryCode] = encryptedRecoveryFixtureValues(t, h, "single-use-code", "other-code")
			if duplicate {
				f.stored[backendDataAttrRecoveryCode] = append(f.stored[backendDataAttrRecoveryCode], encryptedRecoveryFixtureValues(t, h, "single-use-code")...)
			}
			// The passdb snapshot is already decrypted by the identity application.
			snapshot := *f.outcome
			snapshot.Attributes = maps.Clone(f.stored)
			snapshot.Attributes[backendDataAttrRecoveryCode] = []any{"single-use-code", "other-code"}
			f.cached = &snapshot

			selection := canonicalMFASelectionState{identity: enrollment.identity, parent: enrollment.parent, session: enrollment.session}
			valid, err := h.verifyCanonicalRecovery(ctx, selection, "single-use-code")
			assert.NoError(t, err)
			assert.True(t, valid)
			// Restore a stale snapshot even after purge: replay safety must not depend on cache availability.
			f.mu.Lock()
			f.cached = &snapshot
			f.mu.Unlock()

			valid, err = h.verifyCanonicalRecovery(ctx, selection, "single-use-code")
			assert.NoError(t, err)
			assert.False(t, valid, "consumed recovery code must not be accepted from a stale cache")
			assert.Contains(t, f.purged, enrollment.identity.Account)
		})
	}
}

// TestCanonicalRecoveryConcurrentConsumeAllowsOneWinner exercises exact-value LDAP deletion.
func TestCanonicalRecoveryConcurrentConsumeAllowsOneWinner(t *testing.T) {
	h, ctx, enrollment, f := newCanonicalMFACacheFixture(t)
	f.stored[backendDataAttrRecoveryCode] = encryptedRecoveryFixtureValues(t, h, "single-use-code", "other-code")
	other := f.stored[backendDataAttrRecoveryCode][1]
	data, err := h.canonicalEnrollmentBackendData(ctx, enrollment)
	assert.NoError(t, err)

	manager := data.AuthState.GetBackendManager(data.AuthState.Runtime.UsedPassDBBackend, data.AuthState.Runtime.BackendName)

	consumer, ok := manager.(core.TOTPRecoveryCodeConsumer)
	if !assert.True(t, ok, "LDAP must provide atomic consumption") {
		return
	}

	start := make(chan struct{})
	results := make(chan bool, 2)
	errors := make(chan error, 2)

	for range 2 {
		go func() {
			<-start

			valid, _, consumeErr := consumer.ConsumeTOTPRecoveryCode(data.AuthState, "single-use-code")
			results <- valid

			errors <- consumeErr
		}()
	}

	close(start)

	winners := 0

	for range 2 {
		if <-results {
			winners++
		}

		assert.NoError(t, <-errors)
	}

	assert.Equal(t, 1, winners)
	f.mu.Lock()
	defer f.mu.Unlock()

	assert.Equal(t, []any{other}, f.stored[backendDataAttrRecoveryCode])
}

// encryptedRecoveryFixtureValues encodes backend values separately from decrypted cache snapshots.
func encryptedRecoveryFixtureValues(t *testing.T, h *FrontendHandler, codes ...string) []any {
	t.Helper()

	manager := security.NewManager(h.deps.Cfg.GetLDAPConfigEncryptionSecret())

	values := make([]any, 0, len(codes))
	for _, code := range codes {
		value, err := manager.Encrypt(code)
		assert.NoError(t, err)

		values = append(values, value)
	}

	return values
}

// newMFACacheHostServices installs an observable purge service with production host dependencies.
func newMFACacheHostServices(t *testing.T, f *canonicalMFACacheFixture) core.AuthnHostServices {
	t.Helper()

	services, err := core.NewAuthnHostServices(core.AuthnHostServicesInput{
		PasswordVerifier: coreauth.DefaultPasswordVerifier{}, Cache: f,
		BruteForce: coreauth.DefaultBruteForceService{}, Subject: coreauth.DefaultLuaSubject{}, RBL: coreauth.DefaultRBLService{},
	})
	assert.NoError(t, err)

	return services
}
