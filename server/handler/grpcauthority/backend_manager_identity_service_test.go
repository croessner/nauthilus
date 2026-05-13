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

package grpcauthority

import (
	"context"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/mfa"
)

const (
	authorityMFATestRecoveryCodeA = "consume-once"
	authorityMFATestRecoveryCodeB = "keep-code"
	authorityMFATestSecretField   = "test_totp_secret"
	authorityMFATestRecoveryField = "test_totp_recovery"
	authorityMFATestTOTPSecret    = "JBSWY3DPEHPK3PXP"
)

func TestBackendManagerIdentityServiceMFAStateDoesNotExposeStoredSecrets(t *testing.T) {
	backendName := "authority-mfa-state-secrets"
	username := "secret-state@example.test"
	deps := core.AuthDeps{}

	seedAuthorityMFATestUser(t, deps, backendName, username, authorityMFATestTOTPSecret, []string{
		authorityMFATestRecoveryCodeA,
		authorityMFATestRecoveryCodeB,
	})

	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{AuthDeps: deps})

	result, err := service.GetMFAState(context.Background(), authorityMFATestInput(backendName, username))
	if err != nil {
		t.Fatalf("GetMFAState() error = %v", err)
	}

	if !result.MFA.HasTOTP {
		t.Fatal("GetMFAState() HasTOTP = false, want true")
	}

	if result.MFA.RecoveryCodeCount != 2 {
		t.Fatalf("GetMFAState() recovery count = %d, want 2", result.MFA.RecoveryCodeCount)
	}

	if result.TOTPSecret != "" || len(result.RecoveryCodes) != 0 {
		t.Fatalf("GetMFAState() exposed TOTP secret %q or recovery codes %#v", result.TOTPSecret, result.RecoveryCodes)
	}
}

func TestAuthorityUserSnapshotFiltersMFASecretAttributes(t *testing.T) {
	outcome := &core.AuthOutcome{
		Decision:          core.AuthDecisionOK,
		AccountField:      authorityTestUID,
		TOTPSecretField:   authorityMFATestSecretField,
		TOTPRecoveryField: authorityMFATestRecoveryField,
		Backend:           definitions.BackendTest,
		Attributes: bktype.AttributeMapping{
			authorityTestUID:              []any{"snapshot@example.test"},
			authorityMFATestSecretField:   []any{authorityMFATestTOTPSecret},
			authorityMFATestRecoveryField: []any{authorityMFATestRecoveryCodeA, authorityMFATestRecoveryCodeB},
		},
	}

	user := userSnapshotFromOutcome(AuthorityIdentityInput{}, outcome, BackendRefPayload{}, AuthorityMFAState{})
	if user == nil {
		t.Fatal("userSnapshotFromOutcome() returned nil")
	}

	if _, ok := user.Attributes[authorityMFATestSecretField]; ok {
		t.Fatalf("user snapshot exposed %s", authorityMFATestSecretField)
	}

	if _, ok := user.Attributes[authorityMFATestRecoveryField]; ok {
		t.Fatalf("user snapshot exposed %s", authorityMFATestRecoveryField)
	}
}

func TestBackendManagerIdentityServiceConsumesRecoveryCodeOnce(t *testing.T) {
	backendName := "authority-recovery-consume-once"
	username := "consume-once@example.test"
	deps := core.AuthDeps{}

	seedAuthorityMFATestUser(t, deps, backendName, username, "", []string{
		authorityMFATestRecoveryCodeA,
		authorityMFATestRecoveryCodeB,
	})

	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{AuthDeps: deps})
	input := authorityMFATestInput(backendName, username)
	input.Code = authorityMFATestRecoveryCodeA

	results := useRecoveryCodeConcurrently(t, service, input, 2)
	validResults := 0

	for _, result := range results {
		if result.Valid {
			validResults++
		}

		if result.RemainingRecoveryCodeCount != 1 {
			t.Fatalf("remaining recovery count = %d, want 1", result.RemainingRecoveryCodeCount)
		}
	}

	if validResults != 1 {
		t.Fatalf("valid recovery consumptions = %d, want 1", validResults)
	}

	state, err := service.GetMFAState(context.Background(), authorityMFATestInput(backendName, username))
	if err != nil {
		t.Fatalf("GetMFAState() error = %v", err)
	}

	if state.MFA.RecoveryCodeCount != 1 {
		t.Fatalf("final recovery count = %d, want 1", state.MFA.RecoveryCodeCount)
	}
}

func useRecoveryCodeConcurrently(
	t *testing.T,
	service AuthorityIdentityService,
	input AuthorityIdentityInput,
	attempts int,
) []*AuthorityIdentityResult {
	t.Helper()

	results := make(chan *AuthorityIdentityResult, attempts)
	errs := make(chan error, attempts)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			result, err := service.UseRecoveryCode(context.Background(), input)
			if err != nil {
				errs <- err

				return
			}

			results <- result
		}()
	}

	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("UseRecoveryCode() error = %v", err)
	}

	collected := make([]*AuthorityIdentityResult, 0, attempts)
	for result := range results {
		collected = append(collected, result)
	}

	return collected
}

func seedAuthorityMFATestUser(
	t *testing.T,
	deps core.AuthDeps,
	backendName string,
	username string,
	totpSecret string,
	recoveryCodes []string,
) {
	t.Helper()

	core.InitPassDBResultPool()

	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetUsername(username)

	manager := core.NewTestBackendManager(backendName, deps)
	if totpSecret != "" {
		if err := manager.AddTOTPSecret(auth, core.NewTOTPSecret(totpSecret)); err != nil {
			t.Fatalf("AddTOTPSecret() error = %v", err)
		}
	}

	if len(recoveryCodes) > 0 {
		if err := manager.AddTOTPRecoveryCodes(auth, mfa.NewTOTPRecovery(recoveryCodes)); err != nil {
			t.Fatalf("AddTOTPRecoveryCodes() error = %v", err)
		}
	}
}

func authorityMFATestInput(backendName string, username string) AuthorityIdentityInput {
	return AuthorityIdentityInput{
		Username: username,
		Backend: BackendRefPayload{
			Type:     definitions.BackendTestName,
			Name:     backendName,
			Protocol: definitions.ProtoIMAP,
			Username: username,
			Account:  username,
		},
	}
}
