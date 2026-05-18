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
	"errors"
	"net/url"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	authorityMFATestRecoveryCodeA = "consume-once"
	authorityMFATestRecoveryCodeB = "keep-code"
	authorityMFATestSecretField   = "test_totp_secret"
	authorityMFATestRecoveryField = "test_totp_recovery"
	authorityMFATestTOTPSecret    = "JBSWY3DPEHPK3PXP"
	authorityAttributeMail        = "mail"
	authorityAttributeEmployee    = "employeeNumber"
	authorityAttributeMissing     = "missingAttribute"
	authorityAttributePrivateKey  = "sshPrivateKey"
	authorityAttributeRaw         = "unrequestedRawAttribute"
	authorityAttributeSecret      = "oidcClientSecretFromBackend"
	authorityAttributeBearer      = "upstreamBearerTokenAttribute"
	authoritySnapshotMail         = "snapshot@example.test"
	authorityEmployeeNumber       = "1234"
	authorityTOTPIssuer           = "AuthorityIssuer"
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

func TestBackendManagerIdentityServiceBeginTOTPRegistrationUsesConfiguredIssuer(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				TotpIssuer: authorityTOTPIssuer,
			},
		},
	}
	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{
		AuthDeps: core.AuthDeps{Cfg: cfg},
	})

	result, err := service.BeginTOTPRegistration(
		context.Background(),
		authorityMFATestInput("authority-totp-issuer", "issuer-user@example.test"),
	)
	if err != nil {
		t.Fatalf("BeginTOTPRegistration() error = %v", err)
	}

	parsed, err := url.Parse(result.OTPAuthURL)
	if err != nil {
		t.Fatalf("parse OTPAuthURL: %v", err)
	}

	if got := parsed.Query().Get("issuer"); got != authorityTOTPIssuer {
		t.Fatalf("issuer = %q, want %s", got, authorityTOTPIssuer)
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
			authorityTestUID:              []any{authoritySnapshotMail},
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

func TestAuthorityRequestedAttributeReleaseDoesNotDefaultToRawAttributes(t *testing.T) {
	release := releaseRequestedAttributes(
		bktype.AttributeMapping{
			authorityTestUID:           []any{authoritySnapshotMail},
			authorityAttributeMail:     []any{authoritySnapshotMail},
			authorityAttributeEmployee: []any{authorityEmployeeNumber},
		},
		&identityv1.AttributeRequest{IncludeStandardIdentity: true},
	)

	if len(release.Attributes) != 0 {
		t.Fatalf("released attributes = %#v, want no raw attributes without requested names", release.Attributes)
	}
}

func TestAuthorityRequestedAttributeReleaseReportsDeniedAndMissingSafely(t *testing.T) {
	release := releaseRequestedAttributes(
		bktype.AttributeMapping{
			authorityAttributeMail:        []any{authoritySnapshotMail},
			authorityAttributeEmployee:    []any{authorityEmployeeNumber},
			authorityMFATestSecretField:   []any{authorityMFATestTOTPSecret},
			authorityMFATestRecoveryField: []any{authorityMFATestRecoveryCodeA},
			authorityAttributePrivateKey:  []any{"private-key-material"},
			authorityAttributeRaw:         []any{"must-not-leak"},
			authorityAttributeSecret:      []any{"client-secret"},
			authorityAttributeBearer:      []any{"bearer-token"},
		},
		&identityv1.AttributeRequest{
			Names: []string{
				authorityAttributeMail,
				authorityAttributeMissing,
				authorityMFATestSecretField,
				authorityMFATestRecoveryField,
				authorityAttributePrivateKey,
				authorityAttributeSecret,
				authorityAttributeBearer,
			},
			ReportMissing: true,
		},
		authorityMFATestSecretField,
		authorityMFATestRecoveryField,
	)

	if got := release.Attributes[authorityAttributeMail]; len(got) != 1 || got[0] != authoritySnapshotMail {
		t.Fatalf("released mail = %#v, want snapshot@example.test", got)
	}

	for _, name := range []string{
		authorityMFATestSecretField,
		authorityMFATestRecoveryField,
		authorityAttributePrivateKey,
		authorityAttributeSecret,
		authorityAttributeBearer,
		authorityAttributeRaw,
	} {
		if _, ok := release.Attributes[name]; ok {
			t.Fatalf("released sensitive or unrequested attribute %q", name)
		}
	}

	assertSameStringSet(t, release.Missing, []string{authorityAttributeMissing})
	assertSameStringSet(t, release.Denied, []string{
		authorityMFATestSecretField,
		authorityMFATestRecoveryField,
		authorityAttributeSecret,
		authorityAttributePrivateKey,
		authorityAttributeBearer,
	})
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

func TestBackendManagerIdentityServiceWebAuthnUpdateComparesPersistentState(t *testing.T) {
	backendName := "authority-webauthn-update"
	username := "webauthn-update@example.test"
	deps := core.AuthDeps{}
	original := authorityWebAuthnCredential("credential-a", "Security key", 10)
	updated := authorityWebAuthnCredential("credential-a", "Renamed key", 11)

	seedAuthorityWebAuthnCredential(t, deps, backendName, username, original)

	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{AuthDeps: deps})
	input := authorityMFATestInput(backendName, username)
	input.OldCredential = original
	input.NewCredential = updated

	if _, err := service.UpdateWebAuthnCredential(context.Background(), input); err != nil {
		t.Fatalf("UpdateWebAuthnCredential() error = %v", err)
	}

	credentials := readAuthorityWebAuthnCredentials(t, deps, backendName, username)
	if len(credentials) != 1 || credentials[0].Name != "Renamed key" || credentials[0].Authenticator.SignCount != 11 {
		t.Fatalf("credentials after update = %#v, want renamed sign-count 11 credential", credentials)
	}
}

func assertSameStringSet(t *testing.T, got []string, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("string set = %#v, want %#v", got, want)
	}

	index := make(map[string]struct{}, len(got))
	for _, value := range got {
		index[value] = struct{}{}
	}

	for _, value := range want {
		if _, ok := index[value]; !ok {
			t.Fatalf("string set = %#v, missing %q", got, value)
		}
	}
}

func TestBackendManagerIdentityServiceWebAuthnUpdateRejectsStalePersistentState(t *testing.T) {
	backendName := "authority-webauthn-stale"
	username := "webauthn-stale@example.test"
	deps := core.AuthDeps{}
	persistent := authorityWebAuthnCredential("credential-a", "Security key", 10)
	staleOld := authorityWebAuthnCredential("credential-a", "Security key", 3)
	newCredential := authorityWebAuthnCredential("credential-a", "Security key", 11)

	seedAuthorityWebAuthnCredential(t, deps, backendName, username, persistent)

	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{AuthDeps: deps})
	input := authorityMFATestInput(backendName, username)
	input.OldCredential = staleOld
	input.NewCredential = newCredential

	if _, err := service.UpdateWebAuthnCredential(context.Background(), input); err == nil {
		t.Fatal("UpdateWebAuthnCredential() error = nil, want stale-state rejection")
	} else if !errors.Is(err, ErrWebAuthnCredentialStateMismatch) {
		t.Fatalf("UpdateWebAuthnCredential() error = %v, want ErrWebAuthnCredentialStateMismatch", err)
	}

	credentials := readAuthorityWebAuthnCredentials(t, deps, backendName, username)
	if len(credentials) != 1 || credentials[0].Authenticator.SignCount != 10 {
		t.Fatalf("credentials after stale update = %#v, want unchanged sign-count 10 credential", credentials)
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

func seedAuthorityWebAuthnCredential(
	t *testing.T,
	deps core.AuthDeps,
	backendName string,
	username string,
	credential *mfa.PersistentCredential,
) {
	t.Helper()

	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetUsername(username)

	manager := core.NewTestBackendManager(backendName, deps)
	if err := manager.SaveWebAuthnCredential(auth, credential); err != nil {
		t.Fatalf("SaveWebAuthnCredential() error = %v", err)
	}
}

func readAuthorityWebAuthnCredentials(
	t *testing.T,
	deps core.AuthDeps,
	backendName string,
	username string,
) []mfa.PersistentCredential {
	t.Helper()

	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetUsername(username)

	manager := core.NewTestBackendManager(backendName, deps)

	credentials, err := manager.GetWebAuthnCredentials(auth)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials() error = %v", err)
	}

	return credentials
}

func authorityWebAuthnCredential(id string, name string, signCount uint32) *mfa.PersistentCredential {
	return &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte(id),
			Authenticator: webauthn.Authenticator{
				SignCount: signCount,
			},
		},
		Name: name,
	}
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
