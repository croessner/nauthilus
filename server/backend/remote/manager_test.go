// Package remote tests edge-side remote backend behavior.
package remote

import (
	"bytes"
	"context"
	stderrors "errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/v3/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/v3/server/grpcapi/identity/v1"
	authorityclient "github.com/croessner/nauthilus/v3/server/grpcclient/authority"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/go-redis/redismock/v9"
	"github.com/go-webauthn/webauthn/webauthn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	remoteTestAuthorityName        = "edge"
	remoteTestBackendName          = "default"
	remoteTestAccountField         = "mail"
	remoteTestAuthorityBackendType = "ldap"
	remoteTestAuthorityBackendName = "primary"
	remoteTestBackendRefToken      = "opaque-ref"
	remoteTestBufconnRefToken      = "bufconn-ref"
	remoteTestUsername             = "alice"
	remoteTestAccount              = "alice@example.test"
	remoteTestUniqueUserID         = "alice-uid"
	remoteTestDisplayName          = "Alice Example"
	remoteTestAccountA             = "a@example.test"
	remoteTestAccountB             = "b@example.test"
	remoteTestDepartmentNumber     = "departmentNumber"
	remoteTestEmployeeNumber       = "employeeNumber"
	remoteTestSAMLGroupDN          = "cn=developers,ou=groups,dc=example,dc=test"
	remoteTestTOTPCode             = "123456"
	remoteTestTOTPSetupSecret      = "JBSWY3DPEHPK3PXP"
	remoteTestTOTPSetupURL         = "otpauth://totp/Nauthilus:alice?secret=JBSWY3DPEHPK3PXP"
	remoteTestTOTPPendingID        = "pending-registration-a"
	remoteTestBeginTOTPKey         = "begin-key"
	remoteTestFinishTOTPKey        = "finish-key"
	remoteTestDeleteTOTPKey        = "delete-totp-key"
	remoteTestRecoveryCodeA        = "recovery-a"
	remoteTestRecoveryCodeB        = "recovery-b"
	remoteTestGenerateRecoveryKey  = "generate-recovery-key"
	remoteTestUseRecoveryKey       = "use-recovery-key"
	remoteTestDeleteRecoveryKey    = "delete-recovery-key"
	remoteTestWebAuthnSaveKey      = "save-webauthn:alice:remote-guid"
	remoteTestWebAuthnUpdateKey    = "update-webauthn:alice:remote-guid:63726564656e7469616c2d61:3:9"
	remoteTestWebAuthnDeleteKey    = "delete-webauthn:alice:remote-guid"
)

func TestMain(m *testing.M) {
	core.InitPassDBResultPool()

	code := m.Run()
	_ = CloseConnectionManagers()

	os.Exit(code)
}

func TestManagerPassDBAuthenticatesAndBindsBackendRef(t *testing.T) {
	client := &fakeAuthorityClient{
		authResponse: &authv1.AuthResponse{
			Ok:              true,
			Decision:        authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField:    remoteTestAccountField,
			TotpSecretField: "totp",
			Backend:         uint32(definitions.BackendLDAP),
			Attributes: map[string]*commonv1.AttributeValues{
				remoteTestAccountField: {Values: []string{remoteTestAccount}},
			},
			BackendRef: &commonv1.BackendRef{
				Type:        remoteTestAuthorityBackendType,
				Name:        remoteTestAuthorityBackendName,
				Protocol:    "imap",
				Authority:   remoteTestAuthorityName,
				OpaqueToken: remoteTestBackendRefToken,
			},
		},
	}
	manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("auth"), client)
	auth := newRemoteAuthState(t, false)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if !result.Authenticated || !result.UserFound {
		t.Fatalf("PassDB() result authenticated=%v user_found=%v, want both true", result.Authenticated, result.UserFound)
	}

	if result.Backend != definitions.BackendRemote || result.BackendName != remoteTestBackendName {
		t.Fatalf("backend = %s/%q, want remote/default", result.Backend.String(), result.BackendName)
	}

	if got := result.BackendRef.OpaqueToken; got != remoteTestBackendRefToken {
		t.Fatalf("backend ref token = %q, want %s", got, remoteTestBackendRefToken)
	}

	if client.authRequests != 1 || client.lookupRequests != 0 {
		t.Fatalf("auth calls=%d lookup calls=%d, want 1/0", client.authRequests, client.lookupRequests)
	}
}

func TestManagerPassDBUsesLookupForNoAuth(t *testing.T) {
	client := &fakeAuthorityClient{
		lookupResponse: &authv1.AuthResponse{
			Ok:           true,
			Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField: remoteTestAccountField,
			Attributes: map[string]*commonv1.AttributeValues{
				remoteTestAccountField: {Values: []string{"lookup@example.test"}},
			},
		},
	}
	manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("lookup_identity"), client)
	auth := newRemoteAuthState(t, true)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.Authenticated || !result.UserFound {
		t.Fatalf("lookup result authenticated=%v user_found=%v, want false/true", result.Authenticated, result.UserFound)
	}

	if client.authRequests != 0 || client.lookupRequests != 1 {
		t.Fatalf("auth calls=%d lookup calls=%d, want 0/1", client.authRequests, client.lookupRequests)
	}
}

func TestManagerPassDBResolvesOIDCRequestedAttributesThroughAuthority(t *testing.T) {
	client := newResolveUserAuthorityClient(
		definitions.ProtoOIDC,
		map[string]*commonv1.AttributeValues{
			remoteTestAccountField:     {Values: []string{remoteTestAccount}},
			remoteTestDepartmentNumber: {Values: []string{"42"}},
		},
		[]string{"developers"},
		nil,
	)
	manager := newResolveUserManager(client)
	auth := newRemoteAuthState(t, true)
	auth.Request.Protocol.Set(definitions.ProtoOIDC)
	auth.Runtime.IdentityAttributeRequest = &core.IdentityAttributeRequest{
		Names:                   []string{remoteTestDepartmentNumber, remoteTestAccountField},
		IncludeStandardIdentity: true,
		IncludeGroups:           true,
		ReportMissing:           true,
	}

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	assertResolveOnly(t, client)

	request := client.resolveUserRequest
	if request == nil {
		t.Fatal("ResolveUser request was not captured")
	}

	attributes := request.GetAttributes()
	if attributes == nil {
		t.Fatal("ResolveUser attributes = nil, want requested claim attributes")
	}

	if got := attributes.GetNames(); !slices.Equal(got, []string{remoteTestDepartmentNumber, remoteTestAccountField}) {
		t.Fatalf("requested attribute names = %#v, want departmentNumber/mail", got)
	}

	if !attributes.GetIncludeStandardIdentity() || !attributes.GetIncludeGroups() || attributes.GetIncludeGroupDns() {
		t.Fatalf("requested identity flags = standard:%v groups:%v group_dns:%v, want true/true/false",
			attributes.GetIncludeStandardIdentity(),
			attributes.GetIncludeGroups(),
			attributes.GetIncludeGroupDns(),
		)
	}

	if !attributes.GetReportMissing() {
		t.Fatal("ReportMissing = false, want true for edge claim materialization")
	}

	if _, ok := result.Attributes["unrequestedRaw"]; ok {
		t.Fatal("remote result exposed unrequestedRaw")
	}

	if got := result.Attributes[remoteTestAccountField]; !slices.Equal(anyStrings(got), []string{remoteTestAccount}) {
		t.Fatalf("mail attribute = %#v, want alice@example.test", got)
	}
}

func TestManagerPassDBResolvesSAMLRequestedAttributesThroughAuthority(t *testing.T) {
	client := newResolveUserAuthorityClient(
		definitions.ProtoSAML,
		map[string]*commonv1.AttributeValues{
			remoteTestAccountField:   {Values: []string{remoteTestAccount}},
			remoteTestEmployeeNumber: {Values: []string{"1234"}},
		},
		nil,
		[]string{remoteTestSAMLGroupDN},
	)
	manager := newResolveUserManager(client)
	auth := newRemoteAuthState(t, true)
	auth.Request.Protocol.Set(definitions.ProtoSAML)
	auth.Request.SAMLEntityID = "https://sp.example.test/metadata"
	auth.Runtime.IdentityAttributeRequest = &core.IdentityAttributeRequest{
		Names:                          []string{remoteTestEmployeeNumber, remoteTestAccountField},
		IncludeStandardIdentity:        true,
		IncludeGroupDistinguishedNames: true,
		ReportMissing:                  true,
	}

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	assertResolveOnly(t, client)

	attributes := client.resolveUserRequest.GetAttributes()
	if got := attributes.GetNames(); !slices.Equal(got, []string{remoteTestEmployeeNumber, remoteTestAccountField}) {
		t.Fatalf("requested SAML attribute names = %#v, want employeeNumber/mail", got)
	}

	if attributes.GetIncludeGroups() || !attributes.GetIncludeGroupDns() {
		t.Fatalf("requested SAML group flags = groups:%v group_dns:%v, want false/true",
			attributes.GetIncludeGroups(),
			attributes.GetIncludeGroupDns(),
		)
	}

	if got := result.GroupDistinguishedNames; !slices.Equal(got, []string{remoteTestSAMLGroupDN}) {
		t.Fatalf("group DNs = %#v, want first-class SAML group DNs", got)
	}
}

func TestManagerAccountDBUsesListAccounts(t *testing.T) {
	client := &fakeAuthorityClient{
		listResponse: &authv1.ListAccountsResponse{Accounts: []string{remoteTestAccountA, remoteTestAccountB}},
	}
	manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("list_accounts"), client)
	auth := newRemoteAuthState(t, false)

	accounts, err := manager.AccountDB(auth)
	if err != nil {
		t.Fatalf("AccountDB() error = %v", err)
	}

	if len(accounts) != 2 || accounts[0] != remoteTestAccountA || accounts[1] != remoteTestAccountB {
		t.Fatalf("AccountDB() = %#v, want two remote accounts", accounts)
	}
}

func TestManagerFailsClosedForDeniedOperationsAndTransientErrors(t *testing.T) {
	t.Run("operation denied", func(t *testing.T) {
		manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("lookup_identity"), &fakeAuthorityClient{})

		_, err := manager.PassDB(newRemoteAuthState(t, false))
		if err == nil || !stderrors.Is(err, ErrRemoteOperationDenied) {
			t.Fatalf("PassDB() error = %v, want ErrRemoteOperationDenied", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("auth"), &fakeAuthorityClient{err: context.DeadlineExceeded})

		_, err := manager.PassDB(newRemoteAuthState(t, false))
		if err == nil || !stderrors.Is(err, ErrRemoteAuthorityUnavailable) {
			t.Fatalf("PassDB() error = %v, want ErrRemoteAuthorityUnavailable", err)
		}
	})

	t.Run("domain tempfail", func(t *testing.T) {
		manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("auth"), &fakeAuthorityClient{
			authResponse: &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_TEMPFAIL, Error: "temporary"},
		})

		_, err := manager.PassDB(newRemoteAuthState(t, false))
		if err == nil || !stderrors.Is(err, ErrRemoteAuthorityUnavailable) {
			t.Fatalf("PassDB() error = %v, want ErrRemoteAuthorityUnavailable", err)
		}
	})
}

func TestManagerRemoteTOTPOperationsUseAuthority(t *testing.T) {
	client := &fakeAuthorityClient{
		beginTOTPResponse: &identityv1.BeginTOTPRegistrationResponse{
			Status:                okRemoteOperationStatus(),
			PendingRegistrationId: remoteTestTOTPPendingID,
			TotpSecret:            remoteTestTOTPSetupSecret,
			OtpauthUrl:            remoteTestTOTPSetupURL,
			Backend:               remoteBackendRefProto(),
		},
		verifyTOTPResponse: &identityv1.VerifyTOTPResponse{
			Status:  okRemoteOperationStatus(),
			Valid:   true,
			Backend: remoteBackendRefProto(),
		},
		writeResponse: &identityv1.MFAWriteResponse{
			Status:  okRemoteOperationStatus(),
			Changed: true,
			Mfa: &identityv1.MFAState{
				HasTotp:           true,
				RecoveryCodeCount: 2,
			},
			Backend: remoteBackendRefProto(),
		},
	}
	manager := NewManagerForTest(
		remoteTestBackendName,
		remoteTestAuthorityName,
		remoteBackendConfig(
			config.RemoteBackendOperationMFARead,
			config.RemoteBackendOperationMFAVerify,
			config.RemoteBackendOperationMFAWrite,
		),
		client,
	)
	auth := newRemoteAuthStateWithRef(t)

	registration := assertBeginTOTPRegistration(t, manager, auth, client)
	assertFinishTOTPRegistration(t, manager, auth, client, registration)
	assertRemoteTOTPVerification(t, manager, auth, client)
	assertRemoteTOTPDeletion(t, manager, auth, client)
}

func TestManagerRemoteRecoveryOperationsUseAuthority(t *testing.T) {
	client := &fakeAuthorityClient{
		generateRecoveryResponse: &identityv1.GenerateRecoveryCodesResponse{
			Status:            okRemoteOperationStatus(),
			Codes:             []string{remoteTestRecoveryCodeA, remoteTestRecoveryCodeB},
			RecoveryCodeCount: 2,
			Backend:           remoteBackendRefProto(),
		},
		useRecoveryResponse: &identityv1.UseRecoveryCodeResponse{
			Status:                     okRemoteOperationStatus(),
			Valid:                      true,
			RemainingRecoveryCodeCount: 1,
			Backend:                    remoteBackendRefProto(),
		},
		writeResponse: &identityv1.MFAWriteResponse{
			Status:  okRemoteOperationStatus(),
			Changed: true,
			Mfa: &identityv1.MFAState{
				RecoveryCodeCount: 0,
			},
			Backend: remoteBackendRefProto(),
		},
	}
	manager := NewManagerForTest(
		remoteTestBackendName,
		remoteTestAuthorityName,
		remoteBackendConfig(
			config.RemoteBackendOperationMFAVerify,
			config.RemoteBackendOperationMFAWrite,
		),
		client,
	)
	auth := newRemoteAuthStateWithRef(t)

	assertRemoteRecoveryGeneration(t, manager, auth, client)
	assertRemoteRecoveryConsumption(t, manager, auth, client)
	assertRemoteRecoveryDeletion(t, manager, auth, client)
}

func TestManagerRemoteWebAuthnMutationsUseAuthorityAndInvalidateCache(t *testing.T) {
	client := &fakeAuthorityClient{
		writeResponse: &identityv1.MFAWriteResponse{
			Status:  okRemoteOperationStatus(),
			Changed: true,
			Backend: remoteBackendRefProto(),
		},
	}
	manager := NewManagerForTest(
		remoteTestBackendName,
		remoteTestAuthorityName,
		remoteBackendConfig(config.RemoteBackendOperationWebAuthnWrite),
		client,
	)
	auth, mock := newRemoteAuthStateWithWebAuthnCacheMock(t)
	oldCredential := remoteWebAuthnCredential("credential-a", "Security key", 3)
	newCredential := remoteWebAuthnCredential("credential-a", "Renamed key", 9)

	assertRemoteWebAuthnSave(t, manager, auth, client, mock, oldCredential)
	assertRemoteWebAuthnUpdate(t, manager, auth, client, mock, oldCredential, newCredential)
	assertRemoteWebAuthnDelete(t, manager, auth, client, mock, newCredential)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestManagerWebAuthnUpdateIdempotencyKeyIncludesCredentialTransition(t *testing.T) {
	client := &fakeAuthorityClient{
		writeResponse: &identityv1.MFAWriteResponse{
			Status:  okRemoteOperationStatus(),
			Changed: true,
			Backend: remoteBackendRefProto(),
		},
	}
	manager := NewManagerForTest(
		remoteTestBackendName,
		remoteTestAuthorityName,
		remoteBackendConfig(config.RemoteBackendOperationWebAuthnWrite),
		client,
	)
	auth, mock := newRemoteAuthStateWithWebAuthnCacheMock(t)
	firstOld := remoteWebAuthnCredential("credential-a", "Security key", 3)
	firstNew := remoteWebAuthnCredential("credential-a", "Security key", 9)
	secondOld := remoteWebAuthnCredential("credential-a", "Security key", 9)
	secondNew := remoteWebAuthnCredential("credential-a", "Security key", 10)

	mock.ExpectDel("nt:webauthn:user:alice").SetVal(1)

	if err := manager.UpdateWebAuthnCredential(auth, firstOld, firstNew); err != nil {
		t.Fatalf("first UpdateWebAuthnCredential() error = %v", err)
	}

	firstKey := client.updateWebAuthnRequest.GetIdempotencyKey()

	mock.ExpectDel("nt:webauthn:user:alice").SetVal(1)

	if err := manager.UpdateWebAuthnCredential(auth, secondOld, secondNew); err != nil {
		t.Fatalf("second UpdateWebAuthnCredential() error = %v", err)
	}

	secondKey := client.updateWebAuthnRequest.GetIdempotencyKey()

	if firstKey == secondKey {
		t.Fatalf("WebAuthn update idempotency keys must differ across sign-count transitions: %q", firstKey)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func assertRemoteWebAuthnSave(
	t *testing.T,
	manager *Manager,
	auth *core.AuthState,
	client *fakeAuthorityClient,
	mock redismock.ClientMock,
	credential *mfa.PersistentCredential,
) {
	t.Helper()

	mock.ExpectDel("nt:webauthn:user:alice").SetVal(1)

	if err := manager.SaveWebAuthnCredential(auth, credential); err != nil {
		t.Fatalf("SaveWebAuthnCredential() error = %v", err)
	}

	if client.saveWebAuthnRequests != 1 {
		t.Fatalf("save WebAuthn calls = %d, want 1", client.saveWebAuthnRequests)
	}

	assertRemoteCredential(t, client.saveWebAuthnRequest.GetCredential(), credential)
	assertRemoteIdempotencyKey(t, client.saveWebAuthnRequest.GetIdempotencyKey(), remoteTestWebAuthnSaveKey)
}

func assertRemoteWebAuthnUpdate(
	t *testing.T,
	manager *Manager,
	auth *core.AuthState,
	client *fakeAuthorityClient,
	mock redismock.ClientMock,
	oldCredential *mfa.PersistentCredential,
	newCredential *mfa.PersistentCredential,
) {
	t.Helper()

	mock.ExpectDel("nt:webauthn:user:alice").SetVal(1)

	if err := manager.UpdateWebAuthnCredential(auth, oldCredential, newCredential); err != nil {
		t.Fatalf("UpdateWebAuthnCredential() error = %v", err)
	}

	if client.updateWebAuthnRequests != 1 {
		t.Fatalf("update WebAuthn calls = %d, want 1", client.updateWebAuthnRequests)
	}

	assertRemoteCredential(t, client.updateWebAuthnRequest.GetOldCredential(), oldCredential)
	assertRemoteCredential(t, client.updateWebAuthnRequest.GetNewCredential(), newCredential)
	assertRemoteIdempotencyKey(t, client.updateWebAuthnRequest.GetIdempotencyKey(), remoteTestWebAuthnUpdateKey)
}

func assertRemoteWebAuthnDelete(
	t *testing.T,
	manager *Manager,
	auth *core.AuthState,
	client *fakeAuthorityClient,
	mock redismock.ClientMock,
	credential *mfa.PersistentCredential,
) {
	t.Helper()

	mock.ExpectDel("nt:webauthn:user:alice").SetVal(1)

	if err := manager.DeleteWebAuthnCredential(auth, credential); err != nil {
		t.Fatalf("DeleteWebAuthnCredential() error = %v", err)
	}

	if client.deleteWebAuthnRequests != 1 {
		t.Fatalf("delete WebAuthn calls = %d, want 1", client.deleteWebAuthnRequests)
	}

	if !bytes.Equal(client.deleteWebAuthnRequest.GetCredentialId(), credential.ID) {
		t.Fatalf("delete credential ID = %q, want %q", client.deleteWebAuthnRequest.GetCredentialId(), credential.ID)
	}

	assertRemoteIdempotencyKey(t, client.deleteWebAuthnRequest.GetIdempotencyKey(), remoteTestWebAuthnDeleteKey)
}

func TestManagerRemoteWebAuthnUpdateFailurePurgesCache(t *testing.T) {
	client := &fakeAuthorityClient{
		err: status.Error(codes.FailedPrecondition, "stale WebAuthn credential"),
	}
	manager := NewManagerForTest(
		remoteTestBackendName,
		remoteTestAuthorityName,
		remoteBackendConfig(config.RemoteBackendOperationWebAuthnWrite),
		client,
	)
	auth, mock := newRemoteAuthStateWithWebAuthnCacheMock(t)

	mock.ExpectDel("nt:webauthn:user:alice").SetVal(1)

	err := manager.UpdateWebAuthnCredential(
		auth,
		remoteWebAuthnCredential("credential-a", "Security key", 3),
		remoteWebAuthnCredential("credential-a", "Security key", 4),
	)
	if err == nil {
		t.Fatal("UpdateWebAuthnCredential() error = nil, want fail-closed authority error")
	}

	if client.updateWebAuthnRequests != 1 {
		t.Fatalf("update WebAuthn calls = %d, want 1", client.updateWebAuthnRequests)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func assertBeginTOTPRegistration(t *testing.T, manager *Manager, auth *core.AuthState, client *fakeAuthorityClient) core.TOTPRegistration {
	t.Helper()

	registration, err := manager.BeginTOTPRegistration(auth, remoteTestBeginTOTPKey)
	if err != nil {
		t.Fatalf("BeginTOTPRegistration() error = %v", err)
	}

	if registration.PendingRegistrationID != remoteTestTOTPPendingID || registration.Secret == "" || registration.OTPAuthURL == "" {
		t.Fatalf("registration = %#v, want setup material from authority", registration)
	}

	if got := client.beginTOTPRequest.GetIdempotencyKey(); got != remoteTestBeginTOTPKey {
		t.Fatalf("begin idempotency key = %q, want %s", got, remoteTestBeginTOTPKey)
	}

	return registration
}

func assertFinishTOTPRegistration(
	t *testing.T,
	manager *Manager,
	auth *core.AuthState,
	client *fakeAuthorityClient,
	registration core.TOTPRegistration,
) {
	t.Helper()

	if err := manager.FinishTOTPRegistration(auth, registration.PendingRegistrationID, remoteTestTOTPCode, remoteTestFinishTOTPKey); err != nil {
		t.Fatalf("FinishTOTPRegistration() error = %v", err)
	}

	if got := client.finishTOTPRequest.GetPendingRegistrationId(); got != registration.PendingRegistrationID {
		t.Fatalf("finish pending id = %q, want %q", got, registration.PendingRegistrationID)
	}

	if got := client.finishTOTPRequest.GetIdempotencyKey(); got != remoteTestFinishTOTPKey {
		t.Fatalf("finish idempotency key = %q, want %s", got, remoteTestFinishTOTPKey)
	}
}

func assertRemoteTOTPVerification(t *testing.T, manager *Manager, auth *core.AuthState, client *fakeAuthorityClient) {
	t.Helper()

	valid, err := manager.VerifyTOTP(auth, remoteTestTOTPCode)
	if err != nil {
		t.Fatalf("VerifyTOTP() error = %v", err)
	}

	if !valid {
		t.Fatal("VerifyTOTP() valid = false, want true")
	}

	if got := client.verifyTOTPRequest.GetCode(); got != remoteTestTOTPCode {
		t.Fatalf("verify code = %q, want submitted code", got)
	}
}

func assertRemoteTOTPDeletion(t *testing.T, manager *Manager, auth *core.AuthState, client *fakeAuthorityClient) {
	t.Helper()

	if err := manager.DeleteTOTP(auth, remoteTestDeleteTOTPKey); err != nil {
		t.Fatalf("DeleteTOTP() error = %v", err)
	}

	if got := client.deleteTOTPRequest.GetIdempotencyKey(); got != remoteTestDeleteTOTPKey {
		t.Fatalf("delete TOTP idempotency key = %q, want %s", got, remoteTestDeleteTOTPKey)
	}
}

func assertRemoteRecoveryGeneration(t *testing.T, manager *Manager, auth *core.AuthState, client *fakeAuthorityClient) {
	t.Helper()

	codes, err := manager.GenerateRecoveryCodes(auth, 2, remoteTestGenerateRecoveryKey)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes() error = %v", err)
	}

	if len(codes) != 2 || codes[0] != remoteTestRecoveryCodeA {
		t.Fatalf("GenerateRecoveryCodes() = %#v, want authority codes", codes)
	}

	if got := client.generateRecoveryRequest.GetIdempotencyKey(); got != remoteTestGenerateRecoveryKey {
		t.Fatalf("generate recovery idempotency key = %q, want %s", got, remoteTestGenerateRecoveryKey)
	}
}

func assertRemoteRecoveryConsumption(t *testing.T, manager *Manager, auth *core.AuthState, client *fakeAuthorityClient) {
	t.Helper()

	valid, err := manager.UseRecoveryCode(auth, remoteTestRecoveryCodeA, remoteTestUseRecoveryKey)
	if err != nil {
		t.Fatalf("UseRecoveryCode() error = %v", err)
	}

	if !valid {
		t.Fatal("UseRecoveryCode() valid = false, want true")
	}

	if got := client.useRecoveryRequest.GetIdempotencyKey(); got != remoteTestUseRecoveryKey {
		t.Fatalf("use recovery idempotency key = %q, want %s", got, remoteTestUseRecoveryKey)
	}
}

func assertRemoteRecoveryDeletion(t *testing.T, manager *Manager, auth *core.AuthState, client *fakeAuthorityClient) {
	t.Helper()

	if err := manager.DeleteRecoveryCodes(auth, remoteTestDeleteRecoveryKey); err != nil {
		t.Fatalf("DeleteRecoveryCodes() error = %v", err)
	}

	if got := client.deleteRecoveryRequest.GetIdempotencyKey(); got != remoteTestDeleteRecoveryKey {
		t.Fatalf("delete recovery idempotency key = %q, want %s", got, remoteTestDeleteRecoveryKey)
	}
}

func assertRemoteCredential(t *testing.T, got *identityv1.WebAuthnCredential, want *mfa.PersistentCredential) {
	t.Helper()

	if got == nil {
		t.Fatal("credential = nil")
	}

	if !bytes.Equal(got.GetCredentialId(), want.ID) {
		t.Fatalf("credential ID = %q, want %q", got.GetCredentialId(), want.ID)
	}

	if got.GetName() != want.Name {
		t.Fatalf("credential name = %q, want %q", got.GetName(), want.Name)
	}

	if got.GetSignCount() != want.Authenticator.SignCount {
		t.Fatalf("sign count = %d, want %d", got.GetSignCount(), want.Authenticator.SignCount)
	}
}

func assertRemoteIdempotencyKey(t *testing.T, got string, want string) {
	t.Helper()

	if got != want {
		t.Fatalf("idempotency key = %q, want %q", got, want)
	}
}

func TestManagerRemoteMFAOperationsFailClosed(t *testing.T) {
	auth := newRemoteAuthStateWithRef(t)

	t.Run("authority unavailable during TOTP verify", func(t *testing.T) {
		manager := NewManagerForTest(
			remoteTestBackendName,
			remoteTestAuthorityName,
			remoteBackendConfig(config.RemoteBackendOperationMFAVerify),
			&fakeAuthorityClient{err: status.Error(codes.Unavailable, "authority down")},
		)

		_, err := manager.VerifyTOTP(auth, remoteTestTOTPCode)
		if err == nil || !stderrors.Is(err, ErrRemoteAuthorityUnavailable) {
			t.Fatalf("VerifyTOTP() error = %v, want ErrRemoteAuthorityUnavailable", err)
		}
	})

	t.Run("authority unavailable during recovery consumption", func(t *testing.T) {
		manager := NewManagerForTest(
			remoteTestBackendName,
			remoteTestAuthorityName,
			remoteBackendConfig(config.RemoteBackendOperationMFAVerify, config.RemoteBackendOperationMFAWrite),
			&fakeAuthorityClient{err: context.DeadlineExceeded},
		)

		_, err := manager.UseRecoveryCode(auth, remoteTestRecoveryCodeA, "use-key")
		if err == nil || !stderrors.Is(err, ErrRemoteAuthorityUnavailable) {
			t.Fatalf("UseRecoveryCode() error = %v, want ErrRemoteAuthorityUnavailable", err)
		}
	})

	t.Run("missing backend reference", func(t *testing.T) {
		manager := NewManagerForTest(
			remoteTestBackendName,
			remoteTestAuthorityName,
			remoteBackendConfig(config.RemoteBackendOperationMFAVerify),
			&fakeAuthorityClient{},
		)

		_, err := manager.VerifyTOTP(newRemoteAuthState(t, false), remoteTestTOTPCode)
		if err == nil || !stderrors.Is(err, ErrRemoteOperationDenied) {
			t.Fatalf("VerifyTOTP() error = %v, want ErrRemoteOperationDenied", err)
		}
	})

	t.Run("local operation guard", func(t *testing.T) {
		manager := NewManagerForTest(
			remoteTestBackendName,
			remoteTestAuthorityName,
			remoteBackendConfig(config.RemoteBackendOperationMFARead),
			&fakeAuthorityClient{},
		)

		_, err := manager.VerifyTOTP(auth, remoteTestTOTPCode)
		if err == nil || !stderrors.Is(err, ErrRemoteOperationDenied) {
			t.Fatalf("VerifyTOTP() error = %v, want ErrRemoteOperationDenied", err)
		}
	})
}

func TestCoreRegistryBuildsRemoteBackendManager(t *testing.T) {
	cfg := &config.FileSettings{
		Runtime: &config.RuntimeSection{
			Clients: config.RuntimeClientsSection{
				GRPC: config.RuntimeGRPCClientsSection{
					NauthilusAuthorities: map[string]*config.NauthilusAuthorityClientSection{
						remoteTestAuthorityName: {
							Address: "127.0.0.1:9444",
							CallerAuth: config.AuthorityCallerAuthSection{
								OIDCBearer: config.AuthorityOIDCBearerSection{
									Enabled:                 true,
									Mode:                    config.AuthorityClientCredentialsMode,
									TokenEndpoint:           "https://authority.example.test/oidc/token",
									ClientID:                "edge-client",
									ClientSecret:            secret.New("edge-secret"),
									TokenEndpointAuthMethod: config.AuthorityClientSecretPostAuth,
								},
							},
						},
					},
				},
			},
		},
		Auth: &config.AuthSection{
			Backends: config.AuthBackendsSection{
				Remote: map[string]*config.RemoteBackendSection{
					remoteTestBackendName: remoteBackendConfig("auth"),
				},
			},
		},
	}
	db, _ := redismock.NewClientMock()
	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
		Redis:  rediscli.NewTestClient(db),
	}).(*core.AuthState)

	manager := auth.GetBackendManager(definitions.BackendRemote, remoteTestBackendName)
	if manager == nil {
		t.Fatal("GetBackendManager(remote) = nil, want registered manager")
	}
}

func newRemoteAuthState(t *testing.T, noAuth bool) *core.AuthState {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/auth", nil)
	db, _ := redismock.NewClientMock()
	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{Logger: slog.Default(), Redis: rediscli.NewTestClient(db)}).(*core.AuthState)
	auth.Request.HTTPClientRequest = request
	auth.Request.Username = "alice"
	auth.Request.Password = secret.New("password")
	auth.Request.ClientIP = "192.0.2.20"
	auth.Request.XClientPort = "12345"
	auth.Request.ClientHost = "client.example.test"
	auth.Request.XClientID = "client-id"
	auth.Request.ExternalSessionID = "external-session"
	auth.Request.UserAgent = "remote-test"
	auth.Request.XLocalIP = "192.0.2.10"
	auth.Request.XPort = "993"
	auth.Request.Protocol = &config.Protocol{}
	auth.Request.Protocol.Set("imap")
	auth.Request.Method = "plain"
	auth.Request.OIDCCID = "oidc-client"
	auth.Request.AuthLoginAttempt = 2
	auth.Request.NoAuth = noAuth
	auth.Runtime.GUID = "remote-guid"
	auth.Runtime.StartTime = time.Now()

	return auth
}

func newRemoteAuthStateWithRef(t *testing.T) *core.AuthState {
	t.Helper()

	auth := newRemoteAuthState(t, false)
	auth.Runtime.RemoteBackendRef = core.RemoteBackendRef{
		Type:        remoteTestAuthorityBackendType,
		Name:        remoteTestAuthorityBackendName,
		Protocol:    "imap",
		Authority:   remoteTestAuthorityName,
		OpaqueToken: remoteTestBackendRefToken,
	}

	return auth
}

func newRemoteAuthStateWithWebAuthnCacheMock(t *testing.T) (*core.AuthState, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "nt:",
			},
		},
	}
	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
		Redis:  rediscli.NewTestClient(db),
	}).(*core.AuthState)
	auth.Request.Username = "alice"
	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Runtime.GUID = "remote-guid"
	auth.Runtime.RemoteBackendRef = core.RemoteBackendRef{
		Type:        remoteTestAuthorityBackendType,
		Name:        remoteTestAuthorityBackendName,
		Protocol:    "imap",
		Authority:   remoteTestAuthorityName,
		OpaqueToken: remoteTestBackendRefToken,
	}

	return auth, mock
}

func remoteWebAuthnCredential(id string, name string, signCount uint32) *mfa.PersistentCredential {
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

func remoteBackendRefProto() *commonv1.BackendRef {
	return &commonv1.BackendRef{
		Type:        remoteTestAuthorityBackendType,
		Name:        remoteTestAuthorityBackendName,
		Protocol:    "imap",
		Authority:   remoteTestAuthorityName,
		OpaqueToken: remoteTestBackendRefToken,
	}
}

func newResolveUserAuthorityClient(
	protocol string,
	attributes map[string]*commonv1.AttributeValues,
	groups []string,
	groupDistinguishedNames []string,
) *fakeAuthorityClient {
	return &fakeAuthorityClient{
		resolveResponse: &identityv1.UserSnapshotResponse{
			Status: okRemoteOperationStatus(),
			User: &identityv1.UserSnapshot{
				Username:     remoteTestUsername,
				Account:      remoteTestAccount,
				UniqueUserId: remoteTestUniqueUserID,
				DisplayName:  remoteTestDisplayName,
				Attributes:   attributes,
				Groups:       groups,
				GroupDns:     groupDistinguishedNames,
				Backend: &commonv1.BackendRef{
					Type:        remoteTestAuthorityBackendType,
					Name:        remoteTestAuthorityBackendName,
					Protocol:    protocol,
					Authority:   remoteTestAuthorityName,
					OpaqueToken: remoteTestBackendRefToken,
				},
			},
		},
	}
}

func newResolveUserManager(client authorityclient.Client) *Manager {
	return NewManagerForTest(
		remoteTestBackendName,
		remoteTestAuthorityName,
		remoteBackendConfig(
			config.RemoteBackendOperationLookupIdentity,
			config.RemoteBackendOperationAttributeRead,
		),
		client,
	)
}

func assertResolveOnly(t *testing.T, client *fakeAuthorityClient) {
	t.Helper()

	if client.resolveRequests != 1 || client.lookupRequests != 0 {
		t.Fatalf("resolve calls=%d lookup calls=%d, want 1/0", client.resolveRequests, client.lookupRequests)
	}
}

func okRemoteOperationStatus() *commonv1.OperationStatus {
	return &commonv1.OperationStatus{
		Result: commonv1.OperationResult_OPERATION_RESULT_OK,
	}
}

func anyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}

	return result
}

func remoteBackendConfig(operations ...string) *config.RemoteBackendSection {
	return &config.RemoteBackendSection{
		Authority:         remoteTestAuthorityName,
		Mode:              "nauthilus",
		AllowedOperations: operations,
		Timeout:           5 * time.Second,
	}
}

type fakeAuthorityClient struct {
	authResponse             *authv1.AuthResponse
	lookupResponse           *authv1.AuthResponse
	listResponse             *authv1.ListAccountsResponse
	resolveResponse          *identityv1.UserSnapshotResponse
	mfaResponse              *identityv1.MFAStateResponse
	beginTOTPResponse        *identityv1.BeginTOTPRegistrationResponse
	writeResponse            *identityv1.MFAWriteResponse
	verifyTOTPResponse       *identityv1.VerifyTOTPResponse
	generateRecoveryResponse *identityv1.GenerateRecoveryCodesResponse
	useRecoveryResponse      *identityv1.UseRecoveryCodeResponse
	webauthnResponse         *identityv1.WebAuthnCredentialsResponse
	beginTOTPRequest         *identityv1.BeginTOTPRegistrationRequest
	finishTOTPRequest        *identityv1.FinishTOTPRegistrationRequest
	verifyTOTPRequest        *identityv1.VerifyTOTPRequest
	deleteTOTPRequest        *identityv1.DeleteTOTPRequest
	generateRecoveryRequest  *identityv1.GenerateRecoveryCodesRequest
	useRecoveryRequest       *identityv1.UseRecoveryCodeRequest
	deleteRecoveryRequest    *identityv1.DeleteRecoveryCodesRequest
	saveWebAuthnRequest      *identityv1.SaveWebAuthnCredentialRequest
	updateWebAuthnRequest    *identityv1.UpdateWebAuthnCredentialRequest
	deleteWebAuthnRequest    *identityv1.DeleteWebAuthnCredentialRequest
	resolveUserRequest       *identityv1.ResolveUserRequest
	err                      error
	authRequests             int
	lookupRequests           int
	listRequests             int
	resolveRequests          int
	mfaRequests              int
	beginTOTPRequests        int
	finishTOTPRequests       int
	verifyTOTPRequests       int
	deleteTOTPRequests       int
	generateRecoveryRequests int
	useRecoveryRequests      int
	deleteRecoveryRequests   int
	webauthnRequests         int
	saveWebAuthnRequests     int
	updateWebAuthnRequests   int
	deleteWebAuthnRequests   int
}

func (c *fakeAuthorityClient) Authenticate(_ context.Context, _ *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	c.authRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.authResponse, nil
}

func (c *fakeAuthorityClient) LookupIdentity(_ context.Context, _ *authv1.LookupIdentityRequest) (*authv1.AuthResponse, error) {
	c.lookupRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.lookupResponse, nil
}

func (c *fakeAuthorityClient) ListAccounts(_ context.Context, _ *authv1.ListAccountsRequest) (*authv1.ListAccountsResponse, error) {
	c.listRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.listResponse, nil
}

func (c *fakeAuthorityClient) ResolveUser(_ context.Context, request *identityv1.ResolveUserRequest) (*identityv1.UserSnapshotResponse, error) {
	c.resolveRequests++
	c.resolveUserRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.resolveResponse, nil
}

func (c *fakeAuthorityClient) GetMFAState(_ context.Context, _ *identityv1.GetMFAStateRequest) (*identityv1.MFAStateResponse, error) {
	c.mfaRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.mfaResponse, nil
}

func (c *fakeAuthorityClient) BeginTOTPRegistration(
	_ context.Context,
	request *identityv1.BeginTOTPRegistrationRequest,
) (*identityv1.BeginTOTPRegistrationResponse, error) {
	c.beginTOTPRequests++
	c.beginTOTPRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.beginTOTPResponse, nil
}

func (c *fakeAuthorityClient) FinishTOTPRegistration(
	_ context.Context,
	request *identityv1.FinishTOTPRegistrationRequest,
) (*identityv1.MFAWriteResponse, error) {
	c.finishTOTPRequests++
	c.finishTOTPRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.writeResponse, nil
}

func (c *fakeAuthorityClient) VerifyTOTP(
	_ context.Context,
	request *identityv1.VerifyTOTPRequest,
) (*identityv1.VerifyTOTPResponse, error) {
	c.verifyTOTPRequests++
	c.verifyTOTPRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.verifyTOTPResponse, nil
}

func (c *fakeAuthorityClient) DeleteTOTP(
	_ context.Context,
	request *identityv1.DeleteTOTPRequest,
) (*identityv1.MFAWriteResponse, error) {
	c.deleteTOTPRequests++
	c.deleteTOTPRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.writeResponse, nil
}

func (c *fakeAuthorityClient) GenerateRecoveryCodes(
	_ context.Context,
	request *identityv1.GenerateRecoveryCodesRequest,
) (*identityv1.GenerateRecoveryCodesResponse, error) {
	c.generateRecoveryRequests++
	c.generateRecoveryRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.generateRecoveryResponse, nil
}

func (c *fakeAuthorityClient) UseRecoveryCode(
	_ context.Context,
	request *identityv1.UseRecoveryCodeRequest,
) (*identityv1.UseRecoveryCodeResponse, error) {
	c.useRecoveryRequests++
	c.useRecoveryRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.useRecoveryResponse, nil
}

func (c *fakeAuthorityClient) DeleteRecoveryCodes(
	_ context.Context,
	request *identityv1.DeleteRecoveryCodesRequest,
) (*identityv1.MFAWriteResponse, error) {
	c.deleteRecoveryRequests++
	c.deleteRecoveryRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.writeResponse, nil
}

func (c *fakeAuthorityClient) GetWebAuthnCredentials(
	_ context.Context,
	_ *identityv1.GetWebAuthnCredentialsRequest,
) (*identityv1.WebAuthnCredentialsResponse, error) {
	c.webauthnRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.webauthnResponse, nil
}

func (c *fakeAuthorityClient) SaveWebAuthnCredential(
	_ context.Context,
	request *identityv1.SaveWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	c.saveWebAuthnRequests++
	c.saveWebAuthnRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.writeResponse, nil
}

func (c *fakeAuthorityClient) UpdateWebAuthnCredential(
	_ context.Context,
	request *identityv1.UpdateWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	c.updateWebAuthnRequests++
	c.updateWebAuthnRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.writeResponse, nil
}

func (c *fakeAuthorityClient) DeleteWebAuthnCredential(
	_ context.Context,
	request *identityv1.DeleteWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	c.deleteWebAuthnRequests++
	c.deleteWebAuthnRequest = request

	if c.err != nil {
		return nil, c.err
	}

	return c.writeResponse, nil
}
