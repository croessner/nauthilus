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

package pluginruntime

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	servererrors "github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	backendTestAccount      = "alice"
	backendTestAccountAttr  = "account"
	backendTestGUID         = "backend-test"
	backendTestMail         = "alice@example.test"
	backendTestMailAttr     = "mail"
	backendTestModuleName   = "customer"
	backendTestName         = "passdb"
	backendTestQualified    = backendTestModuleName + "." + backendTestName
	backendTestPassword     = "s3cret"
	backendTestProviderAttr = "plugin.customer.passdb.account_provider"
	backendTestRiskAttr     = "plugin.customer.passdb.risk"
	backendTestStatusKey    = "auth.ok"
	backendTestStatusText   = "Plugin authenticated"
	backendTestUIDAttr      = "uid"
	backendTestClientID     = "backend-client"
	backendTestLocalIP      = "127.0.0.10"
	backendTestLocalPort    = "10443"
	backendTestPendingTOTP  = "pending-totp"
	backendTestOldCredID    = "old-credential"
	backendTestNewCredID    = "new-credential"
	backendTestProtocolIMAP = "imap"
	backendTestAttestNone   = "none"

	backendTestOpVerifyPassword           = "verify-password"
	backendTestOpListAccounts             = "list-accounts"
	backendTestOpBeginTOTP                = "begin-totp"
	backendTestOpFinishTOTP               = "finish-totp"
	backendTestOpVerifyTOTP               = "verify-totp"
	backendTestOpDeleteTOTP               = "delete-totp"
	backendTestOpGenerateRecoveryCodes    = "generate-recovery-codes"
	backendTestOpUseRecoveryCode          = "use-recovery-code"
	backendTestOpDeleteRecoveryCodes      = "delete-recovery-codes"
	backendTestOpListWebAuthnCredentials  = "list-webauthn-credentials"
	backendTestOpSaveWebAuthnCredential   = "save-webauthn-credential"
	backendTestOpUpdateWebAuthnCredential = "update-webauthn-credential"
	backendTestOpDeleteWebAuthnCredential = "delete-webauthn-credential"
	backendTestOpPublicMFAState           = "public-mfa-state"
)

func TestBackendManagerPassDBMapsAuthenticatedResult(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			return pluginapi.BackendResult{
				Status: &pluginapi.StatusMessage{
					Code:        pluginCallResultOK,
					MessageKey:  backendTestStatusKey,
					DefaultText: backendTestStatusText,
				},
				Attributes: map[string][]string{
					backendTestMailAttr: {backendTestMail},
				},
				Facts: []pluginapi.PolicyFact{
					{Attribute: backendTestRiskAttr, Value: float64(0.1)},
				},
				Account: backendTestAccount,
				BackendServer: &pluginapi.BackendServerRef{
					Name:     "sql-a",
					Protocol: "mysql",
					Address:  "127.0.0.1",
					Port:     "3306",
				},
				Authenticated: true,
				UserFound:     true,
			}, nil
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	assertAuthenticatedPassDBResult(t, result, auth)
}

func TestBackendManagerPassDBMapsCustomAccountField(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			return pluginapi.BackendResult{
				Account:       backendTestMail,
				AccountField:  backendTestMailAttr,
				UserFound:     true,
				Authenticated: true,
			}, nil
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.Account != backendTestMail || result.AccountField != backendTestMailAttr {
		t.Fatalf("account mapping = %q/%q, want %q/%q", result.Account, result.AccountField, backendTestMail, backendTestMailAttr)
	}

	if got := firstStringAttribute(result.Attributes[backendTestMailAttr]); got != backendTestMail {
		t.Fatalf("custom account attribute = %q, want %s", got, backendTestMail)
	}
}

func TestBackendManagerPassDBRejectsInvalidAccountField(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			return pluginapi.BackendResult{
				Account:      backendTestAccount,
				AccountField: "mail primary",
				UserFound:    true,
			}, nil
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	_, err := manager.PassDB(auth)
	if !stderrors.Is(err, servererrors.ErrBackendTemporaryFailure) {
		t.Fatalf("PassDB() error = %v, want ErrBackendTemporaryFailure", err)
	}
}

func TestBackendManagerAccountDBPropagatesListAccountFactsToPolicy(t *testing.T) {
	activateAccountProviderPluginSnapshot(t, backendTestProviderAttr)

	backend := &fakePluginBackend{
		list: func(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
			return pluginapi.AccountListResult{
				Accounts: []string{backendTestAccount},
				Facts: []pluginapi.PolicyFact{
					{Attribute: backendTestProviderAttr, Value: true},
				},
			}, nil
		},
	}

	runner := newBackendTestRunner(t, []backendTestModule{
		{name: backendTestModuleName, backend: backend},
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	restoreDefaultRunner := replaceDefaultRunnerForTest(runner)
	defer restoreDefaultRunner()

	auth := newBackendTestAuth(t)
	auth.Request.ListAccounts = true
	auth.Cfg().GetServer().Backends = []*config.Backend{mustBackendSelector(t, "plugin("+backendTestQualified+")")}

	accounts := auth.ListUserAccounts()
	if len(accounts) != 1 || accounts[0] != backendTestAccount {
		t.Fatalf("ListUserAccounts() = %#v, want plugin account", accounts)
	}

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()

	attribute, ok := report.Attributes[backendTestProviderAttr]
	if !ok {
		t.Fatalf("missing account-provider plugin fact %q", backendTestProviderAttr)
	}

	if attribute.Value != true {
		t.Fatalf("plugin fact value = %#v, want true", attribute.Value)
	}
}

// assertAuthenticatedPassDBResult verifies the backend result mapping from plugin output.
func assertAuthenticatedPassDBResult(t *testing.T, result *core.PassDBResult, auth *core.AuthState) {
	t.Helper()

	assertBackendResultFlags(t, result)
	assertBackendResultAttributes(t, result)
	assertBackendStatusAndRef(t, result, auth)
	assertBackendFacts(t, result)
}

// assertBackendResultFlags verifies the basic authentication result flags.
func assertBackendResultFlags(t *testing.T, result *core.PassDBResult) {
	t.Helper()

	if !result.Authenticated || !result.UserFound {
		t.Fatalf("result auth flags = authenticated:%t user_found:%t, want both true", result.Authenticated, result.UserFound)
	}

	if result.Backend != definitions.BackendPlugin || result.BackendName != backendTestQualified {
		t.Fatalf("backend = %s/%q, want plugin/%s", result.Backend, result.BackendName, backendTestQualified)
	}

	if result.AccountField != backendTestAccountAttr {
		t.Fatalf("account field = %q, want %s", result.AccountField, backendTestAccountAttr)
	}
}

// assertBackendResultAttributes verifies attributes mapped from the plugin result.
func assertBackendResultAttributes(t *testing.T, result *core.PassDBResult) {
	t.Helper()

	if got := firstStringAttribute(result.Attributes[backendTestMailAttr]); got != backendTestMail {
		t.Fatalf("mail attribute = %q, want %s", got, backendTestMail)
	}

	if got := firstStringAttribute(result.Attributes[backendTestAccountAttr]); got != backendTestAccount {
		t.Fatalf("account attribute = %q, want %s", got, backendTestAccount)
	}
}

// assertBackendStatusAndRef verifies status text and backend server mapping.
func assertBackendStatusAndRef(t *testing.T, result *core.PassDBResult, auth *core.AuthState) {
	t.Helper()

	if auth.Runtime.StatusMessage != backendTestStatusText || auth.Runtime.StatusMessageI18NKey != backendTestStatusKey {
		t.Fatalf("status = %q/%q, want plugin status", auth.Runtime.StatusMessage, auth.Runtime.StatusMessageI18NKey)
	}

	if result.BackendRef.Type != definitions.BackendPluginName || result.BackendRef.OpaqueToken != "127.0.0.1:3306" {
		t.Fatalf("backend ref = %#v, want plugin server reference", result.BackendRef)
	}
}

// assertBackendFacts verifies plugin policy facts were retained.
func assertBackendFacts(t *testing.T, result *core.PassDBResult) {
	t.Helper()

	facts, ok := result.AdditionalAttributes[core.PassDBAdditionalAttributePluginFacts].([]pluginapi.PolicyFact)
	if !ok || len(facts) != 1 || facts[0].Attribute != backendTestRiskAttr {
		t.Fatalf("policy facts = %#v, want plugin fact", result.AdditionalAttributes)
	}
}

func TestBackendManagerPassDBPasswordMismatchMapsFailedAuth(t *testing.T) {
	manager := newBackendTestManager(t, backendTestModuleName, passwordPluginBackend(backendTestPassword), true)
	auth := newBackendTestAuth(t)
	auth.SetPassword(secret.New("wrong"))

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.Authenticated || !result.UserFound {
		t.Fatalf("result auth flags = authenticated:%t user_found:%t, want failed found user", result.Authenticated, result.UserFound)
	}
}

func TestBackendManagerPassDBTemporaryErrorMapsToTempFailure(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			return pluginapi.BackendResult{}, stderrors.New("database timeout with " + backendTestPassword)
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	_, err := manager.PassDB(auth)
	if !stderrors.Is(err, servererrors.ErrBackendTemporaryFailure) {
		t.Fatalf("PassDB() error = %v, want ErrBackendTemporaryFailure", err)
	}

	if strings.Contains(err.Error(), backendTestPassword) {
		t.Fatalf("temporary error leaked password: %v", err)
	}
}

func TestBackendManagerPassDBPanicMapsToSecretSafeTempFailure(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			panic("panic with " + backendTestPassword)
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	_, err := manager.PassDB(auth)
	if !stderrors.Is(err, servererrors.ErrBackendTemporaryFailure) {
		t.Fatalf("PassDB() error = %v, want ErrBackendTemporaryFailure", err)
	}

	if strings.Contains(err.Error(), backendTestPassword) {
		t.Fatalf("panic error leaked password: %v", err)
	}
}

func TestBackendManagerCredentialsRequireCapability(t *testing.T) {
	backend := passwordPluginBackend(backendTestPassword)
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.Authenticated {
		t.Fatal("PassDB() authenticated without credentials capability")
	}

	if !backend.sawCredentialRequest {
		t.Fatal("backend did not attempt credential access")
	}
}

func TestBackendManagerCredentialsAllowedByCapability(t *testing.T) {
	backend := passwordPluginBackend(backendTestPassword)
	manager := newBackendTestManager(t, backendTestModuleName, backend, true)
	auth := newBackendTestAuth(t)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if !result.Authenticated || !backend.sawCredentialRequest {
		t.Fatalf("authenticated = %t credential_requested = %t, want true/true", result.Authenticated, backend.sawCredentialRequest)
	}
}

func TestBackendManagerSameArtifactConfiguredTwiceUsesIndependentPluginResources(t *testing.T) {
	first := &sqlStylePlugin{backendName: backendTestName}
	second := &sqlStylePlugin{backendName: backendTestName}

	runner := newBackendTestRunner(t, []backendTestModule{
		{name: "customer_a", plugin: first, backend: first.backend()},
		{name: "customer_b", plugin: second, backend: second.backend()},
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	firstResult, err := (&BackendManager{runner: runner, qualifiedName: "customer_a." + backendTestName}).PassDB(newBackendTestAuth(t))
	if err != nil {
		t.Fatalf("first PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(firstResult)

	secondResult, err := (&BackendManager{runner: runner, qualifiedName: "customer_b." + backendTestName}).PassDB(newBackendTestAuth(t))
	if err != nil {
		t.Fatalf("second PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(secondResult)

	firstPool := firstStringAttribute(firstResult.Attributes["pool_id"])

	secondPool := firstStringAttribute(secondResult.Attributes["pool_id"])
	if firstPool == "" || secondPool == "" || firstPool == secondPool {
		t.Fatalf("pool ids = %q/%q, want independent plugin-owned resources", firstPool, secondPool)
	}
}

func TestBackendManagerTypedMFAOperationsUseTypedRequests(t *testing.T) {
	manager, backend, auth := newTypedMFABackendTestManager(t)

	exerciseTypedPasswordBackendOperations(t, manager, auth)
	exerciseTypedTOTPBackendOperations(t, manager, auth)
	exerciseTypedRecoveryBackendOperations(t, manager, auth)
	exerciseTypedWebAuthnBackendOperations(t, manager, auth)
	exerciseTypedPublicMFAStateOperation(t, manager, auth)

	assertRecordedBackendOperations(t, backend)
}

func TestBackendManagerMissingOptionalMFAOperationsMapToUnknownBackend(t *testing.T) {
	manager := newBackendTestManager(t, backendTestModuleName, &fakePluginBackend{}, false)
	auth := newBackendTestAuth(t)
	credential := newPersistentCredentialForTest("missing-credential")

	for _, testCase := range missingOptionalMFAOperationCases(manager, auth, credential) {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.run()
			if !stderrors.Is(err, servererrors.ErrUnknownDatabaseBackend) {
				t.Fatalf("operation error = %v, want ErrUnknownDatabaseBackend", err)
			}
		})
	}
}

// newTypedMFABackendTestManager builds the recording backend fixture used by typed MFA parity tests.
func newTypedMFABackendTestManager(t *testing.T) (*BackendManager, *recordingPluginMFABackend, *core.AuthState) {
	t.Helper()

	backend := newRecordingPluginMFABackend()

	runner := newBackendTestRunner(t, []backendTestModule{
		{name: backendTestModuleName, backend: backend},
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	auth := newBackendTestAuth(t)
	auth.Request.XClientID = backendTestClientID
	auth.Request.XLocalIP = backendTestLocalIP
	auth.Request.XPort = backendTestLocalPort
	auth.Runtime.Context.Set("plugin.trace", "trace-1")

	manager := &BackendManager{runner: runner, qualifiedName: backendTestQualified}

	return manager, backend, auth
}

// exerciseTypedPasswordBackendOperations verifies the password and account typed requests.
func exerciseTypedPasswordBackendOperations(t *testing.T, manager *BackendManager, auth *core.AuthState) {
	t.Helper()

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	accounts, err := manager.AccountDB(auth)
	if err != nil || len(accounts) != 1 || accounts[0] != backendTestAccount {
		t.Fatalf("AccountDB() = %#v, %v; want account", accounts, err)
	}
}

// exerciseTypedTOTPBackendOperations verifies the typed TOTP operation family.
func exerciseTypedTOTPBackendOperations(t *testing.T, manager *BackendManager, auth *core.AuthState) {
	t.Helper()

	registration, err := manager.BeginTOTPRegistration(auth, "begin-key")
	if err != nil {
		t.Fatalf("BeginTOTPRegistration() error = %v", err)
	}

	if registration.PendingRegistrationID != backendTestPendingTOTP || registration.OTPAuthURL == "" {
		t.Fatalf("TOTP registration = %#v, want pending setup", registration)
	}

	if err := manager.FinishTOTPRegistration(auth, backendTestPendingTOTP, "123456", "finish-key"); err != nil {
		t.Fatalf("FinishTOTPRegistration() error = %v", err)
	}

	verified, err := manager.VerifyTOTP(auth, "654321")
	if err != nil || !verified {
		t.Fatalf("VerifyTOTP() = %t, %v; want verified", verified, err)
	}

	if err := manager.DeleteTOTP(auth, "delete-totp-key"); err != nil {
		t.Fatalf("DeleteTOTP() error = %v", err)
	}
}

// exerciseTypedRecoveryBackendOperations verifies typed recovery-code requests.
func exerciseTypedRecoveryBackendOperations(t *testing.T, manager *BackendManager, auth *core.AuthState) {
	t.Helper()

	codes, err := manager.GenerateRecoveryCodes(auth, 2, "generate-recovery-key")
	if err != nil || len(codes) != 2 {
		t.Fatalf("GenerateRecoveryCodes() = %#v, %v; want two codes", codes, err)
	}

	valid, err := manager.UseRecoveryCode(auth, "recovery-code", "use-recovery-key")
	if err != nil || !valid {
		t.Fatalf("UseRecoveryCode() = %t, %v; want valid", valid, err)
	}

	if err := manager.DeleteRecoveryCodes(auth, "delete-recovery-key"); err != nil {
		t.Fatalf("DeleteRecoveryCodes() error = %v", err)
	}

	remainingValid, remaining, err := manager.ConsumeTOTPRecoveryCode(auth, "recovery-code")
	if err != nil || !remainingValid || remaining != 1 {
		t.Fatalf("ConsumeTOTPRecoveryCode() = %t/%d, %v; want valid remaining code", remainingValid, remaining, err)
	}
}

// exerciseTypedWebAuthnBackendOperations verifies typed WebAuthn credential requests.
func exerciseTypedWebAuthnBackendOperations(t *testing.T, manager *BackendManager, auth *core.AuthState) {
	t.Helper()

	credentials, err := manager.GetWebAuthnCredentials(auth)
	if err != nil || len(credentials) != 1 || string(credentials[0].ID) != "list-credential" {
		t.Fatalf("GetWebAuthnCredentials() = %#v, %v; want listed credential", credentials, err)
	}

	oldCredential := newPersistentCredentialForTest(backendTestOldCredID)
	newCredential := newPersistentCredentialForTest(backendTestNewCredID)

	if err := manager.SaveWebAuthnCredential(auth, oldCredential); err != nil {
		t.Fatalf("SaveWebAuthnCredential() error = %v", err)
	}

	if err := manager.UpdateWebAuthnCredential(auth, oldCredential, newCredential); err != nil {
		t.Fatalf("UpdateWebAuthnCredential() error = %v", err)
	}

	if err := manager.DeleteWebAuthnCredential(auth, newCredential); err != nil {
		t.Fatalf("DeleteWebAuthnCredential() error = %v", err)
	}
}

// exerciseTypedPublicMFAStateOperation verifies typed public MFA state requests.
func exerciseTypedPublicMFAStateOperation(t *testing.T, manager *BackendManager, auth *core.AuthState) {
	t.Helper()

	state, err := manager.GetPublicMFAState(auth, true)
	if err != nil || !state.HasTOTP || !state.HasWebAuthn || state.RecoveryCodeCount != 2 || len(state.WebAuthnCredentials) != 1 {
		t.Fatalf("GetPublicMFAState() = %#v, %v; want public MFA state", state, err)
	}
}

type missingOptionalMFAOperationCase struct {
	name string
	run  func() error
}

// missingOptionalMFAOperationCases lists optional backend calls that should use missing-backend semantics.
func missingOptionalMFAOperationCases(
	manager *BackendManager,
	auth *core.AuthState,
	credential *mfa.PersistentCredential,
) []missingOptionalMFAOperationCase {
	return []missingOptionalMFAOperationCase{
		{name: "begin totp", run: func() error {
			_, err := manager.BeginTOTPRegistration(auth, "begin-key")

			return err
		}},
		{name: "finish totp", run: func() error {
			return manager.FinishTOTPRegistration(auth, "pending", "123456", "finish-key")
		}},
		{name: "verify totp", run: func() error {
			_, err := manager.VerifyTOTP(auth, "123456")

			return err
		}},
		{name: "delete totp", run: func() error {
			return manager.DeleteTOTP(auth, "delete-key")
		}},
		{name: "generate recovery codes", run: func() error {
			_, err := manager.GenerateRecoveryCodes(auth, 2, "generate-key")

			return err
		}},
		{name: "use recovery code", run: func() error {
			_, err := manager.UseRecoveryCode(auth, "code", "use-key")

			return err
		}},
		{name: "delete recovery codes", run: func() error {
			return manager.DeleteRecoveryCodes(auth, "delete-recovery-key")
		}},
		{name: "list webauthn credentials", run: func() error {
			_, err := manager.GetWebAuthnCredentials(auth)

			return err
		}},
		{name: "save webauthn credential", run: func() error {
			return manager.SaveWebAuthnCredential(auth, credential)
		}},
		{name: "update webauthn credential", run: func() error {
			return manager.UpdateWebAuthnCredential(auth, credential, credential)
		}},
		{name: "delete webauthn credential", run: func() error {
			return manager.DeleteWebAuthnCredential(auth, credential)
		}},
		{name: "public mfa state", run: func() error {
			_, err := manager.GetPublicMFAState(auth, true)

			return err
		}},
	}
}

func newBackendTestManager(t *testing.T, moduleName string, backend *fakePluginBackend, requireCredentials bool) *BackendManager {
	t.Helper()

	plugin := &backendTestPlugin{
		backend:            backend,
		requireCredentials: requireCredentials,
	}

	runner := newBackendTestRunner(t, []backendTestModule{
		{name: moduleName, plugin: plugin, backend: backend, allowCredentials: requireCredentials},
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return &BackendManager{runner: runner, qualifiedName: moduleName + "." + backend.Name()}
}

func newBackendTestRunner(t *testing.T, modules []backendTestModule) *Runner {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	instances := make([]pluginloader.ModuleInstance, 0, len(modules))

	for _, item := range modules {
		module := config.PluginModule{
			Name: item.name,
			Type: config.PluginModuleTypeGo,
			Path: "/plugins/fake-sql.so",
		}
		if item.allowCredentials {
			module.AllowCapabilities = []pluginapi.Capability{pluginapi.CapabilityCredentials}
		}

		registrar := registry.NewRegistrar(module)
		if item.plugin != nil {
			if err := item.plugin.Register(registrar); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
		} else if err := registrar.RegisterBackend(item.backend); err != nil {
			t.Fatalf("RegisterBackend() error = %v", err)
		}

		if err := registrar.Commit(); err != nil {
			t.Fatalf("Commit() error = %v", err)
		}

		instances = append(instances, pluginloader.ModuleInstance{
			Plugin:       item.plugin,
			Module:       module,
			ModuleName:   module.Name,
			Status:       pluginloader.ModuleStatusRegistered,
			Capabilities: registrar.Capabilities(),
			ArtifactPath: module.Path,
		})
	}

	return NewRunnerFromInstances(registry, instances)
}

func newBackendTestAuth(t *testing.T) *core.AuthState {
	t.Helper()

	initBackendTestPools()

	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "https://nauthilus.test/auth", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	auth := core.NewAuthStateFromContextWithDeps(ctx, core.AuthDeps{Cfg: cfg}).(*core.AuthState)
	auth.Runtime.Context = lualib.NewContext()
	auth.Runtime.GUID = backendTestGUID
	auth.Request.Username = backendTestAccount
	auth.Request.Password = secret.New(backendTestPassword)
	auth.Request.Protocol = config.NewProtocol(definitions.ProtoHTTP)

	return auth
}

func passwordPluginBackend(wantPassword string) *fakePluginBackend {
	backend := &fakePluginBackend{}
	backend.verify = func(ctx context.Context, request pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
		backend.sawCredentialRequest = true

		credential, ok := request.Credentials.Password(ctx)
		if !ok {
			return pluginapi.BackendResult{
				Account:   request.Username,
				UserFound: true,
			}, nil
		}

		matches := false

		if err := credential.WithBytes(func(value []byte) error {
			matches = string(value) == wantPassword

			return nil
		}); err != nil {
			return pluginapi.BackendResult{}, err
		}

		return pluginapi.BackendResult{
			Attributes:    map[string][]string{backendTestUIDAttr: {request.Username}},
			Account:       request.Username,
			UserFound:     true,
			Authenticated: matches,
		}, nil
	}

	return backend
}

func firstStringAttribute(values []any) string {
	if len(values) == 0 {
		return ""
	}

	value, _ := values[0].(string)

	return value
}

type backendTestModule struct {
	plugin           pluginapi.Plugin
	backend          pluginapi.Backend
	name             string
	allowCredentials bool
}

type backendTestPlugin struct {
	backend            pluginapi.Backend
	requireCredentials bool
}

func (p *backendTestPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       backendTestGUID,
		Version:    testRuntimePluginVersion,
		APIVersion: pluginapi.APIVersion,
	}
}

func (p *backendTestPlugin) Register(registrar pluginapi.Registrar) error {
	if p.requireCredentials {
		if err := registrar.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
			return err
		}
	}

	return registrar.RegisterBackend(p.backend)
}

type fakePluginBackend struct {
	verify               func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error)
	list                 func(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error)
	sawCredentialRequest bool
}

func (b *fakePluginBackend) Name() string {
	return backendTestName
}

func (b *fakePluginBackend) VerifyPassword(ctx context.Context, request pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	if b.verify == nil {
		return pluginapi.BackendResult{}, nil
	}

	return b.verify(ctx, request)
}

func (b *fakePluginBackend) ListAccounts(ctx context.Context, request pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	if b.list == nil {
		return pluginapi.AccountListResult{}, nil
	}

	return b.list(ctx, request)
}

type recordedPluginBackendCall struct {
	snapshot              pluginapi.RequestSnapshot
	runtime               pluginapi.RuntimeContext
	credential            pluginapi.WebAuthnCredential
	oldCredential         pluginapi.WebAuthnCredential
	newCredential         pluginapi.WebAuthnCredential
	credentialID          []byte
	operation             string
	username              string
	idempotencyKey        string
	pendingRegistrationID string
	code                  string
	count                 uint32
	includeWebAuthn       bool
}

type recordingPluginMFABackend struct {
	calls []recordedPluginBackendCall
}

// newRecordingPluginMFABackend returns a fake backend covering every typed optional MFA interface.
func newRecordingPluginMFABackend() *recordingPluginMFABackend {
	return &recordingPluginMFABackend{}
}

// Name returns the backend component name for the recording fixture.
func (b *recordingPluginMFABackend) Name() string {
	return backendTestName
}

// VerifyPassword records the typed password verification request.
func (b *recordingPluginMFABackend) VerifyPassword(_ context.Context, request pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	b.record(backendTestOpVerifyPassword, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{})

	return pluginapi.BackendResult{
		Account:       request.Username,
		UserFound:     true,
		Authenticated: true,
		BackendServer: backendOperationServerRef(),
	}, nil
}

// ListAccounts records the typed account-list request.
func (b *recordingPluginMFABackend) ListAccounts(_ context.Context, request pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	b.record(backendTestOpListAccounts, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{})

	return pluginapi.AccountListResult{Accounts: []string{request.Username}}, nil
}

// BeginTOTP records the typed TOTP begin request.
func (b *recordingPluginMFABackend) BeginTOTP(_ context.Context, request pluginapi.TOTPBeginRequest) (pluginapi.TOTPBeginResult, error) {
	b.record(backendTestOpBeginTOTP, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		idempotencyKey: request.IdempotencyKey,
	})

	return pluginapi.TOTPBeginResult{
		BackendServer:         backendOperationServerRef(),
		ExpiresAt:             time.Unix(1_750_000_000, 0),
		PendingRegistrationID: backendTestPendingTOTP,
		OTPAuthURL:            "otpauth://totp/nauthilus:alice",
	}, nil
}

// FinishTOTP records the typed TOTP finish request.
func (b *recordingPluginMFABackend) FinishTOTP(_ context.Context, request pluginapi.TOTPFinishRequest) (pluginapi.TOTPFinishResult, error) {
	b.record(backendTestOpFinishTOTP, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		idempotencyKey:        request.IdempotencyKey,
		pendingRegistrationID: request.PendingRegistrationID,
		code:                  request.Code,
	})

	return pluginapi.TOTPFinishResult{BackendServer: backendOperationServerRef(), Verified: true}, nil
}

// VerifyTOTP records the typed TOTP verification request.
func (b *recordingPluginMFABackend) VerifyTOTP(_ context.Context, request pluginapi.TOTPVerifyRequest) (pluginapi.TOTPVerifyResult, error) {
	b.record(backendTestOpVerifyTOTP, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		code: request.Code,
	})

	return pluginapi.TOTPVerifyResult{BackendServer: backendOperationServerRef(), Verified: true}, nil
}

// DeleteTOTP records the typed TOTP delete request.
func (b *recordingPluginMFABackend) DeleteTOTP(_ context.Context, request pluginapi.TOTPDeleteRequest) error {
	b.record(backendTestOpDeleteTOTP, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		idempotencyKey: request.IdempotencyKey,
	})

	return nil
}

// GenerateRecoveryCodes records the typed recovery-code generation request.
func (b *recordingPluginMFABackend) GenerateRecoveryCodes(_ context.Context, request pluginapi.RecoveryCodeGenerateRequest) (pluginapi.RecoveryCodeGenerateResult, error) {
	b.record(backendTestOpGenerateRecoveryCodes, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		idempotencyKey: request.IdempotencyKey,
		count:          request.Count,
	})

	return pluginapi.RecoveryCodeGenerateResult{BackendServer: backendOperationServerRef(), Codes: []string{"code-1", "code-2"}}, nil
}

// UseRecoveryCode records the typed recovery-code consumption request.
func (b *recordingPluginMFABackend) UseRecoveryCode(_ context.Context, request pluginapi.RecoveryCodeUseRequest) (pluginapi.RecoveryCodeUseResult, error) {
	b.record(backendTestOpUseRecoveryCode, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		idempotencyKey: request.IdempotencyKey,
		code:           request.Code,
	})

	return pluginapi.RecoveryCodeUseResult{BackendServer: backendOperationServerRef(), Valid: true, Remaining: 1}, nil
}

// DeleteRecoveryCodes records the typed recovery-code delete request.
func (b *recordingPluginMFABackend) DeleteRecoveryCodes(_ context.Context, request pluginapi.RecoveryCodeDeleteRequest) error {
	b.record(backendTestOpDeleteRecoveryCodes, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		idempotencyKey: request.IdempotencyKey,
	})

	return nil
}

// ListWebAuthnCredentials records the typed WebAuthn list request.
func (b *recordingPluginMFABackend) ListWebAuthnCredentials(_ context.Context, request pluginapi.WebAuthnListRequest) (pluginapi.WebAuthnListResult, error) {
	b.record(backendTestOpListWebAuthnCredentials, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{})

	return pluginapi.WebAuthnListResult{
		BackendServer: backendOperationServerRef(),
		Credentials:   []pluginapi.WebAuthnCredential{newPluginWebAuthnCredentialForTest("list-credential")},
	}, nil
}

// SaveWebAuthnCredential records the typed WebAuthn save request.
func (b *recordingPluginMFABackend) SaveWebAuthnCredential(_ context.Context, request pluginapi.WebAuthnSaveRequest) error {
	b.record(backendTestOpSaveWebAuthnCredential, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		credential: request.Credential,
	})

	return nil
}

// UpdateWebAuthnCredential records the typed WebAuthn replacement request.
func (b *recordingPluginMFABackend) UpdateWebAuthnCredential(_ context.Context, request pluginapi.WebAuthnUpdateRequest) error {
	b.record(backendTestOpUpdateWebAuthnCredential, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		oldCredential: request.OldCredential,
		newCredential: request.NewCredential,
	})

	return nil
}

// DeleteWebAuthnCredential records the typed WebAuthn delete request.
func (b *recordingPluginMFABackend) DeleteWebAuthnCredential(_ context.Context, request pluginapi.WebAuthnDeleteRequest) error {
	b.record(backendTestOpDeleteWebAuthnCredential, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		credentialID: append([]byte(nil), request.CredentialID...),
	})

	return nil
}

// PublicMFAState records the typed public MFA state request.
func (b *recordingPluginMFABackend) PublicMFAState(_ context.Context, request pluginapi.PublicMFAStateRequest) (pluginapi.PublicMFAStateResult, error) {
	credentials := []pluginapi.WebAuthnCredential(nil)
	if request.IncludeWebAuthn {
		credentials = []pluginapi.WebAuthnCredential{newPluginWebAuthnCredentialForTest("public-credential")}
	}

	b.record(backendTestOpPublicMFAState, request.Username, request.Snapshot, request.Runtime, recordedPluginBackendCall{
		includeWebAuthn: request.IncludeWebAuthn,
	})

	return pluginapi.PublicMFAStateResult{
		BackendServer:       backendOperationServerRef(),
		WebAuthnCredentials: credentials,
		RecoveryCodeCount:   2,
		HasTOTP:             true,
		HasWebAuthn:         true,
	}, nil
}

// record appends one normalized call entry for later assertions.
func (b *recordingPluginMFABackend) record(
	operation string,
	username string,
	snapshot pluginapi.RequestSnapshot,
	runtime pluginapi.RuntimeContext,
	extra recordedPluginBackendCall,
) {
	extra.operation = operation
	extra.username = username
	extra.snapshot = snapshot
	extra.runtime = runtime
	b.calls = append(b.calls, extra)
}

// operations returns operation names in call order.
func (b *recordingPluginMFABackend) operations() []string {
	operations := make([]string, 0, len(b.calls))
	for _, call := range b.calls {
		operations = append(operations, call.operation)
	}

	return operations
}

// assertRecordedBackendOperations verifies every typed backend operation reached the plugin.
func assertRecordedBackendOperations(t *testing.T, backend *recordingPluginMFABackend) {
	t.Helper()

	expected := []string{
		backendTestOpVerifyPassword,
		backendTestOpListAccounts,
		backendTestOpBeginTOTP,
		backendTestOpFinishTOTP,
		backendTestOpVerifyTOTP,
		backendTestOpDeleteTOTP,
		backendTestOpGenerateRecoveryCodes,
		backendTestOpUseRecoveryCode,
		backendTestOpDeleteRecoveryCodes,
		backendTestOpUseRecoveryCode,
		backendTestOpListWebAuthnCredentials,
		backendTestOpSaveWebAuthnCredential,
		backendTestOpUpdateWebAuthnCredential,
		backendTestOpDeleteWebAuthnCredential,
		backendTestOpPublicMFAState,
	}
	if !sameStrings(backend.operations(), expected) {
		t.Fatalf("operations = %#v, want %#v", backend.operations(), expected)
	}

	for _, call := range backend.calls {
		if call.username != backendTestAccount {
			t.Fatalf("%s username = %q, want %s", call.operation, call.username, backendTestAccount)
		}

		if call.snapshot.ClientID != backendTestClientID ||
			call.snapshot.LocalIP != backendTestLocalIP ||
			call.snapshot.LocalPort != backendTestLocalPort {
			t.Fatalf("%s snapshot = %#v, want expanded safe request context", call.operation, call.snapshot)
		}

		if value, ok := call.runtime.Get("plugin.trace"); !ok || value != "trace-1" {
			t.Fatalf("%s runtime trace = %#v/%t, want trace-1", call.operation, value, ok)
		}
	}

	assertRecordedBackendOperationDetails(t, backend.calls)
}

// assertRecordedBackendOperationDetails verifies operation-specific typed payload fields.
func assertRecordedBackendOperationDetails(t *testing.T, calls []recordedPluginBackendCall) {
	t.Helper()

	byOperation := make(map[string]recordedPluginBackendCall, len(calls))
	for _, call := range calls {
		if _, exists := byOperation[call.operation]; !exists {
			byOperation[call.operation] = call
		}
	}

	if byOperation[backendTestOpBeginTOTP].idempotencyKey != "begin-key" {
		t.Fatalf("begin key = %q, want begin-key", byOperation[backendTestOpBeginTOTP].idempotencyKey)
	}

	if byOperation[backendTestOpFinishTOTP].pendingRegistrationID != backendTestPendingTOTP ||
		byOperation[backendTestOpFinishTOTP].code != "123456" {
		t.Fatalf("finish payload = %#v, want pending-totp/123456", byOperation[backendTestOpFinishTOTP])
	}

	if byOperation[backendTestOpGenerateRecoveryCodes].count != 2 {
		t.Fatalf("recovery count = %d, want 2", byOperation[backendTestOpGenerateRecoveryCodes].count)
	}

	if string(byOperation[backendTestOpSaveWebAuthnCredential].credential.ID) != backendTestOldCredID {
		t.Fatalf("save credential = %#v, want old credential", byOperation[backendTestOpSaveWebAuthnCredential].credential)
	}

	if string(byOperation[backendTestOpUpdateWebAuthnCredential].oldCredential.ID) != backendTestOldCredID ||
		string(byOperation[backendTestOpUpdateWebAuthnCredential].newCredential.ID) != backendTestNewCredID {
		t.Fatalf("update credentials = %#v, want old/new credentials", byOperation[backendTestOpUpdateWebAuthnCredential])
	}

	if string(byOperation[backendTestOpDeleteWebAuthnCredential].credentialID) != backendTestNewCredID {
		t.Fatalf("delete credential id = %q, want new-credential", string(byOperation[backendTestOpDeleteWebAuthnCredential].credentialID))
	}

	if !byOperation[backendTestOpPublicMFAState].includeWebAuthn {
		t.Fatal("public MFA state did not request WebAuthn credentials")
	}
}

// backendOperationServerRef returns a reusable plugin backend reference for optional operation results.
func backendOperationServerRef() *pluginapi.BackendServerRef {
	return &pluginapi.BackendServerRef{
		Name:     "plugin-backend-a",
		Protocol: backendTestProtocolIMAP,
		Address:  "192.0.2.100",
		Port:     "993",
	}
}

// newPluginWebAuthnCredentialForTest creates an API-level credential fixture.
func newPluginWebAuthnCredentialForTest(id string) pluginapi.WebAuthnCredential {
	return pluginapi.WebAuthnCredential{
		LastUsed:       time.Unix(1_750_000_001, 0),
		ID:             []byte(id),
		PublicKey:      []byte("public-" + id),
		Transports:     []string{"usb", "hybrid"},
		AAGUID:         "aaguid-" + id,
		Attestation:    backendTestAttestNone,
		Authenticator:  "platform",
		SignCount:      17,
		BackupState:    true,
		BackupEligible: true,
	}
}

// newPersistentCredentialForTest creates a host-side WebAuthn credential fixture.
func newPersistentCredentialForTest(id string) *mfa.PersistentCredential {
	return &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID:              []byte(id),
			PublicKey:       []byte("public-" + id),
			AttestationType: backendTestAttestNone,
			Transport:       []protocol.AuthenticatorTransport{protocol.USB, protocol.Hybrid},
			Flags: webauthn.CredentialFlags{
				BackupEligible: true,
				BackupState:    true,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:     []byte("aaguid-" + id),
				SignCount:  17,
				Attachment: protocol.Platform,
			},
		},
		Name:     id,
		LastUsed: time.Unix(1_750_000_001, 0),
	}
}

type sqlStylePlugin struct {
	pool        *fakeSQLPool
	backendName string
}

func (p *sqlStylePlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       "sql-style",
		Version:    testRuntimePluginVersion,
		APIVersion: pluginapi.APIVersion,
	}
}

func (p *sqlStylePlugin) Register(registrar pluginapi.Registrar) error {
	return registrar.RegisterBackend(p.backend())
}

func (p *sqlStylePlugin) Start(context.Context, pluginapi.Host) error {
	p.pool = &fakeSQLPool{id: int(sqlStylePoolCounter.Add(1))}

	return nil
}

func (p *sqlStylePlugin) Stop(context.Context) error {
	if p.pool != nil {
		p.pool.closed = true
	}

	return nil
}

func (p *sqlStylePlugin) backend() pluginapi.Backend {
	return &sqlStyleBackend{plugin: p, name: p.backendName}
}

type sqlStyleBackend struct {
	plugin *sqlStylePlugin
	name   string
}

func (b *sqlStyleBackend) Name() string {
	return b.name
}

func (b *sqlStyleBackend) VerifyPassword(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	if b.plugin.pool == nil || b.plugin.pool.closed {
		return pluginapi.BackendResult{}, fmt.Errorf("pool unavailable")
	}

	poolID := strconv.Itoa(b.plugin.pool.id)

	return pluginapi.BackendResult{
		Attributes:    map[string][]string{"pool_id": {poolID}},
		Account:       backendTestAccount,
		UserFound:     true,
		Authenticated: true,
	}, nil
}

func (b *sqlStyleBackend) ListAccounts(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	return pluginapi.AccountListResult{Accounts: []string{backendTestAccount}}, nil
}

type fakeSQLPool struct {
	id     int
	closed bool
}

var sqlStylePoolCounter atomic.Int64

var backendTestPoolInit sync.Once

func initBackendTestPools() {
	backendTestPoolInit.Do(core.InitPassDBResultPool)
}

// activateAccountProviderPluginSnapshot publishes a minimal snapshot for plugin account-provider facts.
func activateAccountProviderPluginSnapshot(t *testing.T, attribute string) {
	t.Helper()

	snapshot := &policyruntime.Snapshot{
		Generation:    1,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		AttributeRegistry: map[string]policyregistry.AttributeDefinition{
			attribute: {
				ID:         attribute,
				Stage:      policy.StageAccountProvider,
				Operations: []policy.Operation{policy.OperationListAccounts},
				Category:   policyregistry.AttributeCategoryEnvironment,
				Type:       policyregistry.AttributeTypeBool,
				Source:     policyregistry.SourcePlugin,
			},
		},
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationListAccounts: {
				policy.StageAccountProvider: {
					Stage: policy.StageAccountProvider,
					Checks: []policyruntime.CompiledCheck{
						{
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
							Name:       "account_provider",
							Type:       policy.CheckTypeAccountProvider,
							ConfigRef:  "auth.backends",
							Stage:      policy.StageAccountProvider,
							Operations: []policy.Operation{policy.OperationListAccounts},
						},
					},
				},
			},
		},
	}
	if err := policyruntime.DefaultStore().Activate(snapshot); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	t.Cleanup(func() {
		if err := policyruntime.DefaultStore().Activate(&policyruntime.Snapshot{}); err != nil {
			t.Fatalf("restore policy snapshot: %v", err)
		}
	})
}

// mustBackendSelector parses a backend selector and fails the test on invalid syntax.
func mustBackendSelector(t *testing.T, selector string) *config.Backend {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set(selector); err != nil {
		t.Fatalf("backend selector %q error = %v", selector, err)
	}

	return backend
}

// replaceDefaultRunnerForTest swaps the process-wide plugin runner for one test.
func replaceDefaultRunnerForTest(runner *Runner) func() {
	previous, ok := DefaultRunner()

	SetDefaultRunner(runner)

	return func() {
		if ok {
			SetDefaultRunner(previous)

			return
		}

		SetDefaultRunner(NewRunnerFromInstances(pluginregistry.NewRegistry(), nil))
	}
}
