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

//nolint:funlen // Selected-backend tests keep the full stale-session negative contract together.
package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	testBackendMasterTargetLogin = "target@example.test"
	testBackendMasterAdminLogin  = "master@example.test"
	testBackendMasterFormatted   = testBackendMasterTargetLogin + "*" + testBackendMasterAdminLogin
)

func TestTestBackendPassDBReturnsAccountAttribute(t *testing.T) {
	setupMinimalTestConfig(t)
	util.SetDefaultEnvironment(config.GetEnvironment())

	manager := NewTestBackendManager("cbor-smoke", AuthDeps{})
	auth := &AuthState{deps: AuthDeps{Cfg: config.GetFile()}}
	auth.Request.Username = "cbor@example.test"
	auth.Request.Password = secret.New("secret")
	auth.Request.Protocol = config.NewProtocol("imap")

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatal(err)
	}

	values, ok := result.Attributes[result.AccountField]
	if !ok {
		t.Fatalf("expected account field %q in attributes", result.AccountField)
	}

	if len(values) != 1 || values[0] != auth.Request.Username {
		t.Fatalf("expected account attribute %q, got %#v", auth.Request.Username, values)
	}
}

func TestTestBackendPassDBRejectsChangedPassword(t *testing.T) {
	setupMinimalTestConfig(t)
	util.SetDefaultEnvironment(config.GetEnvironment())

	manager := NewTestBackendManager("test_backend_password_contract", AuthDeps{})
	username := "password-contract@example.test"

	firstResult, err := manager.PassDB(newTestBackendPasswordAuth(username, "original-secret"))
	if err != nil {
		t.Fatal(err)
	}

	if !firstResult.Authenticated {
		t.Fatal("first password authentication should seed and authenticate the test account")
	}

	wrongResult, err := manager.PassDB(newTestBackendPasswordAuth(username, "changed-secret"))
	if err != nil {
		t.Fatal(err)
	}

	if wrongResult.Authenticated {
		t.Fatal("changed password must not authenticate an existing test account")
	}

	retryResult, err := manager.PassDB(newTestBackendPasswordAuth(username, "original-secret"))
	if err != nil {
		t.Fatal(err)
	}

	if !retryResult.Authenticated {
		t.Fatal("original password must remain valid after a failed changed-password attempt")
	}
}

func TestTestBackendPasswordHashUsesRequestConfigurationNonce(t *testing.T) {
	setupMinimalTestConfig(t)

	firstConfig := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{
		PasswordNonce: secret.New("request-nonce-one"),
	}}}
	secondConfig := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{
		PasswordNonce: secret.New("request-nonce-two"),
	}}}
	manager := NewTestBackendManager("request_nonce_contract", AuthDeps{Cfg: firstConfig})
	username := "request-nonce@example.test"
	first := newTestBackendPasswordAuth(username, "same-password")
	first.deps.Cfg = firstConfig

	firstResult, err := manager.PassDB(first)
	if err != nil || !firstResult.Authenticated {
		t.Fatalf("first PassDB() = (%#v, %v), want authenticated", firstResult, err)
	}

	second := newTestBackendPasswordAuth(username, "same-password")
	second.deps.Cfg = secondConfig

	secondResult, err := manager.PassDB(second)
	if err != nil {
		t.Fatalf("second PassDB() error = %v", err)
	}

	if secondResult.Authenticated {
		t.Fatal("second request authenticated with a hash derived from the ambient nonce")
	}
}

func TestTestBackendPassDBResolvesMasterUserToTargetAccount(t *testing.T) {
	setupMinimalTestConfig(t)
	util.SetDefaultEnvironment(config.GetEnvironment())

	cfg, ok := config.GetFile().(*config.FileSettings)
	if !ok {
		t.Fatalf("unexpected config type %T", config.GetFile())
	}

	cfg.Server.MasterUser = config.MasterUser{
		Enabled:    true,
		UserFormat: config.DefaultMasterUserFormat,
	}

	manager := NewTestBackendManager("test_backend_master_user_contract", AuthDeps{})
	targetAuth := newTestBackendPasswordAuth(testBackendMasterTargetLogin, "target-secret")
	targetAuth.deps = AuthDeps{Cfg: config.GetFile()}
	masterAuth := newTestBackendPasswordAuth(testBackendMasterAdminLogin, "master-secret")
	masterAuth.deps = AuthDeps{Cfg: config.GetFile()}
	loginAuth := newTestBackendPasswordAuth(testBackendMasterFormatted, "master-secret")
	loginAuth.deps = AuthDeps{Cfg: config.GetFile()}

	if _, err := manager.PassDB(targetAuth); err != nil {
		t.Fatalf("target seed PassDB returned error: %v", err)
	}

	if _, err := manager.PassDB(masterAuth); err != nil {
		t.Fatalf("master seed PassDB returned error: %v", err)
	}

	result, err := manager.PassDB(loginAuth)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Authenticated {
		t.Fatal("master password should authenticate the target account")
	}

	if result.Account != testBackendMasterTargetLogin {
		t.Fatalf("account = %q, want %s", result.Account, testBackendMasterTargetLogin)
	}

	values := result.Attributes[result.AccountField]
	if len(values) != 1 || values[0] != testBackendMasterTargetLogin {
		t.Fatalf("account attribute = %#v, want %s", values, testBackendMasterTargetLogin)
	}
}

func TestTestBackendWebAuthnCredentialPersistenceContract(t *testing.T) {
	setupMinimalTestConfig(t)
	util.SetDefaultEnvironment(config.GetEnvironment())

	manager := NewTestBackendManager("baseline_webauthn_contract", AuthDeps{})
	auth := &AuthState{}
	auth.Request.Username = "baseline-webauthn@example.test"
	auth.Request.Protocol = config.NewProtocol("idp")

	lastUsed := time.Date(2026, time.May, 12, 11, 0, 0, 0, time.UTC)
	original := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("credential-a"),
			Authenticator: webauthn.Authenticator{
				SignCount: 3,
			},
		},
		Name: "Original device",
	}
	updated := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("credential-a"),
			Authenticator: webauthn.Authenticator{
				SignCount: 9,
			},
		},
		Name:     "Renamed device",
		LastUsed: lastUsed,
	}

	if err := manager.SaveWebAuthnCredential(auth, original); err != nil {
		t.Fatalf("SaveWebAuthnCredential returned error: %v", err)
	}

	assertStoredWebAuthnCredentials(t, manager, auth, []mfa.PersistentCredential{*original})

	if err := manager.UpdateWebAuthnCredential(auth, original, updated); err != nil {
		t.Fatalf("UpdateWebAuthnCredential returned error: %v", err)
	}

	assertStoredWebAuthnCredentials(t, manager, auth, []mfa.PersistentCredential{*updated})

	if err := manager.DeleteWebAuthnCredential(auth, updated); err != nil {
		t.Fatalf("DeleteWebAuthnCredential returned error: %v", err)
	}

	assertStoredWebAuthnCredentials(t, manager, auth, nil)
}

func TestSelectedBackendWebAuthnOperationsIgnoreLegacySessionBackend(t *testing.T) {
	setupMinimalTestConfig(t)
	util.SetDefaultEnvironment(config.GetEnvironment())
	gin.SetMode(gin.TestMode)

	const (
		username      = "canonical-webauthn@example.test"
		canonicalName = "canonical-webauthn-backend"
		legacyName    = "legacy-webauthn-backend"
	)

	canonicalManager := NewTestBackendManager(canonicalName, AuthDeps{})
	legacyManager := NewTestBackendManager(legacyName, AuthDeps{})
	canonicalCredential := &mfa.PersistentCredential{
		Credential: webauthn.Credential{ID: []byte("canonical-credential")},
		Name:       "Canonical key",
	}
	legacyCredential := &mfa.PersistentCredential{
		Credential: webauthn.Credential{ID: []byte("legacy-credential")},
		Name:       "Legacy key",
	}

	seedAuth := newTestBackendPasswordAuth(username, "unused")
	if err := canonicalManager.SaveWebAuthnCredential(seedAuth, canonicalCredential); err != nil {
		t.Fatalf("seed canonical credential: %v", err)
	}

	if err := legacyManager.SaveWebAuthnCredential(seedAuth, legacyCredential); err != nil {
		t.Fatalf("seed legacy credential: %v", err)
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/webauthn/devices", nil)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
		definitions.SessionKeyUserBackend:     uint8(definitions.BackendTest),
		definitions.SessionKeyUserBackendName: legacyName,
	}})

	auth := &AuthState{deps: AuthDeps{Cfg: config.GetFile()}}
	auth.Request.HTTPClientContext = ctx
	auth.Request.Username = username
	auth.Request.Protocol = config.NewProtocol(definitions.ProtoIDP)
	auth.Runtime.UsedPassDBBackend = definitions.BackendTest
	auth.Runtime.BackendName = canonicalName

	credentials, err := auth.GetWebAuthnCredentialsFromSelectedBackend()
	if err != nil || len(credentials) != 1 || string(credentials[0].ID) != "canonical-credential" {
		t.Fatalf("selected backend credentials = %#v, err = %v", credentials, err)
	}

	added := &mfa.PersistentCredential{
		Credential: webauthn.Credential{ID: []byte("added-credential")},
		Name:       "Added key",
	}
	if err = auth.SaveWebAuthnCredentialToSelectedBackend(added); err != nil {
		t.Fatalf("save selected backend credential: %v", err)
	}

	updated := *canonicalCredential

	updated.Name = "Renamed canonical key"
	if err = auth.UpdateWebAuthnCredentialInSelectedBackend(canonicalCredential, &updated); err != nil {
		t.Fatalf("update selected backend credential: %v", err)
	}

	if err = auth.DeleteWebAuthnCredentialFromSelectedBackend(added); err != nil {
		t.Fatalf("delete selected backend credential: %v", err)
	}

	assertStoredWebAuthnCredentials(t, canonicalManager, seedAuth, []mfa.PersistentCredential{updated})
	assertStoredWebAuthnCredentials(t, legacyManager, seedAuth, []mfa.PersistentCredential{*legacyCredential})

	if cookie.GetManager(ctx) == nil {
		t.Fatal("test requires a stale legacy manager in the request context")
	}
}

func newTestBackendPasswordAuth(username, password string) *AuthState {
	auth := &AuthState{deps: AuthDeps{Cfg: config.GetFile()}}
	auth.Request.Username = username
	auth.Request.Password = secret.New(password)
	auth.Request.Protocol = config.NewProtocol("idp")

	return auth
}

func assertStoredWebAuthnCredentials(t *testing.T, manager BackendManager, auth *AuthState, expected []mfa.PersistentCredential) {
	t.Helper()

	credentials, err := manager.GetWebAuthnCredentials(auth)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials returned error: %v", err)
	}

	if len(credentials) != len(expected) {
		t.Fatalf("stored credential count = %d, want %d", len(credentials), len(expected))
	}

	for index := range expected {
		got := credentials[index]
		want := expected[index]

		if string(got.ID) != string(want.ID) {
			t.Fatalf("credential %d ID = %q, want %q", index, got.ID, want.ID)
		}

		if got.Name != want.Name {
			t.Fatalf("credential %d name = %q, want %q", index, got.Name, want.Name)
		}

		if got.Authenticator.SignCount != want.Authenticator.SignCount {
			t.Fatalf("credential %d sign count = %d, want %d", index, got.Authenticator.SignCount, want.Authenticator.SignCount)
		}

		if !got.LastUsed.Equal(want.LastUsed) {
			t.Fatalf("credential %d last_used = %s, want %s", index, got.LastUsed, want.LastUsed)
		}
	}
}
