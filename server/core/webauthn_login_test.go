// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"errors"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func TestConfiguredWebAuthnUserVerificationReachesLoginOptions(t *testing.T) {
	originalWebAuthn := webAuthn

	t.Cleanup(func() { webAuthn = originalWebAuthn })

	idpCfg := &config.IDPSection{WebAuthn: config.WebAuthn{
		ResidentKey: "preferred", UserVerification: "required",
	}}
	configuredWebAuthn, err := webauthn.New(newWebAuthnConfig(
		idpCfg, "login.example.test", []string{"https://login.example.test"},
	))
	if !assert.NoError(t, err) {
		return
	}

	webAuthn = configuredWebAuthn
	user := &backend.User{
		ID: "user-id", Name: "alice",
		Credentials: []mfa.PersistentCredential{{
			Credential: webauthn.Credential{ID: []byte("credential-id")},
		}},
	}
	for _, testCase := range []struct {
		name string
		user *backend.User
	}{
		{name: "user-bound", user: user},
		{name: "discoverable", user: nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options, sessionData, beginErr := beginWebAuthnLoginOptions(testCase.user)
			if !assert.NoError(t, beginErr) {
				return
			}

			assert.Equal(t, protocol.VerificationRequired, options.Response.UserVerification)
			assert.Equal(t, protocol.VerificationRequired, sessionData.UserVerification)
		})
	}
}

func TestPersistWebAuthnLoginUpdateFailsClosedOnRejectedPersistence(t *testing.T) {
	persistenceErr := errors.New("authority rejected WebAuthn update")
	user := &backend.User{
		ID: "uid-123", Name: "testuser-closed",
		Credentials: []mfa.PersistentCredential{{
			Credential: webauthn.Credential{
				ID: []byte("device-a"), Authenticator: webauthn.Authenticator{SignCount: 3},
			},
			Name: "Security key",
		}},
	}
	oldCredential := user.Credentials[0]
	newCredential := oldCredential
	newCredential.Authenticator.SignCount = 4
	store := failingWebAuthnCredentialUpdater{err: persistenceErr}

	err := persistWebAuthnLoginUpdate(store, user, &oldCredential, &newCredential)
	if !errors.Is(err, persistenceErr) {
		t.Fatalf("persistWebAuthnLoginUpdate() error = %v, want %v", err, persistenceErr)
	}
	if got := user.Credentials[0].Authenticator.SignCount; got != 3 {
		t.Fatalf("cached credential sign count = %d, want unchanged 3", got)
	}
}

type failingWebAuthnCredentialUpdater struct{ err error }

func (u failingWebAuthnCredentialUpdater) UpdateWebAuthnCredential(
	*mfa.PersistentCredential,
	*mfa.PersistentCredential,
) error {
	return u.err
}

func TestUpdateWebAuthnCredentialAfterLoginKeepsDeviceData(t *testing.T) {
	now := time.Date(2026, time.January, 30, 12, 0, 0, 0, time.UTC)
	credentials := []mfa.PersistentCredential{
		{
			Credential: webauthn.Credential{
				ID: []byte("device-a"), Authenticator: webauthn.Authenticator{SignCount: 3},
			},
			Name: "TouchID", LastUsed: time.Date(2026, time.January, 29, 10, 0, 0, 0, time.UTC),
		},
		{
			Credential: webauthn.Credential{
				ID: []byte("device-b"), Authenticator: webauthn.Authenticator{SignCount: 0},
			},
			Name: "YubiKey", LastUsed: time.Date(2026, time.January, 28, 11, 0, 0, 0, time.UTC),
		},
	}
	loginCredential := &webauthn.Credential{
		ID: []byte("device-b"), Authenticator: webauthn.Authenticator{SignCount: 6},
	}

	oldCredential, updatedCredential := updateWebAuthnCredentialAfterLogin(credentials, loginCredential, now)
	if assert.NotNil(t, oldCredential) && assert.NotNil(t, updatedCredential) {
		assert.Equal(t, "YubiKey", oldCredential.Name)
		assert.Equal(t, "YubiKey", updatedCredential.Name)
		assert.Equal(t, uint32(6), updatedCredential.Authenticator.SignCount)
		assert.Equal(t, now, updatedCredential.LastUsed)
		assert.Equal(t, []byte("device-b"), updatedCredential.ID)
	}
}

func TestUpdateWebAuthnCredentialAfterLoginRejectsStaleSignCount(t *testing.T) {
	now := time.Date(2026, time.January, 30, 12, 0, 0, 0, time.UTC)
	credentials := []mfa.PersistentCredential{{
		Credential: webauthn.Credential{
			ID: []byte("device-a"), Authenticator: webauthn.Authenticator{SignCount: 7},
		},
		Name: "Security key", LastUsed: time.Date(2026, time.January, 29, 10, 0, 0, 0, time.UTC),
	}}
	loginCredential := &webauthn.Credential{
		ID: []byte("device-a"), Authenticator: webauthn.Authenticator{SignCount: 7},
	}

	oldCredential, updatedCredential := updateWebAuthnCredentialAfterLogin(credentials, loginCredential, now)
	assert.Nil(t, oldCredential)
	assert.Nil(t, updatedCredential)
}
