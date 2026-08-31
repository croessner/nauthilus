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
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func TestInitWebAuthnSkipsWhenIDPAndFrontendDisabled(t *testing.T) {
	env := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(env)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
	}
	config.SetTestFile(cfg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := HTTPDeps{
		Cfg:    config.GetFile(),
		Logger: logger,
		Env:    env,
	}

	if err := NewDefaultBootstrap(deps).InitWebAuthn(); err != nil {
		t.Fatalf("expected InitWebAuthn to skip without error, got %v", err)
	}
}

func TestNewWebAuthnConfigCarriesAuthenticatorSelection(t *testing.T) {
	idpCfg := &config.IDPSection{
		WebAuthn: config.WebAuthn{
			AuthenticatorAttachment: "cross-platform",
			ResidentKey:             "preferred",
			UserVerification:        "required",
		},
	}

	runtimeCfg := newWebAuthnConfig(idpCfg, "login.example.test", []string{"https://login.example.test"})

	assert.Equal(t, protocol.CrossPlatform, runtimeCfg.AuthenticatorSelection.AuthenticatorAttachment)
	assert.Equal(t, protocol.ResidentKeyRequirementPreferred, runtimeCfg.AuthenticatorSelection.ResidentKey)
	assert.Equal(t, protocol.VerificationRequired, runtimeCfg.AuthenticatorSelection.UserVerification)

	if assert.NotNil(t, runtimeCfg.AuthenticatorSelection.RequireResidentKey) {
		assert.False(t, *runtimeCfg.AuthenticatorSelection.RequireResidentKey)
	}
}

func TestNewWebAuthnConfigUsesStrictWebAuthnPolicies(t *testing.T) {
	idpCfg := &config.IDPSection{
		WebAuthn: config.WebAuthn{RPDisplayName: "Nauthilus"},
	}

	tests := []struct {
		name    string
		rpID    string
		origins []string
		wantErr bool
	}{
		{
			name:    "valid domain",
			rpID:    "login.example.test",
			origins: []string{"https://login.example.test"},
		},
		{
			name:    "IP address",
			rpID:    "127.0.0.1",
			origins: []string{"http://127.0.0.1"},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtimeCfg := newWebAuthnConfig(idpCfg, test.rpID, test.origins)

			assert.Equal(t, protocol.UnsolicitedOutputPolicyReject, runtimeCfg.ExtensionsUnsolicitedOutputPolicy)

			_, err := webauthn.New(runtimeCfg)
			if test.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
		})
	}
}
