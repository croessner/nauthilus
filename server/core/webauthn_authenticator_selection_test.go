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
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
)

func TestBuildAuthenticatorSelection(t *testing.T) {
	for _, tt := range authenticatorSelectionCases() {
		t.Run(tt.name, func(t *testing.T) {
			assertAuthenticatorSelectionCase(t, tt)
		})
	}
}

type authenticatorSelectionCase struct {
	name                   string
	webAuthnCfg            config.WebAuthn
	wantAttachment         protocol.AuthenticatorAttachment
	wantResidentKey        protocol.ResidentKeyRequirement
	wantUserVerification   protocol.UserVerificationRequirement
	wantRequireResidentKey bool
}

// authenticatorSelectionCases returns WebAuthn selection mapping fixtures.
func authenticatorSelectionCases() []authenticatorSelectionCase {
	return []authenticatorSelectionCase{
		{
			name:                   "defaults (empty config)",
			webAuthnCfg:            config.WebAuthn{},
			wantAttachment:         "",
			wantResidentKey:        protocol.ResidentKeyRequirementDiscouraged,
			wantUserVerification:   protocol.VerificationPreferred,
			wantRequireResidentKey: false,
		},
		{
			name: "platform attachment with passkey (resident key required)",
			webAuthnCfg: config.WebAuthn{
				AuthenticatorAttachment: "platform",
				ResidentKey:             "required",
				UserVerification:        "required",
			},
			wantAttachment:         protocol.Platform,
			wantResidentKey:        protocol.ResidentKeyRequirementRequired,
			wantUserVerification:   protocol.VerificationRequired,
			wantRequireResidentKey: true,
		},
		{
			name: "cross-platform attachment",
			webAuthnCfg: config.WebAuthn{
				AuthenticatorAttachment: "cross-platform",
				ResidentKey:             "preferred",
				UserVerification:        "discouraged",
			},
			wantAttachment:         protocol.CrossPlatform,
			wantResidentKey:        protocol.ResidentKeyRequirementPreferred,
			wantUserVerification:   protocol.VerificationDiscouraged,
			wantRequireResidentKey: false,
		},
		{
			name: "no attachment preference with discouraged resident key",
			webAuthnCfg: config.WebAuthn{
				ResidentKey:      "discouraged",
				UserVerification: "preferred",
			},
			wantAttachment:         "",
			wantResidentKey:        protocol.ResidentKeyRequirementDiscouraged,
			wantUserVerification:   protocol.VerificationPreferred,
			wantRequireResidentKey: false,
		},
	}
}

// assertAuthenticatorSelectionCase verifies one WebAuthn selection mapping.
func assertAuthenticatorSelectionCase(t *testing.T, tt authenticatorSelectionCase) {
	t.Helper()

	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
		IDP: &config.IDPSection{
			WebAuthn: tt.webAuthnCfg,
		},
	}
	config.SetTestFile(cfg)

	result := buildAuthenticatorSelection(config.GetFile())

	assert.Equal(t, tt.wantAttachment, result.AuthenticatorAttachment)
	assert.Equal(t, tt.wantResidentKey, result.ResidentKey)
	assert.Equal(t, tt.wantUserVerification, result.UserVerification)

	if tt.wantRequireResidentKey {
		assert.NotNil(t, result.RequireResidentKey)
		assert.True(t, *result.RequireResidentKey)
	} else {
		assert.NotNil(t, result.RequireResidentKey)
		assert.False(t, *result.RequireResidentKey)
	}
}

func TestMapResidentKey(t *testing.T) {
	assertWebAuthnRequirementMapping(t, mapResidentKey, []webAuthnRequirementCase[protocol.ResidentKeyRequirement]{
		{input: "discouraged", want: protocol.ResidentKeyRequirementDiscouraged},
		{input: "preferred", want: protocol.ResidentKeyRequirementPreferred},
		{input: "required", want: protocol.ResidentKeyRequirementRequired},
		{input: "", want: protocol.ResidentKeyRequirementDiscouraged},
		{input: "invalid", want: protocol.ResidentKeyRequirementDiscouraged},
	})
}

func TestMapUserVerification(t *testing.T) {
	assertWebAuthnRequirementMapping(t, mapUserVerification, []webAuthnRequirementCase[protocol.UserVerificationRequirement]{
		{input: "discouraged", want: protocol.VerificationDiscouraged},
		{input: "preferred", want: protocol.VerificationPreferred},
		{input: "required", want: protocol.VerificationRequired},
		{input: "", want: protocol.VerificationPreferred},
		{input: "invalid", want: protocol.VerificationPreferred},
	})
}

type webAuthnRequirementCase[T comparable] struct {
	input string
	want  T
}

// assertWebAuthnRequirementMapping verifies string-to-WebAuthn-requirement mapping tables.
func assertWebAuthnRequirementMapping[T comparable](t *testing.T, mapValue func(string) T, cases []webAuthnRequirementCase[T]) {
	t.Helper()

	for _, testCase := range cases {
		t.Run(testCase.input, func(t *testing.T) {
			assert.Equal(t, testCase.want, mapValue(testCase.input))
		})
	}
}
