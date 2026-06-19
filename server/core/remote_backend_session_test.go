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

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/stretchr/testify/assert"
)

const (
	testRemoteBackendRefType      = "remote"
	testRemoteBackendRefName      = "default"
	testRemoteBackendRefAuthority = "authority"
	testTargetBackendRefToken     = "target-ref"
	testMasterBackendRefToken     = "master-ref"
)

func TestRestoreRemoteBackendRefFromSession(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		expectedToken string
	}{
		{
			name:          "prefers factor ref for factor account",
			username:      testWebAuthnMasterLogin,
			expectedToken: testMasterBackendRefToken,
		},
		{
			name:          "keeps target ref for other accounts",
			username:      testWebAuthnTargetLogin,
			expectedToken: testTargetBackendRefToken,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			auth := &AuthState{}
			auth.Request.Username = testCase.username

			auth.restoreRemoteBackendRefFromSession(newRemoteBackendRefSessionManager())

			assert.Equal(t, testCase.expectedToken, auth.Runtime.RemoteBackendRef.OpaqueToken)
		})
	}
}

func TestRestoreRemoteBackendRefFromSessionKeepsExplicitRef(t *testing.T) {
	auth := &AuthState{}
	auth.Request.Username = testWebAuthnMasterLogin
	auth.Runtime.RemoteBackendRef = RemoteBackendRef{
		Type:        testRemoteBackendRefType,
		Name:        testRemoteBackendRefName,
		Protocol:    definitions.ProtoOIDC,
		Authority:   testRemoteBackendRefAuthority,
		OpaqueToken: "explicit-factor-ref",
	}

	auth.restoreRemoteBackendRefFromSession(newRemoteBackendRefSessionManager())

	assert.Equal(t, "explicit-factor-ref", auth.Runtime.RemoteBackendRef.OpaqueToken)
}

func newRemoteBackendRefSessionManager() *mockCookieManager {
	return &mockCookieManager{data: map[string]any{
		definitions.SessionKeyRemoteBackendRefType:               testRemoteBackendRefType,
		definitions.SessionKeyRemoteBackendRefName:               testRemoteBackendRefName,
		definitions.SessionKeyRemoteBackendRefProtocol:           definitions.ProtoOIDC,
		definitions.SessionKeyRemoteBackendRefAuthority:          testRemoteBackendRefAuthority,
		definitions.SessionKeyRemoteBackendRefToken:              testTargetBackendRefToken,
		definitions.SessionKeyMFAFactorAccount:                   testWebAuthnMasterLogin,
		definitions.SessionKeyMFAFactorRemoteBackendRefType:      testRemoteBackendRefType,
		definitions.SessionKeyMFAFactorRemoteBackendRefName:      testRemoteBackendRefName,
		definitions.SessionKeyMFAFactorRemoteBackendRefProtocol:  definitions.ProtoOIDC,
		definitions.SessionKeyMFAFactorRemoteBackendRefAuthority: testRemoteBackendRefAuthority,
		definitions.SessionKeyMFAFactorRemoteBackendRefToken:     testMasterBackendRefToken,
	}}
}
