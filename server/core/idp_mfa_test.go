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
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/stretchr/testify/assert"
)

const (
	testIDPMFATargetLogin    = "target@example.test"
	testIDPMFAMasterLogin    = "master@example.test"
	testIDPMFAFormattedLogin = testIDPMFATargetLogin + "*" + testIDPMFAMasterLogin
	testIDPMFATargetUniqueID = "target-uid"
	testIDPMFAMasterUniqueID = "master-uid"
	testIDPMFATargetDisplay  = "Target User"
	testIDPMFAMasterDisplay  = "Master User"
	testIDPMFAFactorRefToken = "master-ref"
	testIDPMFAOIDCClientID   = "oidc-client"
)

func TestStoreCompletedIDPMFASessionUsesCanonicalMFAIdentity(t *testing.T) {
	before := time.Now().Unix()
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyUsername:                       testIDPMFAFormattedLogin,
		definitions.SessionKeyMFAAccount:                     testIDPMFATargetLogin,
		definitions.SessionKeyUniqueUserID:                   testIDPMFATargetUniqueID,
		definitions.SessionKeyMFADisplayName:                 testIDPMFATargetDisplay,
		definitions.SessionKeyMFAFactorAccount:               testIDPMFAMasterLogin,
		definitions.SessionKeyMFAFactorUniqueUserID:          testIDPMFAMasterUniqueID,
		definitions.SessionKeyMFAFactorDisplayName:           testIDPMFAMasterDisplay,
		definitions.SessionKeyMFAFactorRemoteBackendRefToken: testIDPMFAFactorRefToken,
		definitions.SessionKeyProtocol:                       definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:                    testIDPMFAOIDCClientID,
		definitions.SessionKeyHaveTOTP:                       true,
	}}

	StoreCompletedIDPMFASession(mgr, &backend.User{
		ID:          testIDPMFATargetUniqueID,
		Name:        testIDPMFAFormattedLogin,
		DisplayName: "Master formatted login",
	}, definitions.MFAMethodWebAuthn)

	assert.Equal(t, testIDPMFATargetLogin, mgr.GetString(definitions.SessionKeyAccount, ""))
	assert.Equal(t, testIDPMFATargetUniqueID, mgr.GetString(definitions.SessionKeySubject, ""))
	assert.Equal(t, testIDPMFATargetUniqueID, mgr.GetString(definitions.SessionKeyUniqueUserID, ""))
	assert.Equal(t, testIDPMFATargetDisplay, mgr.GetString(definitions.SessionKeyDisplayName, ""))
	assert.Equal(t, definitions.ProtoOIDC, mgr.GetString(definitions.SessionKeyProtocol, ""))
	assert.True(t, mgr.GetBool(definitions.SessionKeyMFACompleted, false))
	assert.Equal(t, definitions.MFAMethodWebAuthn, mgr.GetString(definitions.SessionKeyMFAMethod, ""))
	assert.Equal(t, definitions.MFAMethodWebAuthn, mgr.GetString(definitions.SessionKeyMFAAssuranceMethod, ""))
	assert.GreaterOrEqual(t, mgr.GetInt64(definitions.SessionKeyMFAAssuranceAt, 0), before)
	assert.LessOrEqual(t, mgr.GetInt64(definitions.SessionKeyMFAAssuranceAt, 0), time.Now().Unix())
	assert.Equal(t, definitions.ProtoOIDC+":"+testIDPMFAOIDCClientID, mgr.GetString(definitions.SessionKeyMFAAssuranceScope, ""))
	assert.True(t, mgr.GetBool(definitions.SessionKeyHaveTOTP, false))
	assert.True(t, mgr.GetBool(definitions.SessionKeyHaveWebAuthn, false))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAAccount, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFADisplayName, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorUniqueUserID, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorDisplayName, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorRemoteBackendRefToken, ""))
}

func TestStoreCompletedIDPMFASessionStoresDefaultAssuranceLevels(t *testing.T) {
	tests := []struct {
		name             string
		method           string
		expectedMethod   string
		expectedMFAKey   string
		expectedMFAlevel int
	}{
		{
			name:             "totp stores level two",
			method:           definitions.MFAMethodTOTP,
			expectedMethod:   definitions.MFAMethodTOTP,
			expectedMFAKey:   definitions.MFAMethodTOTP,
			expectedMFAlevel: 2,
		},
		{
			name:             "webauthn stores level three",
			method:           definitions.MFAMethodWebAuthn,
			expectedMethod:   definitions.MFAMethodWebAuthn,
			expectedMFAKey:   definitions.MFAMethodWebAuthn,
			expectedMFAlevel: 3,
		},
		{
			name:             "recovery stores level one",
			method:           "recovery",
			expectedMethod:   definitions.MFAMethodRecoveryCodes,
			expectedMFAKey:   definitions.MFAMethodRecoveryCodes,
			expectedMFAlevel: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyProtocol: definitions.ProtoOIDC,
			}}

			StoreCompletedIDPMFASession(mgr, &backend.User{
				ID:   "uid-user",
				Name: "user@example.test",
			}, tt.method)

			assert.Equal(t, tt.expectedMethod, mgr.GetString(definitions.SessionKeyMFAAssuranceMethod, ""))
			assert.Equal(t, tt.expectedMFAKey, mgr.GetString(definitions.SessionKeyMFAMethod, ""))
			assert.Equal(t, tt.expectedMFAlevel, mgr.GetInt(definitions.SessionKeyMFAAssuranceLevel, 0))
		})
	}
}

func TestStoreCompletedIDPMFASessionUsesEffectivePolicyLevel(t *testing.T) {
	setTestIDPMFAPolicyConfig(t)

	t.Run("oidc client override", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyProtocol:    definitions.ProtoOIDC,
			definitions.SessionKeyIDPClientID: testIDPMFAOIDCClientID,
		}}

		StoreCompletedIDPMFASession(mgr, &backend.User{
			ID:   "uid-user",
			Name: "user@example.test",
		}, definitions.MFAMethodWebAuthn)

		assert.Equal(t, 2, mgr.GetInt(definitions.SessionKeyMFAAssuranceLevel, 0))
	})

	t.Run("saml service provider override", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyProtocol:        definitions.ProtoSAML,
			definitions.SessionKeyIDPSAMLEntityID: "saml-sp",
		}}

		StoreCompletedIDPMFASession(mgr, &backend.User{
			ID:   "uid-user",
			Name: "user@example.test",
		}, definitions.MFAMethodRecoveryCodes)

		assert.Equal(t, 4, mgr.GetInt(definitions.SessionKeyMFAAssuranceLevel, 0))
	})
}

// setTestIDPMFAPolicyConfig installs a temporary IDP policy config for assurance tests.
func setTestIDPMFAPolicyConfig(t *testing.T) {
	t.Helper()

	previousConfigLoaded := config.IsFileLoaded()

	var previousConfig config.File
	if previousConfigLoaded {
		previousConfig = config.GetFile()
	}

	config.SetTestFile(testIDPMFAPolicyConfig())

	t.Cleanup(func() {
		if previousConfigLoaded {
			config.SetTestFile(previousConfig)

			return
		}

		config.SetTestFile(nil)
	})
}

// testIDPMFAPolicyConfig returns the effective-policy fixture for IDP MFA tests.
func testIDPMFAPolicyConfig() *config.FileSettings {
	return &config.FileSettings{
		IDP: &config.IDPSection{
			MFAPolicy: config.MFAPolicy{
				Levels: map[string]int{
					definitions.MFAMethodRecoveryCodes: 1,
					definitions.MFAMethodTOTP:          2,
					definitions.MFAMethodWebAuthn:      3,
				},
			},
			OIDC: config.OIDCConfig{
				Clients: []config.OIDCClient{
					{
						ClientID: testIDPMFAOIDCClientID,
						MFAPolicy: config.MFAPolicy{
							Levels: map[string]int{
								definitions.MFAMethodWebAuthn: 2,
							},
						},
					},
				},
			},
			SAML2: config.SAML2Config{
				ServiceProviders: []config.SAML2ServiceProvider{
					{
						EntityID: "saml-sp",
						ACSURL:   "https://sp.example.test/acs",
						MFAPolicy: config.MFAPolicy{
							Levels: map[string]int{
								definitions.MFAMethodRecoveryCodes: 4,
							},
						},
					},
				},
			},
		},
	}
}
