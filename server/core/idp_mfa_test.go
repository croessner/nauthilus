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
	assert.Empty(t, mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAAccount, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFADisplayName, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorUniqueUserID, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorDisplayName, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyMFAFactorRemoteBackendRefToken, ""))
}
