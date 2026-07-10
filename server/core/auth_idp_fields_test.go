// Copyright (C) 2024 Christian Rößner
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
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

func TestProcessPassDBResultPreservesEmptyIdentityFieldsAndClearsFoundUserGroups(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/idp/user", nil)
	auth := NewAuthStateFromContextWithDeps(ctx, setupAuthDeps()).(*AuthState)
	auth.Request.Username = "subject@example.test"
	passDB := &PassDBMap{backend: definitions.BackendPlugin}

	initial := &PassDBResult{
		UserFound:               true,
		Account:                 "subject@example.test",
		UniqueUserIDField:       "entryUUID",
		DisplayNameField:        "displayName",
		TOTPSecretField:         "totpSecret",
		TOTPRecoveryField:       "totpRecovery",
		Groups:                  []string{"group-b", "group-a"},
		GroupDistinguishedNames: []string{"cn=group-b,dc=example,dc=test", "cn=group-a,dc=example,dc=test"},
		Backend:                 definitions.BackendPlugin,
	}
	if err := ProcessPassDBResult(ctx, initial, auth, passDB); err != nil {
		t.Fatalf("ProcessPassDBResult(initial) error = %v", err)
	}

	assertRuntimeIdentityFields(t, auth, initial)
	assert.Equal(t, []string{"group-a", "group-b"}, auth.GetGroups())
	assert.Equal(t, []string{"cn=group-a,dc=example,dc=test", "cn=group-b,dc=example,dc=test"}, auth.GetGroupDistinguishedNames())

	empty := &PassDBResult{UserFound: true, Backend: definitions.BackendPlugin}
	if err := ProcessPassDBResult(ctx, empty, auth, passDB); err != nil {
		t.Fatalf("ProcessPassDBResult(empty) error = %v", err)
	}

	assertRuntimeIdentityFields(t, auth, initial)
	assert.Empty(t, auth.GetGroups())
	assert.Empty(t, auth.GetGroupDistinguishedNames())
}

// assertRuntimeIdentityFields verifies non-empty identity field names remain installed.
func assertRuntimeIdentityFields(t *testing.T, auth *AuthState, expected *PassDBResult) {
	t.Helper()

	assert.Equal(t, expected.UniqueUserIDField, auth.Runtime.UniqueUserIDField)
	assert.Equal(t, expected.DisplayNameField, auth.Runtime.DisplayNameField)
	assert.Equal(t, expected.TOTPSecretField, auth.Runtime.TOTPSecretField)
	assert.Equal(t, expected.TOTPRecoveryField, auth.Runtime.TOTPRecoveryField)
}

// TestFillIDPFieldsPopulatesUserGroupsFromState verifies that fillIDPFields populates the
// UserGroups field in the CommonRequest from the AuthState.
func TestFillIDPFieldsPopulatesUserGroupsFromState(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(nil)

	auth := &AuthState{
		Request: AuthRequest{
			HTTPClientContext: ctx,
		},
	}
	auth.SetResolvedGroups([]string{"team-b", "team-a"}, nil)

	request := &lualib.CommonRequest{}
	auth.fillIDPFields(request)

	assert.Equal(t, []string{"team-a", "team-b"}, request.UserGroups)
}

// TestFillIDPFieldsUsesEmptyUserGroupsWhenNotSet ensures that fillIDPFields handles the case
// where no groups are resolved in the AuthState.
func TestFillIDPFieldsUsesEmptyUserGroupsWhenNotSet(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(nil)

	auth := &AuthState{
		Request: AuthRequest{
			HTTPClientContext: ctx,
		},
	}

	request := &lualib.CommonRequest{}
	auth.fillIDPFields(request)

	assert.Nil(t, request.UserGroups)
}

func TestApplyContextDataStoresExternalSessionInAuthStateAndGinContext(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(nil)

	auth := &AuthState{
		Request: AuthRequest{
			HTTPClientContext: ctx,
		},
	}

	auth.ApplyContextData(NewAuthContext(WithExternalSessionID(" " + testExternalSessionID + " ")))

	assert.Equal(t, testExternalSessionID, auth.Request.ExternalSessionID)
	assert.Equal(t, testExternalSessionID, ctx.GetString(definitions.CtxExternalSessionKey))
}

func TestSetAuthenticationFieldsMapsExternalSessionFromJSONRequest(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(nil)
	auth := &AuthState{
		Request: AuthRequest{
			HTTPClientContext: ctx,
		},
	}

	ApplyStructuredAuthRequest(auth, &authdto.Request{
		Username:          "user@example.test",
		ExternalSessionID: testExternalSessionID,
	})

	assert.Equal(t, testExternalSessionID, auth.Request.ExternalSessionID)
	assert.Equal(t, testExternalSessionID, ctx.GetString(definitions.CtxExternalSessionKey))
}

func TestSetAuthenticationFieldsMapsLoginAttemptFromJSONRequest(t *testing.T) {
	setupMinimalTestConfig(t)

	auth := &AuthState{deps: setupAuthDeps()}

	ApplyStructuredAuthRequest(auth, &authdto.Request{
		Username:         "user@example.test",
		AuthLoginAttempt: 3,
	})

	assert.Equal(t, uint(2), auth.Security.LoginAttempts)
	assert.Equal(t, uint(2), auth.GetFailCount())
}

func TestCommonRequestSetupRequestIncludesExternalSession(t *testing.T) {
	t.Parallel()

	L := lua.NewState()
	defer L.Close()

	request := L.NewTable()
	commonRequest := &lualib.CommonRequest{
		Session:           "guid-1",
		ExternalSessionID: testExternalSessionID,
	}

	commonRequest.SetupRequest(L, nil, request)

	assert.Equal(t, lua.LString(testExternalSessionID), request.RawGetString(definitions.LuaRequestExternalSession))
}

func TestFillCommonRequestIncludesAuthLoginAttempt(t *testing.T) {
	setupMinimalTestConfig(t)

	auth := &AuthState{
		deps: setupAuthDeps(),
		Request: AuthRequest{
			Protocol: config.NewProtocol("imap"),
		},
	}
	auth.Request.AuthLoginAttempt = 4

	request := &lualib.CommonRequest{}
	auth.FillCommonRequest(request)

	assert.Equal(t, uint(4), request.AuthLoginAttempt)
}
