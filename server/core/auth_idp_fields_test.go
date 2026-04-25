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
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

// TestFillIdPFieldsPopulatesUserGroupsFromState verifies that fillIdPFields populates the
// UserGroups field in the CommonRequest from the AuthState.
func TestFillIdPFieldsPopulatesUserGroupsFromState(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(nil)

	auth := &AuthState{
		Request: AuthRequest{
			HTTPClientContext: ctx,
		},
	}
	auth.SetResolvedGroups([]string{"team-b", "team-a"}, nil)

	request := &lualib.CommonRequest{}
	auth.fillIdPFields(request)

	assert.Equal(t, []string{"team-a", "team-b"}, request.UserGroups)
}

// TestFillIdPFieldsUsesEmptyUserGroupsWhenNotSet ensures that fillIdPFields handles the case
// where no groups are resolved in the AuthState.
func TestFillIdPFieldsUsesEmptyUserGroupsWhenNotSet(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(nil)

	auth := &AuthState{
		Request: AuthRequest{
			HTTPClientContext: ctx,
		},
	}

	request := &lualib.CommonRequest{}
	auth.fillIdPFields(request)

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

	setAuthenticationFields(auth, &authdto.Request{
		Username:          "user@example.test",
		ExternalSessionID: testExternalSessionID,
	})

	assert.Equal(t, testExternalSessionID, auth.Request.ExternalSessionID)
	assert.Equal(t, testExternalSessionID, ctx.GetString(definitions.CtxExternalSessionKey))
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
