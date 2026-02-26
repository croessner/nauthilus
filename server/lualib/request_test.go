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

package lualib

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

func TestSetStatusMessage(t *testing.T) {
	testCases := []struct {
		name          string
		initialStatus *string
		newStatus     string
	}{
		{
			name:          "NilInitialStatus",
			initialStatus: nil,
			newStatus:     "Testing status message",
		},
		{
			name:          "NonNilInitialStatus",
			initialStatus: new("Initial status message"),
			newStatus:     "New status message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			L.Push(lua.LString(tc.newStatus))

			lFunc := SetStatusMessage(&tc.initialStatus)
			lFunc(L)

			if tc.initialStatus == nil || *tc.initialStatus != tc.newStatus {
				t.Errorf("expected status to be %s, got %s", tc.newStatus, *tc.initialStatus)
			}
		})
	}
}

func TestCommonRequestResetIdPFields(t *testing.T) {
	cr := &CommonRequest{
		GrantType:               "authorization_code",
		OIDCClientName:          "Test Client",
		RedirectURI:             "https://example.com/callback",
		MFAMethod:               "totp",
		MFACompleted:            true,
		RequestedScopes:         []string{"openid", "profile"},
		UserGroups:              []string{"admins"},
		AllowedClientScopes:     []string{"openid", "email"},
		AllowedClientGrantTypes: []string{"authorization_code"},
	}

	cr.Reset()

	if cr.GrantType != "" {
		t.Errorf("expected GrantType to be empty, got %q", cr.GrantType)
	}

	if cr.OIDCClientName != "" {
		t.Errorf("expected OIDCClientName to be empty, got %q", cr.OIDCClientName)
	}

	if cr.RedirectURI != "" {
		t.Errorf("expected RedirectURI to be empty, got %q", cr.RedirectURI)
	}

	if cr.MFAMethod != "" {
		t.Errorf("expected MFAMethod to be empty, got %q", cr.MFAMethod)
	}

	if cr.MFACompleted {
		t.Error("expected MFACompleted to be false")
	}

	if cr.RequestedScopes != nil {
		t.Errorf("expected RequestedScopes to be nil, got %v", cr.RequestedScopes)
	}

	if cr.UserGroups != nil {
		t.Errorf("expected UserGroups to be nil, got %v", cr.UserGroups)
	}

	if cr.AllowedClientScopes != nil {
		t.Errorf("expected AllowedClientScopes to be nil, got %v", cr.AllowedClientScopes)
	}

	if cr.AllowedClientGrantTypes != nil {
		t.Errorf("expected AllowedClientGrantTypes to be nil, got %v", cr.AllowedClientGrantTypes)
	}
}

func TestCommonRequestSetupRequestIdPFields(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	cr := &CommonRequest{
		GrantType:               "authorization_code",
		OIDCClientName:          "My App",
		RedirectURI:             "https://app.example.com/cb",
		MFAMethod:               "webauthn",
		MFACompleted:            true,
		RequestedScopes:         []string{"openid", "profile", "email"},
		UserGroups:              []string{"developers", "admins"},
		AllowedClientScopes:     []string{"openid", "profile", "email", "groups"},
		AllowedClientGrantTypes: []string{"authorization_code", "refresh_token"},
	}

	request := L.NewTable()
	cr.SetupRequest(L, nil, request)

	// Verify string fields
	stringTests := []struct {
		key      string
		expected string
	}{
		{definitions.LuaRequestGrantType, "authorization_code"},
		{definitions.LuaRequestOIDCClientName, "My App"},
		{definitions.LuaRequestRedirectURI, "https://app.example.com/cb"},
		{definitions.LuaRequestMFAMethod, "webauthn"},
	}

	for _, st := range stringTests {
		val := request.RawGetString(st.key)

		if val.String() != st.expected {
			t.Errorf("key %q: expected %q, got %q", st.key, st.expected, val.String())
		}
	}

	// Verify MFACompleted bool
	mfaVal := request.RawGet(lua.LString(definitions.LuaRequestMFACompleted))
	if mfaVal != lua.LTrue {
		t.Errorf("expected MFACompleted to be true, got %v", mfaVal)
	}

	// Verify slice fields
	sliceTests := []struct {
		key      string
		expected []string
	}{
		{definitions.LuaRequestRequestedScopes, []string{"openid", "profile", "email"}},
		{definitions.LuaRequestUserGroups, []string{"developers", "admins"}},
		{definitions.LuaRequestAllowedClientScopes, []string{"openid", "profile", "email", "groups"}},
		{definitions.LuaRequestAllowedClientGrantTypes, []string{"authorization_code", "refresh_token"}},
	}

	for _, st := range sliceTests {
		tbl, ok := request.RawGetString(st.key).(*lua.LTable)
		if !ok {
			t.Errorf("key %q: expected table, got %T", st.key, request.RawGetString(st.key))

			continue
		}

		idx := 0

		tbl.ForEach(func(_ lua.LValue, v lua.LValue) {
			if idx < len(st.expected) && v.String() != st.expected[idx] {
				t.Errorf("key %q[%d]: expected %q, got %q", st.key, idx, st.expected[idx], v.String())
			}

			idx++
		})

		if idx != len(st.expected) {
			t.Errorf("key %q: expected %d elements, got %d", st.key, len(st.expected), idx)
		}
	}
}

func TestCommonRequestSetupRequestIdPFieldsEmpty(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	cr := &CommonRequest{}

	request := L.NewTable()
	cr.SetupRequest(L, nil, request)

	// Empty string fields should be present but empty
	if val := request.RawGetString(definitions.LuaRequestGrantType); val.String() != "" {
		t.Errorf("expected empty GrantType, got %q", val.String())
	}

	// MFACompleted should be false
	mfaVal := request.RawGet(lua.LString(definitions.LuaRequestMFACompleted))
	if mfaVal != lua.LFalse {
		t.Errorf("expected MFACompleted to be false, got %v", mfaVal)
	}

	// Slice fields should be empty tables
	tbl, ok := request.RawGetString(definitions.LuaRequestRequestedScopes).(*lua.LTable)
	if !ok {
		t.Fatalf("expected table for RequestedScopes, got %T", request.RawGetString(definitions.LuaRequestRequestedScopes))
	}

	if tbl.Len() != 0 {
		t.Errorf("expected empty RequestedScopes table, got length %d", tbl.Len())
	}
}

func TestCommonRequestPoolIdPFields(t *testing.T) {
	cr := GetCommonRequest()
	cr.GrantType = "device_code"
	cr.MFACompleted = true
	cr.RequestedScopes = []string{"openid"}
	cr.AllowedClientGrantTypes = []string{"device_code"}

	PutCommonRequest(cr)

	// After returning to pool, fields should be reset
	cr2 := GetCommonRequest()

	if cr2.GrantType != "" {
		t.Errorf("expected GrantType to be empty after pool return, got %q", cr2.GrantType)
	}

	if cr2.MFACompleted {
		t.Error("expected MFACompleted to be false after pool return")
	}

	if cr2.RequestedScopes != nil {
		t.Errorf("expected RequestedScopes to be nil after pool return, got %v", cr2.RequestedScopes)
	}

	PutCommonRequest(cr2)
}
