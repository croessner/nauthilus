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
)

const (
	testMasterUserTargetAccount = "alice@example.test"
	testMasterUserAdminAccount  = "admin@example.test"
	testMasterUserFormattedName = testMasterUserTargetAccount + "*" + testMasterUserAdminAccount
	testMasterUserBoundedFormat = "login:{user}|via:{master_user}"
	testMasterUserBoundedName   = "login:" + testMasterUserTargetAccount + "|via:" + testMasterUserAdminAccount
)

func TestParseMasterUserIdentityUsesConfiguredUserFormat(t *testing.T) {
	testCases := []struct {
		name           string
		masterUser     config.MasterUser
		username       string
		wantTargetUser string
		wantMasterUser string
		wantActive     bool
	}{
		{
			name: "default format",
			masterUser: config.MasterUser{
				Enabled:    true,
				UserFormat: config.DefaultMasterUserFormat,
			},
			username:       testMasterUserFormattedName,
			wantTargetUser: testMasterUserTargetAccount,
			wantMasterUser: testMasterUserAdminAccount,
			wantActive:     true,
		},
		{
			name: "custom format",
			masterUser: config.MasterUser{
				Enabled:    true,
				UserFormat: testMasterUserBoundedFormat,
			},
			username:       testMasterUserBoundedName,
			wantTargetUser: testMasterUserTargetAccount,
			wantMasterUser: testMasterUserAdminAccount,
			wantActive:     true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertMasterUserIdentity(t, testCase.username, &testCase.masterUser, testCase.wantTargetUser, testCase.wantMasterUser, testCase.wantActive)
		})
	}
}

func TestParseMasterUserIdentityRejectsInactiveOrAmbiguousInput(t *testing.T) {
	testCases := []struct {
		name       string
		masterUser config.MasterUser
		username   string
	}{
		{
			name: "disabled",
			masterUser: config.MasterUser{
				Enabled:    false,
				UserFormat: config.DefaultMasterUserFormat,
			},
			username: testMasterUserFormattedName,
		},
		{
			name: "ambiguous username",
			masterUser: config.MasterUser{
				Enabled:    true,
				UserFormat: config.DefaultMasterUserFormat,
			},
			username: testMasterUserTargetAccount + "*team*" + testMasterUserAdminAccount,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertMasterUserIdentity(t, testCase.username, &testCase.masterUser, "", "", false)
		})
	}
}

// assertMasterUserIdentity checks the core parser wrapper without duplicating field assertions.
func assertMasterUserIdentity(
	t *testing.T,
	username string,
	masterUser *config.MasterUser,
	wantTargetUser string,
	wantMasterUser string,
	wantActive bool,
) {
	t.Helper()

	identity := parseMasterUserIdentity(username, masterUser)
	if identity.active != wantActive {
		t.Fatalf("active = %v, want %v", identity.active, wantActive)
	}

	if identity.targetUser != wantTargetUser {
		t.Fatalf("target user = %q, want %q", identity.targetUser, wantTargetUser)
	}

	if identity.masterUser != wantMasterUser {
		t.Fatalf("master user = %q, want %q", identity.masterUser, wantMasterUser)
	}
}
