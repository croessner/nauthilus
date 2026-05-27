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

package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const (
	testMasterUserFormatNameDefaultTargetFirst = "default target first"
	testMasterUserFormatNameMasterFirst        = "master first"
	testMasterUserFormatNameStaticBounded      = "static prefix and suffix"
	testMasterUserFormatMasterFirst            = "{master_user}*{user}"
	testMasterUserFormatStaticBounded          = "login:{user}|via:{master_user}:done"
	testMasterUserFormatAdjacent               = "{user}{master_user}"
	testMasterUserTargetAccount                = "alice@example.test"
	testMasterUserAdminAccount                 = "admin@example.test"
	testMasterUserDefaultLogin                 = testMasterUserTargetAccount + "*" + testMasterUserAdminAccount
	testMasterUserCustomSeparatorLogin         = testMasterUserTargetAccount + "#" + testMasterUserAdminAccount
	testMasterUserMasterFirstLogin             = testMasterUserAdminAccount + "*" + testMasterUserTargetAccount
	testMasterUserStaticBoundedLogin           = "login:" + testMasterUserTargetAccount + "|via:" + testMasterUserAdminAccount + ":done"
)

func TestMasterUserDefaultFormat(t *testing.T) {
	cfg := &FileSettings{
		Server: &ServerSection{
			MasterUser: MasterUser{Enabled: true},
		},
	}

	if err := cfg.setDefaultMasterUserFormat(); err != nil {
		t.Fatalf("setDefaultMasterUserFormat() error = %v", err)
	}

	if got := cfg.GetServer().GetMasterUser().GetUserFormat(); got != DefaultMasterUserFormat {
		t.Fatalf("user format = %q, want %q", got, DefaultMasterUserFormat)
	}
}

func TestMasterUserFormatValidation(t *testing.T) {
	testCases := []struct {
		name       string
		userFormat string
		want       bool
	}{
		{
			name:       testMasterUserFormatNameDefaultTargetFirst,
			userFormat: DefaultMasterUserFormat,
			want:       true,
		},
		{
			name:       testMasterUserFormatNameMasterFirst,
			userFormat: testMasterUserFormatMasterFirst,
			want:       true,
		},
		{
			name:       testMasterUserFormatNameStaticBounded,
			userFormat: testMasterUserFormatStaticBounded,
			want:       true,
		},
		{
			name:       "missing separator",
			userFormat: testMasterUserFormatAdjacent,
			want:       false,
		},
		{
			name:       "missing master placeholder",
			userFormat: "{user}*",
			want:       false,
		},
		{
			name:       "duplicate master placeholder",
			userFormat: "{user}*{master_user}*{master_user}",
			want:       false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ValidMasterUserFormat(testCase.userFormat); got != testCase.want {
				t.Fatalf("ValidMasterUserFormat(%q) = %v, want %v", testCase.userFormat, got, testCase.want)
			}
		})
	}
}

func TestParseMasterUserLoginAcceptsFormats(t *testing.T) {
	testCases := []struct {
		name           string
		userFormat     string
		username       string
		wantTargetUser string
		wantMasterUser string
		wantOK         bool
	}{
		{
			name:           testMasterUserFormatNameDefaultTargetFirst,
			userFormat:     DefaultMasterUserFormat,
			username:       testMasterUserDefaultLogin,
			wantTargetUser: testMasterUserTargetAccount,
			wantMasterUser: testMasterUserAdminAccount,
			wantOK:         true,
		},
		{
			name:           "custom separator",
			userFormat:     "{user}#{master_user}",
			username:       testMasterUserCustomSeparatorLogin,
			wantTargetUser: testMasterUserTargetAccount,
			wantMasterUser: testMasterUserAdminAccount,
			wantOK:         true,
		},
		{
			name:           testMasterUserFormatNameMasterFirst,
			userFormat:     testMasterUserFormatMasterFirst,
			username:       testMasterUserMasterFirstLogin,
			wantTargetUser: testMasterUserTargetAccount,
			wantMasterUser: testMasterUserAdminAccount,
			wantOK:         true,
		},
		{
			name:           testMasterUserFormatNameStaticBounded,
			userFormat:     testMasterUserFormatStaticBounded,
			username:       testMasterUserStaticBoundedLogin,
			wantTargetUser: testMasterUserTargetAccount,
			wantMasterUser: testMasterUserAdminAccount,
			wantOK:         true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertParsedMasterUserLogin(t, testCase.userFormat, testCase.username, testCase.wantTargetUser, testCase.wantMasterUser, testCase.wantOK)
		})
	}
}

func TestParseMasterUserLoginRejectsAmbiguousInput(t *testing.T) {
	testCases := []struct {
		name       string
		userFormat string
		username   string
	}{
		{
			name:       "repeated separator is ambiguous",
			userFormat: DefaultMasterUserFormat,
			username:   testMasterUserTargetAccount + "*team*" + testMasterUserAdminAccount,
		},
		{
			name:       "empty master user is rejected",
			userFormat: DefaultMasterUserFormat,
			username:   testMasterUserTargetAccount + "*",
		},
		{
			name:       "invalid format is rejected",
			userFormat: testMasterUserFormatAdjacent,
			username:   testMasterUserTargetAccount + testMasterUserAdminAccount,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertParsedMasterUserLogin(t, testCase.userFormat, testCase.username, "", "", false)
		})
	}
}

// assertParsedMasterUserLogin checks a parsed master-user login against the expected identities.
func assertParsedMasterUserLogin(
	t *testing.T,
	userFormat string,
	username string,
	wantTargetUser string,
	wantMasterUser string,
	wantOK bool,
) {
	t.Helper()

	targetUser, masterUser, ok := ParseMasterUserLogin(username, userFormat)
	if ok != wantOK {
		t.Fatalf("ParseMasterUserLogin() ok = %v, want %v", ok, wantOK)
	}

	if targetUser != wantTargetUser {
		t.Fatalf("target user = %q, want %q", targetUser, wantTargetUser)
	}

	if masterUser != wantMasterUser {
		t.Fatalf("master user = %q, want %q", masterUser, wantMasterUser)
	}
}

func TestHandleFileRejectsLegacyMasterUserDelimiter(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("auth", map[string]any{
		"pipeline": map[string]any{
			"master_user": map[string]any{
				remoteAuthorityEnabledKey: true,
				"delimiter":               "#",
			},
		},
	})

	cfg := &FileSettings{}

	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want legacy delimiter rejection")
	}

	if !strings.Contains(err.Error(), "auth.pipeline.master_user") || !strings.Contains(err.Error(), "delimiter") {
		t.Fatalf("HandleFile() error = %q, want auth.pipeline.master_user delimiter rejection", err)
	}
}
