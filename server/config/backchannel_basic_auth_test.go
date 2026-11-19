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
	"testing"

	"github.com/croessner/nauthilus/v4/server/secret"
)

// backchannelBasicAuthTestUser returns one scoped credential for validation tests.
func backchannelBasicAuthTestUser(username string) BackchannelBasicAuthUser {
	return BackchannelBasicAuthUser{
		Username: username,
		Password: secret.New("scoped-credential-secret"),
		Scopes:   []string{"nauthilus:history_read"},
	}
}

// TestValidateBackchannelBasicAuth verifies which enabled Basic sections are usable and unambiguous.
func TestValidateBackchannelBasicAuth(t *testing.T) {
	password := secret.New("unrestricted-credential-secret")

	tests := []struct {
		name      string
		basicAuth BackchannelBasicAuth
		wantError bool
	}{
		{name: "disabled section is not checked", basicAuth: BackchannelBasicAuth{Username: "management"}},
		{name: "unrestricted credential only", basicAuth: BackchannelBasicAuth{Enabled: true, Username: "management", Password: password}},
		{name: "scoped credentials only", basicAuth: BackchannelBasicAuth{
			Enabled: true, Users: []BackchannelBasicAuthUser{backchannelBasicAuthTestUser("support")},
		}},
		{name: "both kinds", basicAuth: BackchannelBasicAuth{
			Enabled: true, Username: "management", Password: password,
			Users: []BackchannelBasicAuthUser{backchannelBasicAuthTestUser("support"), backchannelBasicAuthTestUser("abuse")},
		}},
		{name: "enabled without any credential", basicAuth: BackchannelBasicAuth{Enabled: true}, wantError: true},
		{name: "username without password", basicAuth: BackchannelBasicAuth{
			Enabled: true, Username: "management", Users: []BackchannelBasicAuthUser{backchannelBasicAuthTestUser("support")},
		}, wantError: true},
		{name: "password without username", basicAuth: BackchannelBasicAuth{Enabled: true, Password: password}, wantError: true},
		{name: "duplicate scoped username", basicAuth: BackchannelBasicAuth{
			Enabled: true, Users: []BackchannelBasicAuthUser{backchannelBasicAuthTestUser("support"), backchannelBasicAuthTestUser("support")},
		}, wantError: true},
		{name: "scoped username equals the unrestricted one", basicAuth: BackchannelBasicAuth{
			Enabled: true, Username: "management", Password: password,
			Users: []BackchannelBasicAuthUser{backchannelBasicAuthTestUser("management")},
		}, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &FileSettings{Server: &ServerSection{BasicAuth: tt.basicAuth}}

			err := settings.validateBackchannelBasicAuth()
			if (err != nil) != tt.wantError {
				t.Fatalf("validateBackchannelBasicAuth() error = %v, wantError = %t", err, tt.wantError)
			}
		})
	}
}

// TestBackchannelBasicAuthUserStructValidation verifies the field rules of a scoped credential.
func TestBackchannelBasicAuthUserStructValidation(t *testing.T) {
	valid := backchannelBasicAuthTestUser("support")

	withoutScopes := valid
	withoutScopes.Scopes = nil

	colonUsername := valid
	colonUsername.Username = "sup:port"

	shortPassword := valid
	shortPassword.Password = secret.New("short")

	tests := []struct {
		name      string
		user      BackchannelBasicAuthUser
		wantError bool
	}{
		{name: "valid credential", user: valid},
		{name: "scopes are required", user: withoutScopes, wantError: true},
		{name: "username must not contain a colon", user: colonUsername, wantError: true},
		{name: "password needs the minimum length", user: shortPassword, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &BackchannelBasicAuth{Enabled: true, Users: []BackchannelBasicAuthUser{tt.user}}

			validate, err := newConfigValidator()
			if err != nil {
				t.Fatalf("newConfigValidator() error = %v", err)
			}

			err = validate.Struct(settings)
			if (err != nil) != tt.wantError {
				t.Fatalf("struct validation error = %v, wantError = %t", err, tt.wantError)
			}
		})
	}
}

// TestValidateGRPCAuthBackchannelAuthAcceptsScopedCredentials verifies that the gRPC authority listener accepts a
// Basic section that only configures scoped credentials, and still refuses one without any usable credential.
func TestValidateGRPCAuthBackchannelAuthAcceptsScopedCredentials(t *testing.T) {
	password := secret.New("unrestricted-credential-secret")

	tests := []struct {
		name      string
		basicAuth BackchannelBasicAuth
		wantError bool
	}{
		{name: "unrestricted credential", basicAuth: BackchannelBasicAuth{Enabled: true, Username: "management", Password: password}},
		{name: "scoped credentials only", basicAuth: BackchannelBasicAuth{
			Enabled: true, Users: []BackchannelBasicAuthUser{backchannelBasicAuthTestUser("edge")},
		}},
		{name: "no usable credential", basicAuth: BackchannelBasicAuth{Enabled: true}, wantError: true},
		{name: "username without password and no scoped credential", basicAuth: BackchannelBasicAuth{
			Enabled: true, Username: "management",
		}, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGRPCAuthBackchannelAuth(&ServerSection{BasicAuth: tt.basicAuth})
			if (err != nil) != tt.wantError {
				t.Fatalf("validateGRPCAuthBackchannelAuth() error = %v, wantError = %t", err, tt.wantError)
			}
		})
	}
}
