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
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v4/server/secret"
)

const backchannelBasicAuthPath = "auth.backchannel.basic_auth"

// BackchannelBasicAuth configures HTTP Basic caller authentication of the backchannel API.
//
// The top-level username and password form the unrestricted credential: it passes every management scope check,
// as it always did, and holds no support scope. Each entry of Users is a scoped credential that holds exactly the
// scopes it lists and is authorized like a Bearer token carrying the same scopes.
type BackchannelBasicAuth struct {
	Users    []BackchannelBasicAuthUser `mapstructure:"users" validate:"omitempty,dive"`
	Password secret.Value               `mapstructure:"password" validate:"omitempty,secret_min=16,alphanumsymbol,secret_excludesall= "`
	Username string                     `mapstructure:"username" validate:"omitempty,excludesall= :"`
	Enabled  bool                       `mapstructure:"enabled"`
}

// BackchannelBasicAuthUser is one scoped HTTP Basic credential of the backchannel API.
type BackchannelBasicAuthUser struct {
	Scopes   []string     `mapstructure:"scopes" validate:"required,min=1,dive,scope_token"`
	Password secret.Value `mapstructure:"password" validate:"secret_required,secret_min=16,alphanumsymbol,secret_excludesall= "`
	Username string       `mapstructure:"username" validate:"required,excludesall= :"`
}

// IsEnabled reports whether HTTP Basic caller authentication is enabled; a nil receiver is disabled.
func (b *BackchannelBasicAuth) IsEnabled() bool {
	return b != nil && b.Enabled
}

// GetUsername returns the username of the unrestricted credential.
func (b *BackchannelBasicAuth) GetUsername() string {
	if b == nil {
		return ""
	}

	return b.Username
}

// GetPassword returns the password of the unrestricted credential.
func (b *BackchannelBasicAuth) GetPassword() secret.Value {
	if b == nil {
		return secret.Value{}
	}

	return b.Password
}

// GetUsers returns the scoped credentials.
func (b *BackchannelBasicAuth) GetUsers() []BackchannelBasicAuthUser {
	if b == nil {
		return nil
	}

	return b.Users
}

// HasUnrestrictedCredential reports whether the unrestricted username and password are both configured.
func (b *BackchannelBasicAuth) HasUnrestrictedCredential() bool {
	return b != nil && b.Username != "" && !b.Password.IsZero()
}

// Unrestricted returns the unrestricted credential in the shape shared with the other Basic settings.
func (b *BackchannelBasicAuth) Unrestricted() *BasicAuth {
	if b == nil {
		return &BasicAuth{}
	}

	return &BasicAuth{Enabled: b.Enabled, Username: b.Username, Password: b.Password}
}

// GetUsername returns the username of the scoped credential.
func (u *BackchannelBasicAuthUser) GetUsername() string {
	if u == nil {
		return ""
	}

	return u.Username
}

// GetPassword returns the password of the scoped credential.
func (u *BackchannelBasicAuthUser) GetPassword() secret.Value {
	if u == nil {
		return secret.Value{}
	}

	return u.Password
}

// GetScopes returns the scopes the credential holds.
func (u *BackchannelBasicAuthUser) GetScopes() []string {
	if u == nil {
		return nil
	}

	return u.Scopes
}

// validateBackchannelBasicAuth rejects an enabled Basic section without any usable credential and ambiguous
// usernames, and warns when the unrestricted credential is still configured.
func (f *FileSettings) validateBackchannelBasicAuth() error {
	if f == nil || f.Server == nil {
		return nil
	}

	basicAuth := f.Server.GetBasicAuth()
	if !basicAuth.IsEnabled() {
		return nil
	}

	if err := validateBackchannelBasicAuthUsers(basicAuth); err != nil {
		return err
	}

	if !basicAuth.HasUnrestrictedCredential() {
		return validateBackchannelBasicAuthWithoutUnrestricted(basicAuth)
	}

	safeWarn(
		"msg", "The unrestricted backchannel Basic credential is configured; it grants full management access. "+
			"Prefer scoped credentials under "+backchannelBasicAuthPath+".users",
		"username", basicAuth.GetUsername(),
	)

	return nil
}

// validateBackchannelBasicAuthWithoutUnrestricted requires scoped credentials when the unrestricted pair is not
// usable, and rejects a pair that is only half configured.
func validateBackchannelBasicAuthWithoutUnrestricted(basicAuth *BackchannelBasicAuth) error {
	if basicAuth.GetUsername() != "" || !basicAuth.GetPassword().IsZero() {
		return fmt.Errorf("%s: username and password must be set together", backchannelBasicAuthPath)
	}

	if len(basicAuth.GetUsers()) == 0 {
		return fmt.Errorf("%s.enabled requires username and password or at least one entry in users",
			backchannelBasicAuthPath)
	}

	return nil
}

// validateBackchannelBasicAuthUsers requires every username to name exactly one credential.
func validateBackchannelBasicAuthUsers(basicAuth *BackchannelBasicAuth) error {
	seen := make(map[string]struct{}, len(basicAuth.GetUsers())+1)
	if username := basicAuth.GetUsername(); username != "" {
		seen[username] = struct{}{}
	}

	for index := range basicAuth.GetUsers() {
		username := strings.TrimSpace(basicAuth.Users[index].GetUsername())
		if _, duplicate := seen[username]; duplicate {
			return fmt.Errorf("%s.users[%d].username: duplicate username '%s'", backchannelBasicAuthPath, index, username)
		}

		seen[username] = struct{}{}
	}

	return nil
}
