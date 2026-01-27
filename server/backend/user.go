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

package backend

import (
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/go-webauthn/webauthn/webauthn"
)

// User represents the user model
type User struct {
	Id          string `redis:"Id"`
	Name        string `redis:"name"`
	DisplayName string `redis:"display_name"`

	Credentials       []webauthn.Credential   `redis:"credentials"`
	Attributes        bktype.AttributeMapping `redis:"-"`
	TOTPSecretField   string                  `redis:"totp_secret_field"`
	TOTPRecoveryField string                  `redis:"totp_recovery_field"`
}

// NewUser creates and returns a new User
func NewUser(name string, displayName string, id string) *User {
	user := &User{}
	user.Id = id
	user.Name = name
	user.DisplayName = displayName
	// user.Credentials = []webauthn.Credential{}

	return user
}

// WebAuthnID returns the user's ID
func (u *User) WebAuthnID() []byte {
	return []byte(u.Id)
}

// WebAuthnName returns the user's username
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon is not (yet) implemented
func (u *User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the user
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
