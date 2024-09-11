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

import "github.com/croessner/nauthilus/server/config"

// MFA is an interface that stores some information for multi factor authentication.
type MFA interface {
	// GetValue returns the MFA value as a string.
	getValue() string

	// SetValue sets an MFA value.
	setValue(string)
}

type TOTPSecret struct {
	value string
}

func (t *TOTPSecret) getValue() string {
	return t.value
}

func (t *TOTPSecret) setValue(value string) {
	t.value = value
}

func (t *TOTPSecret) getLDAPTOTPSecret(protocol *config.LDAPSearchProtocol) string {
	return protocol.TOTPSecretField
}

func NewTOTPSecret(value string) *TOTPSecret {
	totpObj := &TOTPSecret{}
	totpObj.setValue(value)

	return totpObj
}

type WebAuthn struct {
	Value string
}

func (w *WebAuthn) getValue() string {
	return w.Value
}

func (w *WebAuthn) setValue(value string) {
	w.Value = value
}

func (w *WebAuthn) getLDAPUniqueUserID(protocol *config.LDAPSearchProtocol) string {
	return protocol.UniqueUserIDField
}

func NewWebAuthn(value string) *WebAuthn {
	webAuthNObj := &WebAuthn{}
	webAuthNObj.setValue(value)

	return webAuthNObj
}
