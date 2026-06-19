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

// Package mfa provides mfa functionality.
package mfa

import "github.com/croessner/nauthilus/v3/server/config"

// MFA is an interface that stores some information for multi factor authentication.
type MFA interface {
	// GetValue returns the MFA value as a string.
	GetValue() string

	// SetValue sets an MFA value.
	setValue(string)
}

// TOTPSecret describes the exported TOTPSecret type.
type TOTPSecret struct {
	value string
}

// GetValue provides the exported GetValue method.
func (t *TOTPSecret) GetValue() string {
	return t.value
}

func (t *TOTPSecret) setValue(value string) {
	t.value = value
}

var _ MFA = (*TOTPSecret)(nil)

// GetLDAPTOTPSecret provides the exported GetLDAPTOTPSecret method.
func (t *TOTPSecret) GetLDAPTOTPSecret(protocol *config.LDAPSearchProtocol) string {
	return protocol.TOTPSecretField
}

// NewTOTPSecret provides the exported NewTOTPSecret function.
func NewTOTPSecret(value string) *TOTPSecret {
	totpObj := &TOTPSecret{}
	totpObj.setValue(value)

	return totpObj
}

// WebAuthn describes the exported WebAuthn type.
type WebAuthn struct {
	Value string
}

// GetValue provides the exported GetValue method.
func (w *WebAuthn) GetValue() string {
	return w.Value
}

func (w *WebAuthn) setValue(value string) {
	w.Value = value
}

var _ MFA = (*WebAuthn)(nil)

// GetLDAPUniqueUserID provides the exported GetLDAPUniqueUserID method.
func (w *WebAuthn) GetLDAPUniqueUserID(protocol *config.LDAPSearchProtocol) string {
	return protocol.UniqueUserIDField
}

// NewWebAuthn provides the exported NewWebAuthn function.
func NewWebAuthn(value string) *WebAuthn {
	webAuthNObj := &WebAuthn{}
	webAuthNObj.setValue(value)

	return webAuthNObj
}

// TOTPRecovery describes the exported TOTPRecovery type.
type TOTPRecovery struct {
	codes []string
}

// GetCodes provides the exported GetCodes method.
func (t *TOTPRecovery) GetCodes() []string {
	return t.codes
}

// SetCodes provides the exported SetCodes method.
func (t *TOTPRecovery) SetCodes(codes []string) {
	t.codes = codes
}

// GetLDAPRecoveryField provides the exported GetLDAPRecoveryField method.
func (t *TOTPRecovery) GetLDAPRecoveryField(protocol *config.LDAPSearchProtocol) string {
	return protocol.GetTotpRecoveryField()
}

// NewTOTPRecovery provides the exported NewTOTPRecovery function.
func NewTOTPRecovery(codes []string) *TOTPRecovery {
	return &TOTPRecovery{codes: codes}
}
