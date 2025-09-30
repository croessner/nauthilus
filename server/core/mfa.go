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

import mfamodel "github.com/croessner/nauthilus/server/model/mfa"

// NewTOTPSecret creates a new TOTPSecret instance using the provided secret value.
// It returns a pointer to the created TOTPSecret object.
func NewTOTPSecret(value string) *mfamodel.TOTPSecret {
	return mfamodel.NewTOTPSecret(value)
}

// NewWebAuthn creates and returns a new WebAuthn object initialized with the provided value.
func NewWebAuthn(value string) *mfamodel.WebAuthn {
	return mfamodel.NewWebAuthn(value)
}
