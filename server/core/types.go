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

// Done is the value for channels to finish workers
type Done struct{}

// BackendManager defines an interface for managing authentication backends with methods for user authentication and account handling.
type BackendManager interface {
	// PassDB authenticates a user through a password database using the provided AuthState and returns the authentication result.
	PassDB(auth *AuthState) (passDBResult *PassDBResult, err error)

	// AccountDB retrieves a list of user accounts from the backend using the provided authentication state.
	AccountDB(auth *AuthState) (accounts AccountList, err error)

	// AddTOTPSecret adds the specified TOTP secret to the user's authentication state in the backend.
	AddTOTPSecret(auth *AuthState, totp *TOTPSecret) (err error)
}
