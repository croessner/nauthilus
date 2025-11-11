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

// CacheService abstracts positive/negative cache behavior.
type CacheService interface {
	// OnSuccess updates the positive cache after a successful authentication attempt for the specified account name.
	OnSuccess(auth *AuthState, accountName string) error

	// OnFailure handles the actions required in case of an unsuccessful authentication attempt for the given account name.
	OnFailure(auth *AuthState, accountName string)
}
