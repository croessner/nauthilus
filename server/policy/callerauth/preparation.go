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

package callerauth

import policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"

// Prepare compiles one generation-owned authenticator and detached profile metadata.
func Prepare(configuration Configuration) (policyruntime.CallerAuthenticationPreparation, error) {
	authenticator, err := New(configuration)
	if err != nil {
		return policyruntime.CallerAuthenticationPreparation{}, err
	}

	credentials, err := policyruntime.NewCredentialProfiles(authenticator.ProfileIDs())
	if err != nil {
		return policyruntime.CallerAuthenticationPreparation{}, err
	}

	return policyruntime.CallerAuthenticationPreparation{
		Authenticator: authenticator,
		Credentials:   credentials,
	}, nil
}
