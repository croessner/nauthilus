// Copyright (C) 2024-2025 Christian Rößner
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

package auth

import (
	"github.com/croessner/nauthilus/v4/server/core"
)

// NewDefaultHostServices constructs the explicit production host implementation bundle.
func NewDefaultHostServices() core.AuthnHostServices {
	services, err := core.NewAuthnHostServices(core.AuthnHostServicesInput{
		PasswordVerifier: DefaultPasswordVerifier{},
		Cache:            DefaultCacheService{},
		BruteForce:       DefaultBruteForceService{},
		Subject:          DefaultLuaSubject{},
		RBL:              DefaultRBLService{},
	})
	if err != nil {
		panic(err)
	}

	return services
}
