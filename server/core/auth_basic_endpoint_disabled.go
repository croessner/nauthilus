//go:build !auth_basic_endpoint

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

import "github.com/gin-gonic/gin"

func (a *AuthState) preprocessBasicEndpointInput(_ *gin.Context) bool {
	return false
}

func (a *AuthState) handleBasicEndpointAuthPhase(_ *gin.Context, _ authFSMState) bool {
	return false
}
