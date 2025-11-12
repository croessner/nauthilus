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

import (
	"github.com/gin-gonic/gin"
)

// BruteForceService encapsulates backoff calculations and history/counter loading.
// Implementations live in a subpackage and register themselves via services_registry.
type BruteForceService interface {
	// WaitDelay returns the wait time in seconds based on configured max and login attempts.
	WaitDelay(maxWaitDelay, loginAttempt uint) int

	// LoadHistories loads brute-force related histories and updates counters on the AuthState.
	LoadHistories(ctx *gin.Context, auth *AuthState, accountName string)
}
