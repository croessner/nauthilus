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
	"math"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

// BruteForceService encapsulates backoff calculations and history/counter loading.
// Default implementation preserves the legacy behavior.
type BruteForceService interface {
	// WaitDelay returns the wait time in seconds based on configured max and login attempts.
	WaitDelay(maxWaitDelay, loginAttempt uint) int

	// LoadHistories loads brute-force related histories and updates counters on the AuthState.
	LoadHistories(ctx *gin.Context, a *AuthState, accountName string)
}

// DefaultBruteForceService is the default implementation used by the core until an orchestrator is introduced.
type DefaultBruteForceService struct{}

var defaultBruteForceService BruteForceService = DefaultBruteForceService{}

// WaitDelay implements the same hyperbolic tangent curve used previously in calculateWaitDelay.
func (DefaultBruteForceService) WaitDelay(maxWaitDelay, loginAttempt uint) int {
	scale := 0.03

	return int(float64(maxWaitDelay) * math.Tanh(scale*float64(loginAttempt)))
}

// LoadHistories mirrors the legacy logic from processCache() that created a BucketManager and
// populated the AuthState's LoginAttempts/Passwords* counters.
func (DefaultBruteForceService) LoadHistories(ctx *gin.Context, a *AuthState, accountName string) {
	var bm bruteforce.BucketManager

	bm = bruteforce.NewBucketManager(ctx.Request.Context(), a.GUID, a.ClientIP).
		WithUsername(a.Username).
		WithPassword(a.Password).
		WithAccountName(accountName)

	// Set the protocol if available
	if a.Protocol != nil && a.Protocol.Get() != "" {
		bm = bm.WithProtocol(a.Protocol.Get())
	}

	// Set the OIDC Client ID if available
	if a.OIDCCID != "" {
		bm = bm.WithOIDCCID(a.OIDCCID)
	}

	bm.LoadAllPasswordHistories()

	a.LoginAttempts = bm.GetLoginAttempts()
	a.PasswordsAccountSeen = bm.GetPasswordsAccountSeen()
	a.PasswordsTotalSeen = bm.GetPasswordsTotalSeen()

	// Preserve legacy no-op when feature disabled
	_ = config.GetFile().HasFeature(definitions.FeatureBruteForce)
}
