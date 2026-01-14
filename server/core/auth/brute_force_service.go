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
	"math"

	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/core"
	"github.com/gin-gonic/gin"
)

// DefaultBruteForceService implements core.BruteForceService in the auth subpackage.
// It mirrors the legacy behavior previously implemented in core.
//
//goland:nointerface
type DefaultBruteForceService struct{}

// WaitDelay implements the same hyperbolic tangent curve used previously in calculateWaitDelay.
func (DefaultBruteForceService) WaitDelay(maxWaitDelay, loginAttempt uint) int {
	scale := 0.03

	return int(float64(maxWaitDelay) * math.Tanh(scale*float64(loginAttempt)))
}

// LoadHistories mirrors the legacy logic that created a BucketManager and
// populated the AuthState's LoginAttempts/Passwords* counters.
func (DefaultBruteForceService) LoadHistories(ctx *gin.Context, auth *core.AuthState, accountName string) {
	var bm bruteforce.BucketManager

	bm = bruteforce.NewBucketManagerWithDeps(ctx.Request.Context(), auth.GUID, auth.ClientIP, bruteforce.BucketManagerDeps{
		Cfg:      auth.Cfg(),
		Logger:   auth.Logger(),
		Redis:    auth.Redis(),
		Tolerate: auth.Tolerate,
	}).
		WithUsername(auth.Username).
		WithPassword(auth.Password).
		WithAccountName(accountName)

	// Set the protocol if available
	if auth.Protocol != nil && auth.Protocol.Get() != "" {
		bm = bm.WithProtocol(auth.Protocol.Get())
	}

	// Set the OIDC Client ID if available
	if auth.OIDCCID != "" {
		bm = bm.WithOIDCCID(auth.OIDCCID)
	}

	bm.LoadAllPasswordHistories()

	// Synchronize with centralized login attempt manager; bucket authority overrides header hints.
	auth.SyncLoginAttemptsFromBucket(bm.GetLoginAttempts())
	auth.PasswordsAccountSeen = bm.GetPasswordsAccountSeen()
	auth.PasswordsTotalSeen = bm.GetPasswordsTotalSeen()
}
