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

package core

import (
	"github.com/gin-gonic/gin"
)

// Registry for pluggable auth services to avoid import cycles when moving
// implementations into a subpackage (server/core/auth).
// Implementations should call the Register* functions from their init() to provide defaults.

var (
	regLuaFilter    LuaFilter
	regPostAction   PostAction
	regFeatureEng   FeatureEngine
	regActionDisp   ActionDispatcher
	regRBLService   RBLService
	regBF           BruteForceService
	regCacheService CacheService
	regPassVerifier PasswordVerifier
)

// RegisterLuaFilter registers the active LuaFilter implementation.
func RegisterLuaFilter(l LuaFilter) { regLuaFilter = l }

// RegisterPostAction registers the active PostAction implementation.
func RegisterPostAction(p PostAction) { regPostAction = p }

// RegisterFeatureEngine registers the active FeatureEngine implementation.
func RegisterFeatureEngine(f FeatureEngine) { regFeatureEng = f }

// RegisterActionDispatcher registers the active ActionDispatcher implementation.
func RegisterActionDispatcher(a ActionDispatcher) { regActionDisp = a }

// RegisterRBLService registers the active RBLService implementation.
func RegisterRBLService(r RBLService) { regRBLService = r }

// RegisterCacheService registers the active CacheService implementation.
func RegisterCacheService(c CacheService) { regCacheService = c }

// RegisterPasswordVerifier registers the active PasswordVerifier implementation.
func RegisterPasswordVerifier(v PasswordVerifier) { regPassVerifier = v }

func getLuaFilter() LuaFilter                 { return regLuaFilter }
func getPostAction() PostAction               { return regPostAction }
func getFeatureEngine() FeatureEngine         { return regFeatureEng }
func getActionDispatcher() ActionDispatcher   { return regActionDisp }
func getRBLService() RBLService               { return regRBLService }
func getBruteForceService() BruteForceService { return regBF }
func getCacheService() CacheService           { return regCacheService }
func getPasswordVerifier() PasswordVerifier   { return regPassVerifier }

// RegisterBruteForceService registers the active BruteForceService implementation.
func RegisterBruteForceService(b BruteForceService) { regBF = b }

// Exported getters for tests and callers that need direct access.

func GetBruteForceService() BruteForceService { return getBruteForceService() }
func GetCacheService() CacheService           { return getCacheService() }
func GetPasswordVerifier() PasswordVerifier   { return getPasswordVerifier() }

func GetFeatureEngine() FeatureEngine       { return getFeatureEngine() }
func GetActionDispatcher() ActionDispatcher { return getActionDispatcher() }
func GetRBLService() RBLService             { return getRBLService() }

// Optional convenience helpers for callers that don't have *AuthState.
// They keep signatures local to core while allowing external implementations.
func bfWaitDelay(maxWaitDelay, loginAttempt uint) int {
	if svc := getBruteForceService(); svc != nil {
		return svc.WaitDelay(maxWaitDelay, loginAttempt)
	}

	return 0
}

func bfLoadHistories(ctx *gin.Context, a *AuthState, account string) {
	if svc := getBruteForceService(); svc != nil {
		svc.LoadHistories(ctx, a, account)
	}
}
