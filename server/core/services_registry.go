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
	regLuaSubject     LuaSubject
	regPluginSubject  PluginSubjectSourceBridge
	regPluginEnv      PluginEnvironmentSourceBridge
	regPostAction     PostAction
	regPluginEffect   PluginEffectBridge
	regEnvironmentEng EnvironmentEngine
	regActionDisp     ActionDispatcher
	regRBLService     RBLService
	regBF             BruteForceService
	regCacheService   CacheService
	regPassVerifier   PasswordVerifier
)

// RegisterLuaSubject registers the active LuaSubject implementation.
func RegisterLuaSubject(l LuaSubject) { regLuaSubject = l }

// RegisterPluginSubjectSourceBridge registers the native plugin subject-source adapter.
func RegisterPluginSubjectSourceBridge(b PluginSubjectSourceBridge) { regPluginSubject = b }

// RegisterPluginEnvironmentSourceBridge registers the native plugin environment-source adapter.
func RegisterPluginEnvironmentSourceBridge(b PluginEnvironmentSourceBridge) { regPluginEnv = b }

// RegisterPostAction registers the active PostAction implementation.
func RegisterPostAction(p PostAction) { regPostAction = p }

// RegisterPluginEffectBridge registers the native plugin policy effect adapter.
func RegisterPluginEffectBridge(b PluginEffectBridge) { regPluginEffect = b }

// RegisterEnvironmentEngine registers the active EnvironmentEngine implementation.
func RegisterEnvironmentEngine(f EnvironmentEngine) { regEnvironmentEng = f }

// RegisterActionDispatcher registers the active ActionDispatcher implementation.
func RegisterActionDispatcher(a ActionDispatcher) { regActionDisp = a }

// RegisterRBLService registers the active RBLService implementation.
func RegisterRBLService(r RBLService) { regRBLService = r }

// RegisterCacheService registers the active CacheService implementation.
func RegisterCacheService(c CacheService) { regCacheService = c }

// RegisterPasswordVerifier registers the active PasswordVerifier implementation.
func RegisterPasswordVerifier(v PasswordVerifier) { regPassVerifier = v }

func getLuaSubject() LuaSubject { return regLuaSubject }
func getPluginSubjectSourceBridge() PluginSubjectSourceBridge {
	return regPluginSubject
}

// getPluginEnvironmentSourceBridge returns the registered native pre-auth environment adapter.
func getPluginEnvironmentSourceBridge() PluginEnvironmentSourceBridge {
	return regPluginEnv
}
func getPostAction() PostAction { return regPostAction }
func getPluginEffectBridge() PluginEffectBridge {
	return regPluginEffect
}
func getEnvironmentEngine() EnvironmentEngine { return regEnvironmentEng }
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

// GetEnvironmentEngine returns the registered Lua environment source evaluator.
func GetEnvironmentEngine() EnvironmentEngine { return getEnvironmentEngine() }

// GetActionDispatcher returns the registered Lua action dispatcher.
func GetActionDispatcher() ActionDispatcher { return getActionDispatcher() }

// GetRBLService returns the registered RBL service.
func GetRBLService() RBLService { return getRBLService() }

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
