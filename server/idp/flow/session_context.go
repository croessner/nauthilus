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

package flow

import "github.com/croessner/nauthilus/server/definitions"

type sessionContextSetter interface {
	Set(key string, value any)
}

type sessionContextMutator interface {
	sessionContextSetter
	Delete(key string)
}

// RestoreFlowCookieContext restores minimal protocol/grant context in the session
// after temporary sub-flow cleanup (e.g. require_mfa abort).
func RestoreFlowCookieContext(mgr sessionContextSetter, flowType string, grantType string) {
	if mgr == nil {
		return
	}

	if flowType != "" {
		mgr.Set(definitions.SessionKeyIdPFlowType, flowType)
	}

	if grantType != "" {
		mgr.Set(definitions.SessionKeyOIDCGrantType, grantType)
	}
}

// SetRequireMFAPending stores required MFA registration methods.
// Empty pending list clears the require_mfa session state.
func SetRequireMFAPending(mgr sessionContextMutator, pending string) {
	if mgr == nil {
		return
	}

	if pending == "" {
		ClearRequireMFAContext(mgr)

		return
	}

	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, pending)
}

// ClearRequireMFAContext removes temporary require_mfa session keys.
func ClearRequireMFAContext(mgr sessionContextMutator) {
	if mgr == nil {
		return
	}

	mgr.Delete(definitions.SessionKeyRequireMFAFlow)
	mgr.Delete(definitions.SessionKeyRequireMFAPending)
	mgr.Delete(definitions.SessionKeyRequireMFAParentFlowID)
}
