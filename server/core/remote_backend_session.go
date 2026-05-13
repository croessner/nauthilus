// Copyright (C) 2026 Christian Roessner
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
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
)

// StoreRemoteBackendRef persists the authority backend reference in the encrypted edge session.
func StoreRemoteBackendRef(mgr cookie.Manager, ref RemoteBackendRef) {
	if mgr == nil {
		return
	}

	if ref.IsZero() {
		ClearRemoteBackendRef(mgr)

		return
	}

	mgr.Set(definitions.SessionKeyRemoteBackendRefType, ref.Type)
	mgr.Set(definitions.SessionKeyRemoteBackendRefName, ref.Name)
	mgr.Set(definitions.SessionKeyRemoteBackendRefProtocol, ref.Protocol)
	mgr.Set(definitions.SessionKeyRemoteBackendRefAuthority, ref.Authority)
	mgr.Set(definitions.SessionKeyRemoteBackendRefToken, ref.OpaqueToken)
}

// RemoteBackendRefFromSession restores the authority backend reference from the encrypted edge session.
func RemoteBackendRefFromSession(mgr cookie.Manager) (RemoteBackendRef, bool) {
	if mgr == nil {
		return RemoteBackendRef{}, false
	}

	ref := RemoteBackendRef{
		Type:        mgr.GetString(definitions.SessionKeyRemoteBackendRefType, ""),
		Name:        mgr.GetString(definitions.SessionKeyRemoteBackendRefName, ""),
		Protocol:    mgr.GetString(definitions.SessionKeyRemoteBackendRefProtocol, ""),
		Authority:   mgr.GetString(definitions.SessionKeyRemoteBackendRefAuthority, ""),
		OpaqueToken: mgr.GetString(definitions.SessionKeyRemoteBackendRefToken, ""),
	}

	if ref.IsZero() || ref.OpaqueToken == "" {
		return RemoteBackendRef{}, false
	}

	return ref, true
}

// ClearRemoteBackendRef removes an authority backend reference from the encrypted edge session.
func ClearRemoteBackendRef(mgr cookie.Manager) {
	if mgr == nil {
		return
	}

	mgr.Delete(definitions.SessionKeyRemoteBackendRefType)
	mgr.Delete(definitions.SessionKeyRemoteBackendRefName)
	mgr.Delete(definitions.SessionKeyRemoteBackendRefProtocol)
	mgr.Delete(definitions.SessionKeyRemoteBackendRefAuthority)
	mgr.Delete(definitions.SessionKeyRemoteBackendRefToken)
}
