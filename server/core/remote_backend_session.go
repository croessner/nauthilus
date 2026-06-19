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
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

// remoteBackendRefSessionKeys groups the session keys that hold one backend reference.
type remoteBackendRefSessionKeys struct {
	refType   string
	name      string
	protocol  string
	authority string
	token     string
}

var defaultRemoteBackendRefKeys = remoteBackendRefSessionKeys{
	refType:   definitions.SessionKeyRemoteBackendRefType,
	name:      definitions.SessionKeyRemoteBackendRefName,
	protocol:  definitions.SessionKeyRemoteBackendRefProtocol,
	authority: definitions.SessionKeyRemoteBackendRefAuthority,
	token:     definitions.SessionKeyRemoteBackendRefToken,
}

var mfaFactorRemoteBackendRefKeys = remoteBackendRefSessionKeys{
	refType:   definitions.SessionKeyMFAFactorRemoteBackendRefType,
	name:      definitions.SessionKeyMFAFactorRemoteBackendRefName,
	protocol:  definitions.SessionKeyMFAFactorRemoteBackendRefProtocol,
	authority: definitions.SessionKeyMFAFactorRemoteBackendRefAuthority,
	token:     definitions.SessionKeyMFAFactorRemoteBackendRefToken,
}

// StoreRemoteBackendRef persists the authority backend reference in the encrypted edge session.
func StoreRemoteBackendRef(mgr cookie.Manager, ref RemoteBackendRef) {
	storeRemoteBackendRefWithKeys(mgr, ref, defaultRemoteBackendRefKeys)
}

// RemoteBackendRefFromSession restores the authority backend reference from the encrypted edge session.
func RemoteBackendRefFromSession(mgr cookie.Manager) (RemoteBackendRef, bool) {
	return remoteBackendRefFromSessionKeys(mgr, defaultRemoteBackendRefKeys)
}

// StorePendingIDPMFAFactorRemoteBackendRef persists the authority backend reference used for MFA factor checks.
func StorePendingIDPMFAFactorRemoteBackendRef(mgr cookie.Manager, ref RemoteBackendRef) {
	storeRemoteBackendRefWithKeys(mgr, ref, mfaFactorRemoteBackendRefKeys)
}

// MFAFactorRemoteBackendRefFromSession restores the authority backend reference used for MFA factor checks.
func MFAFactorRemoteBackendRefFromSession(mgr cookie.Manager) (RemoteBackendRef, bool) {
	return remoteBackendRefFromSessionKeys(mgr, mfaFactorRemoteBackendRefKeys)
}

// storeRemoteBackendRefWithKeys writes one backend reference into the supplied session key set.
func storeRemoteBackendRefWithKeys(mgr cookie.Manager, ref RemoteBackendRef, keys remoteBackendRefSessionKeys) {
	if mgr == nil {
		return
	}

	if ref.IsZero() {
		clearRemoteBackendRefWithKeys(mgr, keys)

		return
	}

	mgr.Set(keys.refType, ref.Type)
	mgr.Set(keys.name, ref.Name)
	mgr.Set(keys.protocol, ref.Protocol)
	mgr.Set(keys.authority, ref.Authority)
	mgr.Set(keys.token, ref.OpaqueToken)
}

// remoteBackendRefFromSessionKeys reads one backend reference from the supplied session key set.
func remoteBackendRefFromSessionKeys(mgr cookie.Manager, keys remoteBackendRefSessionKeys) (RemoteBackendRef, bool) {
	if mgr == nil {
		return RemoteBackendRef{}, false
	}

	ref := RemoteBackendRef{
		Type:        mgr.GetString(keys.refType, ""),
		Name:        mgr.GetString(keys.name, ""),
		Protocol:    mgr.GetString(keys.protocol, ""),
		Authority:   mgr.GetString(keys.authority, ""),
		OpaqueToken: mgr.GetString(keys.token, ""),
	}

	if ref.IsZero() || ref.OpaqueToken == "" {
		return RemoteBackendRef{}, false
	}

	return ref, true
}

// restoreRemoteBackendRefFromSession restores the backend reference that matches the active session identity.
func (a *AuthState) restoreRemoteBackendRefFromSession(mgr cookie.Manager) {
	if a == nil {
		return
	}

	if !a.Runtime.RemoteBackendRef.IsZero() {
		return
	}

	if ref, ok := RemoteBackendRefForAuthSession(a, mgr); ok {
		a.Runtime.RemoteBackendRef = ref
	}
}

// RemoteBackendRefForAuthSession selects the backend reference that matches
// the active authentication identity, including pending MFA factor sessions.
func RemoteBackendRefForAuthSession(auth *AuthState, mgr cookie.Manager) (RemoteBackendRef, bool) {
	return remoteBackendRefForAuthSession(auth, mgr)
}

// remoteBackendRefForAuthSession selects the MFA factor reference when the AuthState resolves that factor account.
func remoteBackendRefForAuthSession(auth *AuthState, mgr cookie.Manager) (RemoteBackendRef, bool) {
	if auth != nil && mgr != nil {
		factorAccount := mgr.GetString(definitions.SessionKeyMFAFactorAccount, "")
		factorUniqueUserID := mgr.GetString(definitions.SessionKeyMFAFactorUniqueUserID, "")
		username := auth.Request.Username

		if username != "" && (username == factorAccount || username == factorUniqueUserID) {
			if ref, ok := MFAFactorRemoteBackendRefFromSession(mgr); ok {
				return ref, true
			}
		}
	}

	return RemoteBackendRefFromSession(mgr)
}

// ClearRemoteBackendRef removes an authority backend reference from the encrypted edge session.
func ClearRemoteBackendRef(mgr cookie.Manager) {
	clearRemoteBackendRefWithKeys(mgr, defaultRemoteBackendRefKeys)
}

// ClearMFAFactorRemoteBackendRef removes the authority backend reference used for MFA factor checks.
func ClearMFAFactorRemoteBackendRef(mgr cookie.Manager) {
	clearRemoteBackendRefWithKeys(mgr, mfaFactorRemoteBackendRefKeys)
}

// clearRemoteBackendRefWithKeys removes one backend reference from the supplied session key set.
func clearRemoteBackendRefWithKeys(mgr cookie.Manager, keys remoteBackendRefSessionKeys) {
	if mgr == nil {
		return
	}

	mgr.Delete(keys.refType)
	mgr.Delete(keys.name)
	mgr.Delete(keys.protocol)
	mgr.Delete(keys.authority)
	mgr.Delete(keys.token)
}
