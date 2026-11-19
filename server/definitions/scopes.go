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

package definitions

// SecurityReadScopes returns the scopes that open the read-only security routes: brute-force listings and OIDC
// session listings. The wider security and admin scopes include them.
func SecurityReadScopes() []string {
	return []string{ScopeSecurityRead, ScopeSecurity, ScopeAdmin}
}

// SecurityWriteScopes returns the scopes that open the mutating security routes: cache and brute-force flushes
// and OIDC session deletion. The wider security and admin scopes include them.
func SecurityWriteScopes() []string {
	return []string{ScopeSecurityWrite, ScopeSecurity, ScopeAdmin}
}

// SecurityJobScopes returns the scopes that may read the status of an asynchronous security job. A caller that
// may start such a job must be able to follow it, so both the read and the write scope qualify.
func SecurityJobScopes() []string {
	return []string{ScopeSecurityRead, ScopeSecurityWrite, ScopeSecurity, ScopeAdmin}
}
