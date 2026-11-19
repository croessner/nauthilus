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

// StandardClaim describes a standard OpenID Connect claim: the scope that releases it and its default type.
type StandardClaim struct {
	Scope string
	Type  string
}

// StandardClaims returns the standard OpenID Connect claims Nauthilus releases through its built-in scopes.
func StandardClaims() map[string]StandardClaim {
	return map[string]StandardClaim{
		ClaimName:                {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimGivenName:           {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimFamilyName:          {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimMiddleName:          {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimNickName:            {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimPreferredUserName:   {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimProfile:             {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimWebsite:             {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimPicture:             {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimGender:              {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimBirtDate:            {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimZoneInfo:            {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimLocale:              {Scope: ScopeProfile, Type: ClaimTypeString},
		ClaimUpdatedAt:           {Scope: ScopeProfile, Type: ClaimTypeInteger},
		ClaimEmail:               {Scope: ScopeEmail, Type: ClaimTypeString},
		ClaimEmailVerified:       {Scope: ScopeEmail, Type: ClaimTypeBoolean},
		ClaimPhoneNumber:         {Scope: ScopePhone, Type: ClaimTypeString},
		ClaimPhoneNumberVerified: {Scope: ScopePhone, Type: ClaimTypeBoolean},
		ClaimAddress:             {Scope: ScopeAddress, Type: ClaimTypeAddress},
		ClaimGroups:              {Scope: ScopeGroups, Type: ClaimTypeStringArray},
	}
}

// BuiltinScopes returns every scope Nauthilus defines itself: the standard OpenID Connect scopes and its own
// management, policy, and support scopes. Any other scope is defined by the deployment.
func BuiltinScopes() []string {
	return []string{
		ScopeOpenID, ScopeOfflineAccess, ScopeProfile, ScopeEmail, ScopeAddress, ScopePhone, ScopeGroups,
		ScopeAdmin, ScopePolicyEvaluate, ScopePolicyDiagnostics,
		ScopeSecurity, ScopeSecurityRead, ScopeSecurityWrite,
		ScopeAuthenticate, ScopeLookupIdentity, ScopeListAccounts,
		ScopeMFARead, ScopeMFAVerify, ScopeMFAWrite, ScopeWebAuthnRead, ScopeWebAuthnWrite, ScopeAttributeRead,
		ScopeHistoryRead, ScopeHistoryDetail, ScopeOperationsRead,
	}
}
