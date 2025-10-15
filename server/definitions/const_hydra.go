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

//go:build hydra
// +build hydra

package definitions

// ProtoOryHydra corresponds to the "ory-hydra" protocol.
const ProtoOryHydra = "ory-hydra"

// ServOryHydra is the service identifier for Ory Hydra related flows.
const ServOryHydra = "ory_hydra"

// DbgHydra is the debugging module selector for Hydra related debug output.
const DbgHydra DbgModule = 3

// DbgHydraName is the human-readable name for the Hydra debug module.
const DbgHydraName = "hydra"

// Custom defined types for claims (Hydra/OIDC only).
const (
	// ClaimTypeString is the OIDC custom-claim type for strings.
	ClaimTypeString = "string"

	// ClaimTypeBoolean is the OIDC custom-claim type for booleans.
	ClaimTypeBoolean = "boolean"

	// ClaimTypeFloat is the OIDC custom-claim type for floating-point numbers.
	ClaimTypeFloat = "float"

	// ClaimTypeInteger is the OIDC custom-claim type for integers.
	ClaimTypeInteger = "integer"
)

// Standard OpenID Connect scopes (Hydra/OIDC only).
const (
	// ScopeOpenId is the mandatory OpenID Connect scope.
	ScopeOpenId = "openid"

	// ScopeOfflineAccess enables refresh tokens.
	ScopeOfflineAccess = "offline_access"

	// ScopeProfile grants access to basic profile information.
	ScopeProfile = "profile"

	// ScopeEmail grants access to the user's email address.
	ScopeEmail = "email"

	// ScopeAddress grants access to the user's address information.
	ScopeAddress = "address"

	// ScopePhone grants access to the user's phone information.
	ScopePhone = "phone"

	// ScopeGroups grants access to the user's groups.
	ScopeGroups = "groups"
)

// Standard OIDC claim names (Hydra/OIDC only).
const (
	// ClaimName is the "name" claim.
	ClaimName = "name"

	// ClaimGivenName is the "given_name" claim.
	ClaimGivenName = "given_name"

	// ClaimFamilyName is the "family_name" claim.
	ClaimFamilyName = "family_name"

	// ClaimMiddleName is the "middle_name" claim.
	ClaimMiddleName = "middle_name"

	// ClaimNickName is the "nickname" claim.
	ClaimNickName = "nickname"

	// ClaimPreferredUserName is the "preferred_username" claim.
	ClaimPreferredUserName = "preferred_username"

	// ClaimWebsite is the "website" claim.
	ClaimWebsite = "website"

	// ClaimProfile is the "profile" claim.
	ClaimProfile = "profile"

	// ClaimPicture is the "picture" claim.
	ClaimPicture = "picture"

	// ClaimEmail is the "email" claim.
	ClaimEmail = "email"

	// ClaimEmailVerified is the "email_verified" claim.
	ClaimEmailVerified = "email_verified"

	// ClaimGender is the "gender" claim.
	ClaimGender = "gender"

	// ClaimBirtDate is the "birthdate" claim.
	ClaimBirtDate = "birthdate"

	// ClaimZoneInfo is the "zoneinfo" claim.
	ClaimZoneInfo = "zoneinfo"

	// ClaimLocale is the "locale" claim.
	ClaimLocale = "locale"

	// ClaimPhoneNumber is the "phone_number" claim.
	ClaimPhoneNumber = "phone_number"

	// ClaimPhoneNumberVerified is the "phone_number_verified" claim.
	ClaimPhoneNumberVerified = "phone_number_verified"

	// ClaimAddress is the "address" claim.
	ClaimAddress = "address"

	// ClaimUpdatedAt is the "updated_at" claim.
	ClaimUpdatedAt = "updated_at"

	// ClaimGroups is the "groups" claim.
	ClaimGroups = "groups"
)

// Cookie keys used by Hydra-driven registration/login flows.
const (
	// CookieAccount refers to the user's account identifier.
	CookieAccount = "account"

	// CookieHaveTOTP indicates whether the user already has a TOTP secret.
	CookieHaveTOTP = "already_have_totp"

	// CookieTOTPURL holds the otpauth:// URL during TOTP registration.
	CookieTOTPURL = "totp_url"

	// CookieUserBackend records which backend authenticated the user (e.g. LDAP/Lua).
	CookieUserBackend = "user_backend"

	// CookieUniqueUserID stores a backend-specific unique user identifier.
	CookieUniqueUserID = "unique_userid"

	// CookieDisplayName stores a human-friendly display name for the user.
	CookieDisplayName = "display_name"

	// CookieLang stores the UI language preference selected during login/consent.
	CookieLang = "lang"

	// CookieUsername stores the supplied username during the login flow.
	CookieUsername = "username"

	// CookieAuthResult stores the authentication outcome (uint8 AuthResult).
	CookieAuthResult = "auth_result"

	// CookieSubject stores the OIDC subject if computed in-session.
	CookieSubject = "subject"

	// CookieRemember signals a "remember me" option for the session.
	CookieRemember = "remember"

	// CookieRegistration is used during WebAuthn device registration.
	CookieRegistration = "webauthn_registration"

	// CookieTOTPSecret temporarily holds a generated TOTP secret during flow.
	CookieTOTPSecret = "totp_secret"

	// CookieHome marks that the user reached the 2FA home page in the flow.
	CookieHome = "home"
)
