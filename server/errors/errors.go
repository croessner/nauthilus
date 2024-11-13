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

package errors

import (
	"errors"
)

type DetailedError struct {
	err      error
	guid     string
	details  string
	instance string
}

func (d *DetailedError) Error() string {
	return d.err.Error()
}

func (d *DetailedError) WithGUID(guid string) *DetailedError {
	if d == nil {
		return nil
	}

	d.guid = guid

	return d
}

func (d *DetailedError) WithDetail(detail string) *DetailedError {
	if d == nil {
		return nil
	}

	d.details = detail

	return d
}

func (d *DetailedError) WithInstance(instance string) *DetailedError {
	if d == nil {
		return nil
	}

	d.instance = instance

	return d
}

func (d *DetailedError) GetGUID() string {
	return d.guid
}

func (d *DetailedError) GetDetails() string {
	return d.details
}

func (d *DetailedError) GetInstance() string {
	return d.instance
}

func NewDetailedError(err string) *DetailedError {
	return &DetailedError{err: errors.New(err)}
}

// auth.

var (
	ErrNoBackendsConfigured                    = errors.New("no database backends configured")
	ErrUnknownService                          = errors.New("unknown service")
	ErrAllBackendConfigError                   = errors.New("configuration errors in all Database sections")
	ErrInvalidJSONPayload                      = errors.New("invalid JSON payload")
	ErrUnsupportedMediaType                    = errors.New("unsupported media type")
	ErrFeatureBackendServersMonitoringDisabled = errors.New("backend_server_monitoring not enabled")
	ErrMonitoringBackendServersEmpty           = errors.New("no monitoring backend servers configured")
	ErrInvalidUsername                         = errors.New("invalid username")
	ErrPasswordEncoding                        = errors.New("password encoding error")
)

// env.

var (
	ErrWrongVerboseLevel = errors.New("wrong verbose level: <%s>")
	ErrWrongLDAPScope    = errors.New("wrong LDAP scope: <%s>")
	ErrWrongPassDB       = errors.New("wrong passdb backend: <%s>")
	ErrWrongFeature      = errors.New("wrong feature: <%s>")
	ErrWrongDebugModule  = errors.New("wrong debug module: <%s>")
)

// file.

var (
	ErrNoLDAPSection          = errors.New("no 'ldap:' section found")
	ErrNoLDAPSearchSection    = errors.New("no 'ldap::search:' section found")
	ErrNoLDAPConfig           = errors.New("no 'ldap::config:' section found")
	ErrNoLDAPServerURIs       = errors.New("no 'ldap::config::server_uri' definition")
	ErrBruteForceTooManyRules = errors.New("too many rules in 'user'account' section")
	ErrCSRFSecretWrongSize    = errors.New("csrf secret must exactly be 32 bytes long")
	ErrCookieStoreAuthSize    = errors.New("cookie store auth key must exactly be 32 bytes")
	ErrCookieStoreEncSize     = errors.New("cookie store encryption key must exactly be 16, 24 or 32 bytes")
	ErrNoPasswordNonce        = errors.New("no 'password_nonce' defined")
	ErrNoLuaScriptPath        = errors.New("no 'lua::config:script_path' definition")
	ErrRedisDatabaseNumber    = errors.New("server::redis::datavase_number must be >= 0 and < 15")
	ErrRedisPoolSize          = errors.New("server::redis::pool_size must be > 0")
)

// ldap.

var (
	ErrLDAPConnect        = NewDetailedError("ldap_servers_connect_error")
	ErrLDAPConfig         = NewDetailedError("ldap_config_error")
	ErrNoLDAPSearchResult = NewDetailedError("ldap_no_search_result")
	ErrLDAPConnectTimeout = NewDetailedError("ldap_connect_timeout")
)

// lua.

var (
	ErrLuaConfig               = NewDetailedError("lua_config_error")
	ErrBackendLuaWrongUserData = NewDetailedError("wrong_user_data_result")
	ErrBackendLua              = NewDetailedError("script_execution_failed")
)

// util.

var (
	ErrUnsupportedAlgorithm      = errors.New("unsupported hash algorithm")
	ErrUnsupportedPasswordOption = errors.New("unsupported password option")
)

// common.

var (
	ErrNoPassDBResult = errors.New("no pass Database result")
	ErrUnknownCause   = errors.New("something went wrong")
)

// bruteforce.

var (
	ErrRuleNoName             = errors.New("missing 'name' field in rule")
	ErrRuleNoIPv4AndIPv6      = errors.New("do not set 'ipv4' and 'ipv6' at the same time in a rule")
	ErrRuleMissingIPv4AndIPv6 = errors.New("neither 'ipv4' nor 'ipv6' specified in rule")
	ErrRuleNoCIDR             = errors.New("missing 'cidr' in rule")
	ErrRuleNoPeriod           = errors.New("missing 'period' in rule")
	ErrRuleNoFailedRequests   = errors.New("missing 'failed_requests' in rule")
	ErrWrongIPAddress         = errors.New("unable to parse IP address")
)

// hydra.

var (
	ErrNoLoginChallenge = errors.New("missing login challenge")
	ErrNoAccount        = errors.New("no account found")
	ErrUnknownJSON      = errors.New("unable to parse JSON response")
	ErrHTTPRequestGone  = errors.New("http request gone")
	ErrHydraNoClientId  = errors.New("no client_id returned from hydra server")
	ErrNoTLS            = errors.New("no tls connection")
	ErrTOTPCodeInvalid  = errors.New("totp code invalid")
	ErrNoTOTPCode       = errors.New("totp code not found")
	ErrBruteForceAttack = errors.New("please contact the support")
)

// features.

var (
	ErrDNSResolver = errors.New("resolver failed")
)

// http.

var (
	ErrLanguageNotFound = errors.New("requested language not found")
	ErrUnauthorized     = errors.New("unauthorized")
)

// register.

var (
	ErrNotLoggedIn = errors.New("user not logged in")
	ErrNoTOTPURL   = errors.New("no TOTP URL found")
)

// webauthn.

var (
	ErrWebAuthnSessionData    = errors.New("no webauthn session data found")
	ErrNoDisplayName          = errors.New("no display name found")
	ErrUnknownDatabaseBackend = errors.New("unknown Database backend")
)

// Lua features.

var (
	ErrFeatureLuaNameMissing     = errors.New("feature 'name' sttribute missing")
	ErrFeatureLuaScriptPathEmpty = errors.New("feature 'script_path' attribute missing")
)

// Lua filters.

var (
	ErrNoFiltersDefined         = errors.New("no filters defined")
	ErrFilterLuaNameMissing     = errors.New("filter 'name' sttribute missing")
	ErrFilterLuaScriptPathEmpty = errors.New("filter 'script_path' attribute missing")
)

// misc.

var (
	ErrInvalidRange = errors.New("invalid range")
)
