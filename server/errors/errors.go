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

// Unwrap returns the underlying error, enabling errors.Is to match copies
// created by WithDetail/WithGUID/WithInstance against the original sentinel.
func (d *DetailedError) Unwrap() error {
	return d.err
}

// Is reports whether target matches this DetailedError. Two DetailedErrors match
// when they share the same underlying error string, so copies produced by
// WithDetail/WithGUID/WithInstance still match the original sentinel.
func (d *DetailedError) Is(target error) bool {
	if t, ok := target.(*DetailedError); ok {
		return d.err.Error() == t.err.Error()
	}

	return false
}

func (d *DetailedError) WithGUID(guid string) *DetailedError {
	if d == nil {
		return nil
	}

	return &DetailedError{err: d.err, guid: guid, details: d.details, instance: d.instance}
}

func (d *DetailedError) WithDetail(detail string) *DetailedError {
	if d == nil {
		return nil
	}

	return &DetailedError{err: d.err, guid: d.guid, details: detail, instance: d.instance}
}

func (d *DetailedError) WithInstance(instance string) *DetailedError {
	if d == nil {
		return nil
	}

	return &DetailedError{err: d.err, guid: d.guid, details: d.details, instance: instance}
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
	ErrAllBackendConfigError                   = NewDetailedError("configuration errors in all Database sections")
	ErrUnsupportedMediaType                    = errors.New("unsupported media type")
	ErrFeatureBackendServersMonitoringDisabled = errors.New("backend_server_monitoring not enabled")
	ErrMonitoringBackendServersEmpty           = errors.New("no monitoring backend servers configured")
	ErrInvalidUsername                         = errors.New("invalid username")
	ErrEmptyUsername                           = errors.New("empty_username")
	ErrEmptyPassword                           = errors.New("empty_password")
	ErrPasswordEncoding                        = errors.New("password encoding error")
	ErrIncorrectCache                          = errors.New("incorrect cache")
	ErrUnregisteredComponent                   = errors.New("unregistered component")
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
	ErrNoLDAPSection       = errors.New("no 'ldap:' section found")
	ErrNoLDAPSearchSection = errors.New("no 'ldap::search:' section found")
)

// ldap.

var (
	ErrLDAPConnect        = NewDetailedError("ldap_servers_connect_error")
	ErrLDAPConfig         = NewDetailedError("ldap_config_error")
	ErrNoLDAPSearchResult = NewDetailedError("ldap_no_search_result")
	ErrLDAPConnectTimeout = NewDetailedError("ldap_connect_timeout")
	ErrLDAPSearchTimeout  = NewDetailedError("ldap_search_timeout")
	ErrLDAPBindTimeout    = NewDetailedError("ldap_bind_timeout")
	ErrLDAPModify         = NewDetailedError("ldap_modify_error")
	// ErrLDAPPoolExhausted indicates that the LDAP pool could not serve the request
	// within the allotted time (capacity token acquisition or waiting for a free
	// connection timed out). Callers should treat this as a temporary failure and
	// avoid mapping it to "user not found".
	ErrLDAPPoolExhausted = NewDetailedError("ldap_pool_exhausted")
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
	ErrNoPassDBResult  = errors.New("no pass Database result")
	ErrUnknownCause    = errors.New("something went wrong")
	ErrDurationTooHigh = errors.New("duration of too high")
)

// bruteforce.

var (
	ErrRuleNoIPv4AndIPv6      = errors.New("do not set 'ipv4' and 'ipv6' at the same time in a rule")
	ErrRuleMissingIPv4AndIPv6 = errors.New("neither 'ipv4' nor 'ipv6' specified in rule")
	ErrWrongIPAddress         = errors.New("unable to parse IP address")
)

// auth.

var (
	ErrNoAccount        = errors.New("no account found")
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
	ErrNoFeatureDefined         = errors.New("no feature defined")
	ErrNoFiltersDefined         = errors.New("no filters defined")
	ErrFilterLuaNameMissing     = errors.New("filter 'name' sttribute missing")
	ErrFilterLuaScriptPathEmpty = errors.New("filter 'script_path' attribute missing")
)

// misc.

var (
	ErrNotImplemented = errors.New("not implemented yet")
	ErrInvalidRange   = errors.New("invalid range")
)

// connection.

var (
	ErrMissingTLS = errors.New("missing TLS connection")
)
