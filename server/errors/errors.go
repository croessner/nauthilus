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

// Package errors provides errors functionality.
package errors

import (
	"errors"
)

// DetailedError describes the exported DetailedError type.
type DetailedError struct {
	err      error
	guid     string
	details  string
	instance string
}

func (d *DetailedError) Error() string {
	if d.details != "" {
		return d.err.Error() + ": " + d.details
	}

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

// WithGUID provides the exported WithGUID method.
func (d *DetailedError) WithGUID(guid string) *DetailedError {
	if d == nil {
		return nil
	}

	return &DetailedError{err: d.err, guid: guid, details: d.details, instance: d.instance}
}

// WithDetail provides the exported WithDetail method.
func (d *DetailedError) WithDetail(detail string) *DetailedError {
	if d == nil {
		return nil
	}

	return &DetailedError{err: d.err, guid: d.guid, details: detail, instance: d.instance}
}

// WithInstance provides the exported WithInstance method.
func (d *DetailedError) WithInstance(instance string) *DetailedError {
	if d == nil {
		return nil
	}

	return &DetailedError{err: d.err, guid: d.guid, details: d.details, instance: instance}
}

// GetGUID provides the exported GetGUID method.
func (d *DetailedError) GetGUID() string {
	return d.guid
}

// GetDetails provides the exported GetDetails method.
func (d *DetailedError) GetDetails() string {
	return d.details
}

// GetInstance provides the exported GetInstance method.
func (d *DetailedError) GetInstance() string {
	return d.instance
}

// NewDetailedError provides the exported NewDetailedError function.
func NewDetailedError(err string) *DetailedError {
	return &DetailedError{err: errors.New(err)}
}

// auth.

var (
	// ErrAllBackendConfigError reports that every configured backend section failed validation.
	ErrAllBackendConfigError = NewDetailedError("configuration errors in all Database sections")
	// ErrUnsupportedMediaType reports an unsupported request content type.
	ErrUnsupportedMediaType = errors.New("unsupported media type")
	// ErrBackendHealthChecksDisabled reports that backend health checks are not enabled.
	ErrBackendHealthChecksDisabled = errors.New("backend_health_checks not enabled")
	// ErrMonitoringBackendServersEmpty reports that backend monitoring has no configured targets.
	ErrMonitoringBackendServersEmpty = errors.New("no monitoring backend servers configured")
	// ErrInvalidUsername reports a syntactically invalid username.
	ErrInvalidUsername = errors.New("invalid username")
	// ErrEmptyUsername reports an empty username.
	ErrEmptyUsername = errors.New("empty_username")
	// ErrEmptyPassword reports an empty password.
	ErrEmptyPassword = errors.New("empty_password")
	// ErrPasswordEncoding reports a password encoding failure.
	ErrPasswordEncoding = errors.New("password encoding error")
	// ErrIncorrectCache reports an unexpected cache backend state.
	ErrIncorrectCache = errors.New("incorrect cache")
	// ErrUnregisteredComponent reports an unknown application component.
	ErrUnregisteredComponent = errors.New("unregistered component")
)

// env.

var (
	// ErrWrongVerboseLevel reports an invalid verbosity configuration value.
	ErrWrongVerboseLevel = errors.New("wrong verbose level: <%s>")
	// ErrWrongLDAPScope reports an invalid LDAP scope configuration value.
	ErrWrongLDAPScope = errors.New("wrong LDAP scope: <%s>")
	// ErrWrongPassDB reports an invalid passdb backend configuration value.
	ErrWrongPassDB = errors.New("wrong passdb backend: <%s>")
	// ErrWrongRuntimeModule reports an invalid runtime module configuration value.
	ErrWrongRuntimeModule = errors.New("wrong runtime module: <%s>")
	// ErrWrongDebugModule reports an invalid debug module configuration value.
	ErrWrongDebugModule = errors.New("wrong debug module: <%s>")
)

// file.

var (
	// ErrNoLDAPSection reports that the LDAP backend root is missing.
	ErrNoLDAPSection = errors.New("no 'auth.backends.ldap' section found")
	// ErrNoLDAPSearchSection reports that no LDAP protocol mappings are configured.
	ErrNoLDAPSearchSection = errors.New("no 'auth.backends.ldap.search' section found")
)

// ldap.

var (
	// ErrLDAPConnect is an exported package value.
	ErrLDAPConnect = NewDetailedError("ldap_servers_connect_error")
	// ErrLDAPConfig is an exported package value.
	ErrLDAPConfig = NewDetailedError("ldap_config_error")
	// ErrNoLDAPSearchResult reports that an LDAP search returned no matching entry.
	ErrNoLDAPSearchResult = NewDetailedError("ldap_no_search_result")
	// ErrLDAPConnectTimeout reports that an LDAP connection attempt timed out.
	ErrLDAPConnectTimeout = NewDetailedError("ldap_connect_timeout")
	// ErrLDAPSearchTimeout reports that an LDAP search operation timed out.
	ErrLDAPSearchTimeout = NewDetailedError("ldap_search_timeout")
	// ErrLDAPBindTimeout reports that an LDAP bind operation timed out.
	ErrLDAPBindTimeout = NewDetailedError("ldap_bind_timeout")
	// ErrLDAPModify reports that an LDAP modify operation failed.
	ErrLDAPModify = NewDetailedError("ldap_modify_error")
	// ErrLDAPPoolExhausted indicates that the LDAP pool could not serve the request
	// within the allotted time (capacity token acquisition or waiting for a free
	// connection timed out). Callers should treat this as a temporary failure and
	// avoid mapping it to "user not found".
	ErrLDAPPoolExhausted = NewDetailedError("ldap_pool_exhausted")
	// ErrBackendTemporaryFailure indicates that a backend could not make an auth
	// decision because of a temporary technical failure.
	ErrBackendTemporaryFailure = NewDetailedError("backend_temporary_failure")
)

// lua.

var (
	// ErrLuaConfig is an exported package value.
	ErrLuaConfig = NewDetailedError("lua_config_error")
	// ErrBackendLuaWrongUserData is an exported package value.
	ErrBackendLuaWrongUserData = NewDetailedError("wrong_user_data_result")
	// ErrBackendLua reports a Lua script execution failure.
	ErrBackendLua = NewDetailedError("script_execution_failed")
)

// util.

var (
	// ErrUnsupportedAlgorithm is an exported package value.
	ErrUnsupportedAlgorithm = errors.New("unsupported hash algorithm")
	// ErrUnsupportedPasswordOption is an exported package value.
	ErrUnsupportedPasswordOption = errors.New("unsupported password option")
)

// common.

var (
	// ErrNoPassDBResult is an exported package value.
	ErrNoPassDBResult = errors.New("no pass Database result")
	// ErrUnknownCause is an exported package value.
	ErrUnknownCause = errors.New("something went wrong")
	// ErrDurationTooHigh reports an out-of-range duration value.
	ErrDurationTooHigh = errors.New("duration of too high")
)

// bruteforce.

var (
	// ErrRuleNoIPv4AndIPv6 is an exported package value.
	ErrRuleNoIPv4AndIPv6 = errors.New("do not set 'ipv4' and 'ipv6' at the same time in a rule")
	// ErrRuleMissingIPv4AndIPv6 is an exported package value.
	ErrRuleMissingIPv4AndIPv6 = errors.New("neither 'ipv4' nor 'ipv6' specified in rule")
	// ErrWrongIPAddress reports an invalid IP address value.
	ErrWrongIPAddress = errors.New("unable to parse IP address")
)

// auth.

var (
	// ErrNoAccount is an exported package value.
	ErrNoAccount = errors.New("no account found")
	// ErrNoTLS is an exported package value.
	ErrNoTLS = errors.New("no tls connection")
	// ErrTOTPCodeInvalid reports an invalid TOTP code.
	ErrTOTPCodeInvalid = errors.New("totp code invalid")
	// ErrNoTOTPCode reports that no TOTP code was provided.
	ErrNoTOTPCode = errors.New("totp code not found")
	// ErrBruteForceAttack reports that brute-force protections blocked the request.
	ErrBruteForceAttack = errors.New("please contact the support")
)

// DNS and runtime controls.

var (
	// ErrDNSResolver is an exported package value.
	ErrDNSResolver = errors.New("resolver failed")
)

// http.

var (
	// ErrLanguageNotFound is an exported package value.
	ErrLanguageNotFound = errors.New("requested language not found")
	// ErrUnauthorized is an exported package value.
	ErrUnauthorized = errors.New("unauthorized")
)

// register.

var (
	// ErrNotLoggedIn is an exported package value.
	ErrNotLoggedIn = errors.New("user not logged in")
	// ErrNoTOTPURL is an exported package value.
	ErrNoTOTPURL = errors.New("no TOTP URL found")
)

// webauthn.

var (
	// ErrWebAuthnSessionData is an exported package value.
	ErrWebAuthnSessionData = errors.New("no webauthn session data found")
	// ErrNoDisplayName is an exported package value.
	ErrNoDisplayName = errors.New("no display name found")
	// ErrUnknownDatabaseBackend reports an unsupported database backend.
	ErrUnknownDatabaseBackend = errors.New("unknown Database backend")
)

// Lua environment sources.

var (
	// ErrEnvironmentSourceLuaNameMissing indicates a Lua environment source without a name.
	ErrEnvironmentSourceLuaNameMissing = errors.New("environment source 'name' attribute missing")

	// ErrEnvironmentSourceLuaScriptPathEmpty indicates a Lua environment source without a script path.
	ErrEnvironmentSourceLuaScriptPathEmpty = errors.New("environment source 'script_path' attribute missing")
)

// Lua subject sources.

var (
	// ErrNoRuntimeModuleDefined indicates that a required runtime module was not configured.
	ErrNoRuntimeModuleDefined = errors.New("no runtime module defined")

	// ErrNoSubjectSourcesDefined indicates that no Lua subject sources are configured.
	ErrNoSubjectSourcesDefined = errors.New("no subject sources defined")

	// ErrSubjectSourceLuaNameMissing indicates a Lua subject source without a name.
	ErrSubjectSourceLuaNameMissing = errors.New("subject source 'name' attribute missing")

	// ErrSubjectSourceLuaScriptPathEmpty indicates a Lua subject source without a script path.
	ErrSubjectSourceLuaScriptPathEmpty = errors.New("subject source 'script_path' attribute missing")
)

// misc.

var (
	// ErrNotImplemented is an exported package value.
	ErrNotImplemented = errors.New("not implemented yet")
	// ErrInvalidRange is an exported package value.
	ErrInvalidRange = errors.New("invalid range")
)

// connection.

var (
	// ErrMissingTLS is an exported package value.
	ErrMissingTLS = errors.New("missing TLS connection")
)
