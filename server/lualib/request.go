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

package lualib

import (
	"sync"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	lua "github.com/yuin/gopher-lua"
)

// commonRequestPool is a sync.Pool for CommonRequest objects to reduce memory allocations.
var commonRequestPool = sync.Pool{
	New: func() any {
		return &CommonRequest{}
	},
}

// GetCommonRequest gets a CommonRequest from the pool or creates a new one if the pool is empty.
func GetCommonRequest() *CommonRequest {
	return commonRequestPool.Get().(*CommonRequest)
}

// PutCommonRequest returns a CommonRequest to the pool after resetting it.
func PutCommonRequest(cr *CommonRequest) {
	cr.Reset()
	commonRequestPool.Put(cr)
}

// CommonRequest represents a common request object with various properties used in different functionalities.
type CommonRequest struct {
	// BackendServers holds the list of backend servers.
	BackendServers []*config.BackendServer

	// TOTPRecoveryCodes stores the user's TOTP recovery codes.
	TOTPRecoveryCodes []string

	// RequestedScopes holds the OIDC scopes requested by the client.
	RequestedScopes []string

	// UserGroups holds the user's group memberships (e.g. from LDAP memberOf).
	UserGroups []string

	// AllowedClientScopes holds the configured allowed scopes for the OIDC client.
	AllowedClientScopes []string

	// AllowedClientGrantTypes holds the configured allowed grant types for the OIDC client.
	AllowedClientGrantTypes []string

	// Service is the http routers endpoint name.
	Service string

	// Session stores the unique session identifier.
	Session string // GUID

	// ClientIP stores the IP address of the client.
	ClientIP string

	// ClientPort stores the port number used by the client.
	ClientPort string

	// ClientNet stores the network used by the client.
	ClientNet string

	// ClientHost stores the hostname of the client.
	ClientHost string

	// ClientID stores the unique identifier for the client.
	ClientID string

	// UserAgent stores toe User-Agent of the client.
	UserAgent string

	// LocalIP stores the IP address of the local machine.
	LocalIP string

	// LocalPort stores the port number used by the local machine.
	LocalPort string

	// Username stores the username of the user that was used to authenticate.
	Username string

	// Account stores the user's account information.
	Account string

	// AccountField stores the user's account field.
	AccountField string

	// UniqueUserID stores the unique user identifier.
	UniqueUserID string

	// DisplayName stores the user's display name.
	DisplayName string

	// Password stores the user's password.
	Password []byte

	// WebAuthnCredential stores a serialized WebAuthn credential (JSON).
	WebAuthnCredential string

	// WebAuthnOldCredential stores a serialized WebAuthn credential (JSON).
	WebAuthnOldCredential string

	// Protocol stores the protocol that the user used to authenticate.
	Protocol string

	// Method stores the authentication method used.
	Method string

	// OIDCCID represents the OpenID Connect Client ID used for authentication.
	OIDCCID string

	// SAMLEntityID represents the SAML Entity ID used for authentication.
	SAMLEntityID string

	// GrantType represents the OIDC grant type used for the current flow.
	GrantType string

	// OIDCClientName represents the human-readable OIDC client name.
	OIDCClientName string

	// RedirectURI represents the requested redirect URI for OIDC flows.
	RedirectURI string

	// MFAMethod represents the MFA method used (e.g. totp, webauthn, recovery).
	MFAMethod string

	// BruteForceName stores the name of the brute force protection mechanism.
	BruteForceName string

	// FeatureName is a feature that triggered the action.
	FeatureName string

	// XSSL contains SSL information.
	XSSL string

	// XSSLSessionID is the SSL session identifier.
	XSSLSessionID string

	// XSSLClientVerify indicates whether SSL client is verified.
	XSSLClientVerify string

	// XSSLClientDN is the client's Distinguished Name in the SSL certificate.
	XSSLClientDN string

	// XSSLClientCN is the client's Common Name in the SSL certificate.
	XSSLClientCN string

	// XSSLIssuer is the issuer of the SSL certificate.
	XSSLIssuer string

	// XSSLClientNotBefore is the date before which the SSL certificate is not valid.
	XSSLClientNotBefore string

	// XSSLClientNotAfter is the date after which the SSL certificate is not valid.
	XSSLClientNotAfter string

	// XSSLSubjectDN is the Subject's Distinguished Name in the SSL certificate.
	XSSLSubjectDN string

	// XSSLIssuerDN is the Issuer's Distinguished Name in the SSL certificate.
	XSSLIssuerDN string

	// XSSLClientSubjectDN is the client's Subject Distinguished Name in the SSL certificate.
	XSSLClientSubjectDN string

	// XSSLClientIssuerDN is the client's Issuer Distinguished Name in the SSL certificate.
	XSSLClientIssuerDN string

	// XSSLProtocol is the SSL protocol used.
	XSSLProtocol string

	// XSSLCipher is the encryption cipher used in the SSL protocol.
	XSSLCipher string

	// SSLSerial is the serial number of the SSL certificate used for secure communication.
	SSLSerial string

	// SSLFingerprint represents the SSL certificate's fingerprint for the client in the request.
	SSLFingerprint string

	// RedisPrefix is the redis prefix for keys.
	RedisPrefix string

	// StatusMessage is a configurable message that is returned to the client upon errors (not tempfail).
	StatusMessage *string

	// UsedBackendAddr holds the address of the backend server used for authentication.
	UsedBackendAddr *string

	// UsedBackendPort holds the port of the backend server used for authentication.
	UsedBackendPort *int

	// Latency represents the request latency in milliseconds.
	Latency float64

	// BruteForceCounter keeps track of unsuccessful login attempts for the user.
	BruteForceCounter uint

	// HTTPStatus represents the HTTP status code.
	HTTPStatus int

	// Debug is a flag indicating if the action is executed in debug mode.
	Debug bool

	// Repeating is a flag indicating if the action would be repeated.
	Repeating bool

	// RWP indicates whether the request was identified as a Repeating Wrong Password.
	// When true, bucket counters were NOT increased because the same wrong password was repeated.
	RWP bool

	// UserFound is a flag indicating if the user executing the action was found in the system.
	UserFound bool

	// Authenticated is a flag indicating if the user is authenticated.
	Authenticated bool

	// NoAuth is a flag indicating if the action requires no authentication.
	NoAuth bool

	// MFACompleted indicates whether MFA verification was successfully completed.
	MFACompleted bool
}

// Reset resets all fields of the CommonRequest to their zero values.
func (c *CommonRequest) Reset() {
	c.BackendServers = nil
	c.TOTPRecoveryCodes = nil
	c.RequestedScopes = nil
	c.UserGroups = nil
	c.AllowedClientScopes = nil
	c.AllowedClientGrantTypes = nil
	c.Service = ""
	c.Session = ""
	c.ClientIP = ""
	c.ClientPort = ""
	c.ClientNet = ""
	c.ClientHost = ""
	c.ClientID = ""
	c.UserAgent = ""
	c.LocalIP = ""
	c.LocalPort = ""
	c.Username = ""
	c.Account = ""
	c.AccountField = ""
	c.UniqueUserID = ""
	c.DisplayName = ""
	if len(c.Password) > 0 {
		clear(c.Password)
	}

	c.Password = nil
	c.WebAuthnCredential = ""
	c.WebAuthnOldCredential = ""
	c.Protocol = ""
	c.Method = ""
	c.OIDCCID = ""
	c.SAMLEntityID = ""
	c.GrantType = ""
	c.OIDCClientName = ""
	c.RedirectURI = ""
	c.MFAMethod = ""
	c.BruteForceName = ""
	c.FeatureName = ""
	c.XSSL = ""
	c.XSSLSessionID = ""
	c.XSSLClientVerify = ""
	c.XSSLClientDN = ""
	c.XSSLClientCN = ""
	c.XSSLIssuer = ""
	c.XSSLClientNotBefore = ""
	c.XSSLClientNotAfter = ""
	c.XSSLSubjectDN = ""
	c.XSSLIssuerDN = ""
	c.XSSLClientSubjectDN = ""
	c.XSSLClientIssuerDN = ""
	c.XSSLProtocol = ""
	c.XSSLCipher = ""
	c.SSLSerial = ""
	c.SSLFingerprint = ""
	c.RedisPrefix = ""
	c.StatusMessage = nil
	c.UsedBackendAddr = nil
	c.UsedBackendPort = nil
	c.Latency = 0
	c.BruteForceCounter = 0
	c.HTTPStatus = 0
	c.Debug = false
	c.Repeating = false
	c.RWP = false
	c.UserFound = false
	c.Authenticated = false
	c.NoAuth = false
	c.MFACompleted = false
}

// setStringSliceField writes a string slice as a Lua table into the given request table.
// If the slice is empty, an empty table is set.
func (c *CommonRequest) setStringSliceField(L *lua.LState, request *lua.LTable, key string, values []string) {
	tbl := L.NewTable()

	for _, v := range values {
		tbl.Append(lua.LString(v))
	}

	request.RawSetString(key, tbl)
}

// SetupRequest sets up the request object with the common request properties
func (c *CommonRequest) SetupRequest(L *lua.LState, cfg config.File, request *lua.LTable) *lua.LTable {
	logFormat := definitions.LogFormatDefault
	logLevel := ""

	if cfg != nil {
		logLevel = cfg.GetServer().GetLog().GetLogLevelName()

		if cfg.GetServer().GetLog().IsLogFormatJSON() {
			logFormat = definitions.LogFormatJSON
		}
	}

	request.RawSet(lua.LString(definitions.LuaRequestDebug), lua.LBool(c.Debug))
	request.RawSet(lua.LString(definitions.LuaRequestRepeating), lua.LBool(c.Repeating))
	request.RawSet(lua.LString(definitions.LuaRequestRWP), lua.LBool(c.RWP))
	request.RawSet(lua.LString(definitions.LuaRequestUserFound), lua.LBool(c.UserFound))
	request.RawSet(lua.LString(definitions.LuaRequestAuthenticated), lua.LBool(c.Authenticated))
	request.RawSet(lua.LString(definitions.LuaRequestNoAuth), lua.LBool(c.NoAuth))

	request.RawSet(lua.LString(definitions.LuaRequestBruteForceCounter), lua.LNumber(c.BruteForceCounter))

	request.RawSetString(definitions.LuaRequestService, lua.LString(c.Service))
	request.RawSetString(definitions.LuaRequestSession, lua.LString(c.Session))
	request.RawSetString(definitions.LuaRequestClientIP, lua.LString(c.ClientIP))
	request.RawSetString(definitions.LuaRequestClientPort, lua.LString(c.ClientPort))
	request.RawSetString(definitions.LuaRequestClientNet, lua.LString(c.ClientNet))
	request.RawSetString(definitions.LuaRequestClientHost, lua.LString(c.ClientHost))
	request.RawSetString(definitions.LuaRequestClientID, lua.LString(c.ClientID))
	request.RawSetString(definitions.LuaRequestUserAgent, lua.LString(c.UserAgent))
	request.RawSetString(definitions.LuaRequestLocalIP, lua.LString(c.LocalIP))
	request.RawSetString(definitions.LuaRequestLocalPort, lua.LString(c.LocalPort))
	request.RawSetString(definitions.LuaRequestUsername, lua.LString(c.Username))
	request.RawSetString(definitions.LuaRequestAccount, lua.LString(c.Account))
	request.RawSetString(definitions.LuaRequestAccountField, lua.LString(c.AccountField))
	request.RawSetString(definitions.LuaRequestUniqueUserID, lua.LString(c.UniqueUserID))
	request.RawSetString(definitions.LuaRequestDisplayName, lua.LString(c.DisplayName))
	if len(c.TOTPRecoveryCodes) > 0 {
		recoveryTable := L.NewTable()
		for _, code := range c.TOTPRecoveryCodes {
			recoveryTable.Append(lua.LString(code))
		}
		request.RawSetString(definitions.LuaRequestTOTPRecoveryCodes, recoveryTable)
	}
	request.RawSetString(definitions.LuaRequestPassword, lua.LString(string(c.Password)))
	request.RawSetString(definitions.LuaRequestWebAuthnCredential, lua.LString(c.WebAuthnCredential))
	request.RawSetString(definitions.LuaRequestWebAuthnOldCredential, lua.LString(c.WebAuthnOldCredential))
	request.RawSetString(definitions.LuaRequestProtocol, lua.LString(c.Protocol))
	request.RawSetString(definitions.LuaRequestMethod, lua.LString(c.Method))
	request.RawSetString(definitions.LuaRequestOIDCCID, lua.LString(c.OIDCCID))
	request.RawSetString(definitions.LuaRequestSAMLEntityID, lua.LString(c.SAMLEntityID))
	request.RawSetString(definitions.LuaRequestGrantType, lua.LString(c.GrantType))
	request.RawSetString(definitions.LuaRequestOIDCClientName, lua.LString(c.OIDCClientName))
	request.RawSetString(definitions.LuaRequestRedirectURI, lua.LString(c.RedirectURI))
	request.RawSetString(definitions.LuaRequestMFAMethod, lua.LString(c.MFAMethod))
	request.RawSet(lua.LString(definitions.LuaRequestMFACompleted), lua.LBool(c.MFACompleted))

	c.setStringSliceField(L, request, definitions.LuaRequestRequestedScopes, c.RequestedScopes)
	c.setStringSliceField(L, request, definitions.LuaRequestUserGroups, c.UserGroups)
	c.setStringSliceField(L, request, definitions.LuaRequestAllowedClientScopes, c.AllowedClientScopes)
	c.setStringSliceField(L, request, definitions.LuaRequestAllowedClientGrantTypes, c.AllowedClientGrantTypes)

	request.RawSetString(definitions.LuaRequestBruteForceBucket, lua.LString(c.BruteForceName))
	request.RawSetString(definitions.LuaRequestFeature, lua.LString(c.FeatureName))
	if c.StatusMessage != nil {
		request.RawSetString(definitions.LuaRequestStatusMessage, lua.LString(*c.StatusMessage))
	}
	request.RawSetString(definitions.LuaRequestXSSL, lua.LString(c.XSSL))
	request.RawSetString(definitions.LuaRequestXSSSLSessionID, lua.LString(c.XSSLSessionID))
	request.RawSetString(definitions.LuaRequestXSSLClientVerify, lua.LString(c.XSSLClientVerify))
	request.RawSetString(definitions.LuaRequestXSSLClientDN, lua.LString(c.XSSLClientDN))
	request.RawSetString(definitions.LuaRequestXSSLClientCN, lua.LString(c.XSSLClientCN))
	request.RawSetString(definitions.LuaRequestXSSLIssuer, lua.LString(c.XSSLIssuer))
	request.RawSetString(definitions.LuaRequestXSSLClientNotBefore, lua.LString(c.XSSLClientNotBefore))
	request.RawSetString(definitions.LuaRequestXSSLClientNotAfter, lua.LString(c.XSSLClientNotAfter))
	request.RawSetString(definitions.LuaRequestXSSLSubjectDN, lua.LString(c.XSSLSubjectDN))
	request.RawSetString(definitions.LuaRequestXSSLIssuerDN, lua.LString(c.XSSLIssuerDN))
	request.RawSetString(definitions.LuaRequestXSSLClientSubjectDN, lua.LString(c.XSSLClientSubjectDN))
	request.RawSetString(definitions.LuaRequestXSSLClientIssuerDN, lua.LString(c.XSSLClientIssuerDN))
	request.RawSetString(definitions.LuaRequestXSSLProtocol, lua.LString(c.XSSLProtocol))
	request.RawSetString(definitions.LuaRequestXSSLCipher, lua.LString(c.XSSLCipher))
	request.RawSetString(definitions.LuaRequestSSLSerial, lua.LString(c.SSLSerial))
	request.RawSetString(definitions.LuaRequestSSLFingerprint, lua.LString(c.SSLFingerprint))

	logging := L.NewTable()
	logging.RawSetString(definitions.LuaRequestLogFormat, lua.LString(logFormat))
	logging.RawSetString(definitions.LuaRequestLogLevel, lua.LString(logLevel))

	request.RawSetString("logging", logging)

	request.RawSetString(definitions.LuaRequestLogFormat, lua.LString(logFormat))
	request.RawSetString(definitions.LuaRequestLogLevel, lua.LString(logLevel))

	request.RawSetString(definitions.LuaRequestLatency, lua.LNumber(c.Latency))
	request.RawSetString(definitions.LuaRequestHTTPStatus, lua.LNumber(c.HTTPStatus))

	request.RawSetString(definitions.LuaRequestRedisPrefix, lua.LString(c.RedisPrefix))

	return request
}

// SetStatusMessage sets a new status message by updating the provided string pointer based on the input from the Lua state.
func SetStatusMessage(status **string) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		newStatus := stack.CheckString(1)

		if *status != nil {
			**status = newStatus
		} else {
			*status = &newStatus
		}

		return 0
	}
}
