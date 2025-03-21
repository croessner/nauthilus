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
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// CommonRequest represents a common request object with various properties used in different functionalities.
type CommonRequest struct {
	// Debug is a flag indicating if the action is executed in debug mode.
	Debug bool

	// Repeating is a flag indicating if the action would be repeated.
	Repeating bool

	// UserFound is a flag indicating if the user executing the action was found in the system.
	UserFound bool

	// Authenticated is a flag indicating if the user is authenticated.
	Authenticated bool

	// NoAuth is a flag indicating if the action requires no authentication.
	NoAuth bool

	// BruteForceCounter keeps track of unsuccessful login attempts for the user.
	BruteForceCounter uint

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
	Password string

	// Protocol stores the protocol that the user used to authenticate.
	Protocol string

	// BruteForceName stores the name of the brute force protection mechanism.
	BruteForceName string

	// FeatureName is a feature that triggered the action.
	FeatureName string

	// StatusMessage is a configurable message that is returned to the client upon errors (not tempfail).
	StatusMessage *string

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
}

// LoaderModHTTPRequest is a function that returns a LGFunction which sets up a Lua module for handling HTTP requests.
// The module creates Lua functions that can be used to retrieve HTTP request headers and body.
//
// Parameters:
// - httpRequest: A pointer to the http.Request object.
//
// Returns:
// - A LGFunction that creates the Lua module and sets up the Lua functions.
func LoaderModHTTPRequest(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnGetAllHTTPRequestHeaders: GetAllHTTPRequestHeaders(httpRequest),
			definitions.LuaFnGetHTTPRequestHeader:     GetHTTPRequestHeader(httpRequest),
			definitions.LuaFnGetHTTPRequestBody:       GetHTTPRequestBody(httpRequest),
		})

		L.Push(mod)

		return 1
	}
}

// SetupRequest sets up the request object with the common request properties
func (c *CommonRequest) SetupRequest(request *lua.LTable) *lua.LTable {
	logFormat := definitions.LogFormatDefault
	logLevel := config.GetFile().GetServer().Log.Level.Get()

	if config.GetFile().GetServer().Log.JSON {
		logFormat = definitions.LogFormatJSON
	}

	request.RawSet(lua.LString(definitions.LuaRequestDebug), lua.LBool(c.Debug))
	request.RawSet(lua.LString(definitions.LuaRequestRepeating), lua.LBool(c.Repeating))
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
	request.RawSetString(definitions.LuaRequestPassword, lua.LString(c.Password))
	request.RawSetString(definitions.LuaRequestProtocol, lua.LString(c.Protocol))
	request.RawSetString(definitions.LuaRequestBruteForceBucket, lua.LString(c.BruteForceName))
	request.RawSetString(definitions.LuaRequestFeature, lua.LString(c.FeatureName))
	request.RawSetString(definitions.LuaRequestStatusMessage, lua.LString(*c.StatusMessage))
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

	request.RawSetString(definitions.LuaRequestLogFormat, lua.LString(logFormat))
	request.RawSetString(definitions.LuaRequestLogLevel, lua.LString(logLevel))

	return request
}

func SetStatusMessage(status **string) lua.LGFunction {
	return func(L *lua.LState) int {
		newStatus := L.CheckString(1)

		*status = &newStatus

		return 0
	}
}

// GetAllHTTPRequestHeaders returns a LGFunction that creates a Lua table containing all headers from the http.Request object
// The table is indexed by the lowercase header name and each header's value is a list of strings
// The function expects a *http.Request object as its parameter
//
// Example usage:
//
//	headers := getAllHeaders(request)
//	L.SetGlobal("getAllHeaders", L.NewClosure(headers))
//	result := L.DoString(`
//	  local headers = getAllHeaders()
//	  print(headers["content-type"][1]) -- print the first value of the "content-type" header
//	`)
//	if result != nil {
//	  fmt.Println("Error:", result)
//	}
func GetAllHTTPRequestHeaders(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		headerTable := L.NewTable()

		for headerName, headerValues := range httpRequest.Header {
			headerName = strings.ToLower(headerName)

			headerList := L.NewTable()

			for _, headerValue := range headerValues {
				headerList.Append(lua.LString(headerValue))
			}

			headerTable.RawSetString(headerName, headerList)
		}

		L.Push(headerTable)

		return 1
	}
}

// GetHTTPRequestHeader returns a LGFunction that retrieves a specific header from the http.Request object
// The function expects a *http.Request object as its parameter and the name of the requested header as a string
// If the requested header exists, it creates a Lua table containing the header's value as a list of strings
// The table is indexed by the lowercase header name
// createHeaderTable is a helper function that creates a Lua table for a header value
// It takes an LState, an LTable, the header name, and a list of header values as parameters
func GetHTTPRequestHeader(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		reqzestedHeader := strings.ToLower(L.CheckString(1))
		headerValueTable := L.NewTable()

		for headerName, headerValues := range httpRequest.Header {
			headerName = strings.ToLower(headerName)

			if headerName != reqzestedHeader {
				continue
			}

			for _, headerValue := range headerValues {
				headerValueTable.Append(lua.LString(headerValue))
			}

			break
		}

		L.Push(headerValueTable)

		return 1
	}
}

// GetHTTPRequestBody reads the HTTP request body and returns it as a Lua string.
// The function expects one parameter: the HTTP request object.
// It returns the request body as a Lua string.
// If an error occurs, it raises a Lua error with the error message and returns 0.
// The read request body is then assigned back to the request's body for the next handler.
func GetHTTPRequestBody(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		// Read the HTTP body
		bodyBytes, err := io.ReadAll(httpRequest.Body)
		if err != nil {
			L.RaiseError("failed to read request body: %v", err)

			return 0
		}

		// Make sure the body is readable for the next handler...
		httpRequest.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		L.Push(lua.LString(bodyBytes))

		return 1
	}
}
