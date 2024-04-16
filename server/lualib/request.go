package lualib

import (
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/global"
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
}

// SetupRequest sets up the request object with the common request properties
func (c *CommonRequest) SetupRequest(request *lua.LTable) *lua.LTable {
	request.RawSet(lua.LString(global.LuaRequestDebug), lua.LBool(c.Debug))
	request.RawSet(lua.LString(global.LuaRequestRepeating), lua.LBool(c.Repeating))
	request.RawSet(lua.LString(global.LuaRequestUserFound), lua.LBool(c.UserFound))
	request.RawSet(lua.LString(global.LuaRequestAuthenticated), lua.LBool(c.Authenticated))
	request.RawSet(lua.LString(global.LuaRequestNoAuth), lua.LBool(c.NoAuth))

	request.RawSet(lua.LString(global.LuaRequestBruteForceCounter), lua.LNumber(c.BruteForceCounter))

	request.RawSetString(global.LuaRequestService, lua.LString(c.Service))
	request.RawSetString(global.LuaRequestSession, lua.LString(c.Session))
	request.RawSetString(global.LuaRequestClientIP, lua.LString(c.ClientIP))
	request.RawSetString(global.LuaRequestClientPort, lua.LString(c.ClientPort))
	request.RawSetString(global.LuaRequestClientNet, lua.LString(c.ClientNet))
	request.RawSetString(global.LuaRequestClientHost, lua.LString(c.ClientHost))
	request.RawSetString(global.LuaRequestClientID, lua.LString(c.ClientID))
	request.RawSetString(global.LuaRequestUserAgent, lua.LString(c.UserAgent))
	request.RawSetString(global.LuaRequestLocalIP, lua.LString(c.LocalIP))
	request.RawSetString(global.LuaRequestLocalPort, lua.LString(c.LocalPort))
	request.RawSetString(global.LuaRequestUsername, lua.LString(c.Username))
	request.RawSetString(global.LuaRequestAccount, lua.LString(c.Account))
	request.RawSetString(global.LuaRequestUniqueUserID, lua.LString(c.UniqueUserID))
	request.RawSetString(global.LuaRequestDisplayName, lua.LString(c.DisplayName))
	request.RawSetString(global.LuaRequestPassword, lua.LString(c.Password))
	request.RawSetString(global.LuaRequestProtocol, lua.LString(c.Protocol))
	request.RawSetString(global.LuaRequestBruteForceBucket, lua.LString(c.BruteForceName))
	request.RawSetString(global.LuaRequestFeature, lua.LString(c.FeatureName))
	request.RawSetString(global.LuaRequestStatusMessage, lua.LString(*c.StatusMessage))
	request.RawSetString(global.LuaRequestXSSL, lua.LString(c.XSSL))
	request.RawSetString(global.LuaRequestXSSSLSessionID, lua.LString(c.XSSLSessionID))
	request.RawSetString(global.LuaRequestXSSLClientVerify, lua.LString(c.XSSLClientVerify))
	request.RawSetString(global.LuaRequestXSSLClientDN, lua.LString(c.XSSLClientDN))
	request.RawSetString(global.LuaRequestXSSLClientCN, lua.LString(c.XSSLClientCN))
	request.RawSetString(global.LuaRequestXSSLIssuer, lua.LString(c.XSSLIssuer))
	request.RawSetString(global.LuaRequestXSSLClientNotBefore, lua.LString(c.XSSLClientNotBefore))
	request.RawSetString(global.LuaRequestXSSLClientNotAfter, lua.LString(c.XSSLClientNotAfter))
	request.RawSetString(global.LuaRequestXSSLSubjectDN, lua.LString(c.XSSLSubjectDN))
	request.RawSetString(global.LuaRequestXSSLIssuerDN, lua.LString(c.XSSLIssuerDN))
	request.RawSetString(global.LuaRequestXSSLClientSubjectDN, lua.LString(c.XSSLClientSubjectDN))
	request.RawSetString(global.LuaRequestXSSLClientIssuerDN, lua.LString(c.XSSLClientIssuerDN))
	request.RawSetString(global.LuaRequestXSSLProtocol, lua.LString(c.XSSLProtocol))
	request.RawSetString(global.LuaRequestXSSLCipher, lua.LString(c.XSSLCipher))

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

		for name, headers := range httpRequest.Header {
			name = strings.ToLower(name)

			headerList := L.NewTable()

			for _, h := range headers {
				headerList.Append(lua.LString(h))
			}

			headerTable.RawSetString(name, headerList)
		}

		L.Push(headerTable)

		return 1
	}
}
