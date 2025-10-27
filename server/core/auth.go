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

package core

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/jwtutil"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"golang.org/x/sync/singleflight"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var backchanSF singleflight.Group

// ClaimHandler represents a claim handler struct.
// A claim handler in this context is something to work with JSON Web Tokens (JWT), often used for APIs.
type ClaimHandler struct {
	// Type is the reflected Kind of the claim value.
	Type reflect.Kind

	// ApplyFunc is a function that takes in three parameters: the claim value, the map of claims and the claim key.
	// The function is intended to apply some process on the claim using the provided parameters,
	// and return a boolean result.
	ApplyFunc func(value any, claims map[string]any, claimKey string) bool
}

// BackendServer represents a type for managing a slive of config.BackendServer
type BackendServer struct {
	// backendServer is a slice of pointers to config.BackendServer objects
	backendServer []*config.BackendServer

	// mu provides a read/write mutex for thread-safe operations on the backendServer
	mu sync.RWMutex
}

// Update updates the backendServer field of the BackendServer object with the provided servers slice.
func (n *BackendServer) Update(servers []*config.BackendServer) {
	n.mu.Lock()

	defer n.mu.Unlock()

	n.backendServer = servers
}

func (n *BackendServer) GetTotalServers() int {
	n.mu.RLock()

	defer n.mu.RUnlock()

	return len(n.backendServer)
}

// NewBackendServer creates a new instance of the BackendServer struct.
// It returns a pointer to the newly created BackendServer.
func NewBackendServer() *BackendServer {
	return &BackendServer{}
}

// State is implemented by AuthState and defines the methods to interact with the authentication process.
type State interface {
	// SetUsername sets the username for the current authentication state.
	SetUsername(username string)

	// SetPassword sets the password for the current authentication state.
	SetPassword(password string)

	// SetClientIP sets the client's IP address used during the authentication process.
	SetClientIP(clientIP string)

	// SetClientPort sets the client's port as a string.
	SetClientPort(clientPort string)

	// SetClientHost sets the client host information for the current state using the provided hostname string.
	SetClientHost(clientHost string)

	// SetClientID sets the client ID to the provided string value.
	SetClientID(clientID string)

	// SetStatusCodes sets the current status code associated with the authentication process.
	SetStatusCodes(statusCode string)

	// SetOperationMode sets the operation mode for the authentication process based on the provided gin context.
	SetOperationMode(ctx *gin.Context)

	// SetNoAuth sets the authentication state to no authentication required when true, or requires authentication when false.
	SetNoAuth(bool)

	// SetProtocol sets the authentication protocol to be used during the authentication process.
	SetProtocol(protocol *config.Protocol)

	// GetGUID retrieves the globally unique identifier (GUID) associated with the current authentication state.
	GetGUID() string

	// GetUsername retrieves the username currently stored in the state and returns it as a string.
	GetUsername() string

	// GetPassword retrieves the current password stored in the authentication state as a string.
	GetPassword() string

	// GetProtocol retrieves the protocol configuration associated with the current state.
	GetProtocol() *config.Protocol

	// SetLoginAttempts sets the number of login attempts for the current authentication process.
	SetLoginAttempts(uint)

	// SetMethod sets the authentication method used during the authentication process.
	SetMethod(method string)

	// SetUserAgent sets the user agent information for the current authentication state.
	SetUserAgent(userAgent string)

	// SetLocalIP sets the local IP address for the current state.
	SetLocalIP(localIP string)

	// SetLocalPort sets the local port for the authentication state.
	SetLocalPort(localPort string)

	// SetSSL sets the SSL parameter to the specified value for the authentication process.
	SetSSL(ssl string)

	// SetSSLSessionID sets the SSL session ID associated with the current state for tracking and verification purposes.
	SetSSLSessionID(sslSessionID string)

	// SetSSLClientVerify sets the verification result of the SSL client as a string. Typically used for SSL client validation.
	SetSSLClientVerify(sslClientVerify string)

	// SetSSLClientDN sets the SSL client distinguished name (DN) for the current authentication state.
	SetSSLClientDN(sslClientDN string)

	// SetSSLClientCN sets the Common Name (CN) from the SSL client certificate for the current authentication state.
	SetSSLClientCN(sslClientCN string)

	// SetSSLIssuer sets the SSL issuer string for the current authentication state.
	SetSSLIssuer(sslIssuer string)

	// SetSSLClientNotBefore sets the "not before" validity period for the SSL client certificate.
	SetSSLClientNotBefore(sslClientNotBefore string)

	// SetSSLClientNotAfter sets the expiration date and time of the SSL client certificate.
	SetSSLClientNotAfter(sslClientNotAfter string)

	// SetSSLSubjectDN sets the SSL subject distinguished name (DN) associated with the current authentication state.
	SetSSLSubjectDN(sslSubjectDN string)

	// SetSSLIssuerDN sets the distinguished name (DN) of the SSL issuer for the current state.
	SetSSLIssuerDN(sslIssuerDN string)

	// SetSSLClientSubjectDN sets the distinguished name (DN) of the SSL client certificate's subject.
	SetSSLClientSubjectDN(sslClientSubjectDN string)

	// SetSSLClientIssuerDN sets the distinguished name (DN) of the SSL client issuer to the provided string value.
	SetSSLClientIssuerDN(sslClientIssuerDN string)

	// SetSSLProtocol sets the SSL security protocol for the current authentication session.
	SetSSLProtocol(sslProtocol string)

	// SetSSLCipher sets the SSL cipher used for the client connection.
	SetSSLCipher(sslCipher string)

	// SetSSLSerial sets the SSL serial number for the authentication state.
	SetSSLSerial(sslSerial string)

	// SetSSLFingerprint sets the SSL fingerprint value for the current state.
	SetSSLFingerprint(sslFingerprint string)

	// SetOIDCCID sets the OIDC Client ID for the authentication state.
	SetOIDCCID(oidcCID string)

	// GetAccountOk returns the account field value and a boolean indicating if the account field is present and valid.
	GetAccountOk() (string, bool)

	// GetTOTPSecretOk retrieves the TOTP secret if available and returns it along with a bool indicating its presence.
	GetTOTPSecretOk() (string, bool)

	// GetAccountField retrieves the current account field associated with the authentication process.
	GetAccountField() string

	// GetTOTPSecretField retrieves the TOTP secret field associated with the current authentication state.
	GetTOTPSecretField() string

	// GetTOTPRecoveryField retrieves the TOTP recovery field used during the authentication process.
	GetTOTPRecoveryField() string

	// GetUniqueUserIDField returns the name of the field or attribute that represents a unique user identifier in the database.
	GetUniqueUserIDField() string

	// GetDisplayNameField retrieves the display name field of a user from the current state.
	GetDisplayNameField() string

	// GetUsedPassDBBackend returns the backend used for the password database during the authentication process.
	GetUsedPassDBBackend() definitions.Backend

	// GetAttributes retrieves a map of database attributes where keys are field names and values are the corresponding data.
	GetAttributes() bktype.AttributeMapping

	// GetAdditionalLogs retrieves a slice of additional log entries, useful for appending context-specific logging details.
	GetAdditionalLogs() []any

	// GetClientIP retrieves the client's IP address associated with the current authentication or request context.
	GetClientIP() string

	// PreproccessAuthRequest preprocesses the authentication request and determines if it should be rejected.
	PreproccessAuthRequest(ctx *gin.Context) bool

	// UpdateBruteForceBucketsCounter increments counters to track brute-force attack attempts for the associated client IP.
	UpdateBruteForceBucketsCounter(ctx *gin.Context)

	// HandleAuthentication processes the primary authentication logic based on the request context and service parameters.
	HandleAuthentication(ctx *gin.Context)

	// HandlePassword processes the password-based authentication for a user and returns the authentication result.
	HandlePassword(ctx *gin.Context) definitions.AuthResult

	// ProcessFeatures evaluates and processes feature-related data from the request context.
	// It returns a boolean indicating whether the process should abort further execution.
	ProcessFeatures(ctx *gin.Context) (abort bool)

	// ProcessAuthentication processes authentication requests using.
	ProcessAuthentication(ctx *gin.Context)

	// FilterLua applies Lua-based filtering logic to the provided PassDBResult and execution context.
	// It returns an AuthResult indicating the outcome of the filtering process.
	FilterLua(passDBResult *PassDBResult, ctx *gin.Context) definitions.AuthResult

	// PostLuaAction performs actions or post-processing after executing Lua scripts during authentication workflow.
	PostLuaAction(passDBResult *PassDBResult)

	// WithDefaults configures the State with default values derived from the provided gin.Context.
	WithDefaults(ctx *gin.Context) State

	// WithClientInfo adds client-related information from the provided context to the current authentication state and returns it.
	WithClientInfo(ctx *gin.Context) State

	// WithLocalInfo enriches the authentication state with the client's local information based on the provided context.
	WithLocalInfo(ctx *gin.Context) State

	// WithUserAgent updates the State object with information extracted from the request's User-Agent header.
	WithUserAgent(ctx *gin.Context) State

	// WithXSSL sets XSSL-related context for the authentication process and returns the updated State object.
	WithXSSL(ctx *gin.Context) State

	// InitMethodAndUserAgent initializes the authentication method and user agent fields if they are not already set.
	InitMethodAndUserAgent() State

	// userExists checks if the user exists in the authentication backend.
	// It returns a boolean indicating existence and an error if any issues are encountered.
	userExists() (bool, error)

	// IsMasterUser determines if the authenticated user has master-level privileges, returning true if they do.
	IsMasterUser() bool
}

// AuthState represents a struct that holds information related to an authentication process.
type AuthState struct {
	// StartTime represents the starting time of a client request.
	StartTime time.Time

	// NoAuth is a flag that is set if the request mode does not require authentication.
	NoAuth bool

	// ListAccounts is a flag that is set if Nauthilus is requested to send a full list of available user accounts.
	ListAccounts bool

	// UserFound is a flag that is set if a password Database found the user.
	UserFound bool

	// Authenticated indicates whether the PassDB stage concluded with a decision (success or definitive fail).
	// It is false only for tempfail conditions where no decision could be made.
	Authenticated bool

	// Authorized indicates whether filters allowed the request. It is set by FilterLua.
	Authorized bool

	// PasswordsAccountSeen is a counter increased whenever a new failed password was detected for the current account.
	PasswordsAccountSeen uint

	// PasswordsTotalSeen is a counter increased whenever a new failed password was detected.
	PasswordsTotalSeen uint

	// LoginAttempts is a counter incremented for each failed login request
	LoginAttempts uint

	// StatusCodeOk is the HTTP status code that is set by SetStatusCodes.
	StatusCodeOK int

	// StatusCodeInternalError is the HTTP status code that is set by SetStatusCodes.
	StatusCodeInternalError int

	// StatusCodeFail is the HTTP status code that is set by SetStatusCodes.
	StatusCodeFail int

	// GUID is a global unique identifier inherited in all functions and methods that deal with the
	// authentication process. It is necessary to track log lines belonging to one request.
	GUID *string

	// Method is set by the "Auth-Method" HTTP request header (Nginx protocol). It is typically something like "plain"
	// or "login".
	Method *string

	// AccountField is the name of either an SQL field name or an LDAP attribute that was used to retrieve a user account.
	AccountField *string

	// Username is the value taken from the HTTP header "Auth-User" (Nginx protocol).
	Username string

	// Password is the value taken from the HTTP header "Auth-Pass" (Nginx protocol).
	Password string

	// ClientIP is the IP of a client that is to be authenticated. The value is set by the HTTP request header
	// "Client-IP" (Nginx protocol).
	ClientIP string

	// XClientPort adds the remote client TCP port, which is set by the HTTP request header "X-Client-Port".
	XClientPort string

	// ClientHost is the DNS A name of the remote client. It is set with the HTTP request header "Client-Host" (Nginx
	// protocol).
	ClientHost string

	// HAProxy specific headers
	XSSL                string // %[ssl_fc]
	XSSLSessionID       string // %[ssl_fc_session_id,hex]
	XSSLClientVerify    string // %[ssl_c_verify]
	XSSLClientDN        string // %{+Q}[ssl_c_s_dn]
	XSSLClientCN        string // %{+Q}[ssl_c_s_dn(cn)]
	XSSLIssuer          string // %{+Q}[ssl_c_i_dn]
	XSSLClientNotBefore string // %{+Q}[ssl_c_notbefore]
	XSSLClientNotAfter  string // %{+Q}[ssl_c_notafter]
	XSSLSubjectDN       string // %{+Q}[ssl_c_s_dn]
	XSSLIssuerDN        string // %{+Q}[ssl_c_i_dn]
	XSSLClientSubjectDN string // %{+Q}[ssl_c_s_dn]
	XSSLClientIssuerDN  string // %{+Q}[ssl_c_i_dn]
	XSSLProtocol        string // %[ssl_fc_protocol]
	XSSLCipher          string // %[ssl_fc_cipher]

	// SSLSerial represents the serial number of an SSL certificate as a string.
	SSLSerial string

	// SSLFingerprint represents the fingerprint of an SSL certificate.
	SSLFingerprint string

	// XClientID is delivered by some mail user agents when using IMAP. This value is set by the HTTP request header
	// "X-Client-Id".
	XClientID string

	// XLocalIP is the TCP/IP address of the server that asks for authentication. Its value is set by the HTTP request
	// header "X-Local-IP".
	XLocalIP string

	// XPort is the TCP port of the server that asks for authentication. Its value is set by the HTTP request
	// header "X-Local-Port".
	XPort string

	// UserAgent may have been seent by a mail user agent and is set by the HTTP request header "User-Agent".
	UserAgent *string

	// StatusMessage is the HTTP response payload that is sent to the remote server that asked for authentication.
	StatusMessage string

	// Service is set by Nauthilus depending on the router endpoint. Look at requestHandler for the structure of available
	// endpoints.
	Service string

	// BruteForceName is the canonical name of a brute force bucket that was triggered by a rule.
	BruteForceName string

	// FeatureName is the name of a feature that has triggered a reject.
	FeatureName string

	BackendName string

	// OIDCCID is the OIDC Client ID used for authentication.
	OIDCCID string

	// TOTPSecret is used to store a TOTP secret in an SQL Database.
	TOTPSecret *string

	// TOTPSecretField is the SQL field or LDAP attribute that resolves the TOTP secret for two-factor authentication.
	TOTPSecretField *string

	// TOTPRecoveryField NYI
	TOTPRecoveryField *string

	// UniqueUserIDField is a string representing a unique user identifier.
	UniqueUserIDField *string

	// DisplayNameField is the display name of a user
	DisplayNameField *string

	// AdditionalLogging is a slice of strings that can be filled from Lua features and a Lua backend. Its result will be
	// added to the regular log lines.
	AdditionalLogs []any

	// BruteForceCounter is a map that increments failed login requests. The key is a rule name defined in the
	// configuration file.
	BruteForceCounter map[string]uint

	// BFClientNet is a hint: the CIDR network chosen by the brute-force path for this request (if any).
	BFClientNet string

	// BFRepeating is a hint: whether the request belongs to a historically known brute-force CIDR.
	BFRepeating bool

	// SourcePassDBBackend is a marker for the Database that is responsible for a specific user. It is set by the
	// password Database and stored in Redis to track the authentication flow across databases (including proxy).
	SourcePassDBBackend definitions.Backend

	// UsedPassDBBackend is set by the password Database that answered the current authentication request.
	UsedPassDBBackend definitions.Backend

	// UsedBackendIP is set by a filter Lua script for the Nginx endpoint to set the HTTP response header 'Auth-Server'.
	UsedBackendIP string

	// UsedBackendPort is set by a filter Lua script for the Nginx endpoint to set the HTTP response header 'Auth-Port'.
	UsedBackendPort int

	// Attributes is a result container for SQL and LDAP queries. Databases store their result by using a field or
	// attribute name as a key and the corresponding result as a value.
	Attributes bktype.AttributeMapping

	// Protocol is set by the HTTP request header "Auth-Protocol" (Nginx protocol).
	Protocol *config.Protocol

	// HTTPClientContext tracks the context for an HTTP client connection.
	HTTPClientContext *gin.Context

	// MonitoringFlags is a slice of definitions.Monitoring that is used to skip certain steps while processing an authentication request.
	MonitoringFlags []definitions.Monitoring

	// MasterUserMode is a flag for a backend to indicate a master user mode is ongoing.
	MasterUserMode bool

	*bruteforce.PasswordHistory
	*lualib.Context
}

var _ State = (*AuthState)(nil)

// authStatePool is a sync.Pool for AuthState objects
var authStatePool = sync.Pool{
	New: func() any {
		util.DebugModule(
			definitions.DbgAuth,
			definitions.LogKeyMsg, "Creating new AuthState object",
		)

		return &AuthState{}
	},
}

// reset resets all fields of the AuthState to their zero values
// This is used when returning an AuthState to the pool
func (a *AuthState) reset() {
	// Reset primitive types
	a.StartTime = time.Time{}
	a.NoAuth = false
	a.ListAccounts = false
	a.UserFound = false
	a.Authenticated = false
	a.Authorized = false
	a.PasswordsAccountSeen = 0
	a.PasswordsTotalSeen = 0
	a.LoginAttempts = 0
	a.StatusCodeOK = 0
	a.StatusCodeInternalError = 0
	a.StatusCodeFail = 0
	a.Username = ""
	a.Password = ""
	a.ClientIP = ""
	a.XClientPort = ""
	a.ClientHost = ""
	a.XSSL = ""
	a.XSSLSessionID = ""
	a.XSSLClientVerify = ""
	a.XSSLClientDN = ""
	a.XSSLClientCN = ""
	a.XSSLIssuer = ""
	a.XSSLClientNotBefore = ""
	a.XSSLClientNotAfter = ""
	a.XSSLSubjectDN = ""
	a.XSSLIssuerDN = ""
	a.XSSLClientSubjectDN = ""
	a.XSSLClientIssuerDN = ""
	a.XSSLProtocol = ""
	a.XSSLCipher = ""
	a.SSLSerial = ""
	a.SSLFingerprint = ""
	a.XClientID = ""
	a.XLocalIP = ""
	a.XPort = ""
	a.StatusMessage = ""
	a.Service = ""
	a.BruteForceName = ""
	a.FeatureName = ""
	a.BackendName = ""
	a.OIDCCID = ""
	a.UsedBackendIP = ""
	a.UsedBackendPort = 0
	a.SourcePassDBBackend = definitions.BackendUnknown
	a.UsedPassDBBackend = definitions.BackendUnknown
	a.MasterUserMode = false

	// Reset brute-force hints
	a.BFClientNet = ""
	a.BFRepeating = false

	// Reset pointer types
	a.GUID = nil
	a.Method = nil
	a.AccountField = nil
	a.TOTPSecret = nil
	a.TOTPSecretField = nil
	a.TOTPRecoveryField = nil
	a.UniqueUserIDField = nil
	a.DisplayNameField = nil
	a.UserAgent = nil
	a.Protocol = nil
	a.HTTPClientContext = nil
	a.PasswordHistory = nil
	a.Context = nil

	// Reset slice types
	a.AdditionalLogs = nil
	a.MonitoringFlags = nil

	// Reset map types
	a.BruteForceCounter = nil
	a.Attributes = nil
}

// PassDBResult is used in all password databases to store final results of an authentication process.
type PassDBResult struct {
	// Authenticated is a flag that is set if a user was not only found, but also succeeded authentication.
	Authenticated bool

	// UserFound is a flag that is set if the user was found in a password Database.
	UserFound bool

	// BackendName specifies the name of the backend that authenticated or found the user in the password database.
	BackendName string

	// AccountField is the SQL field or LDAP attribute that was used for the user account.
	AccountField *string

	// TOTPSecretField is set by the Database which has found the user.
	TOTPSecretField *string

	// TOTPRecoveryField NYI
	TOTPRecoveryField *string

	// UniqueUserIDField is a string representing a unique user identifier.
	UniqueUserIDField *string

	// DisplayNameField is the display name of a user
	DisplayNameField *string

	// Backend is set by the Database backend, which has found the user.
	Backend definitions.Backend

	// Attributes is the result catalog returned by the underlying password Database.
	Attributes bktype.AttributeMapping

	// AdditionalFeatures contains additional features for machine learning
	AdditionalFeatures map[string]any
}

// Reset resets all fields of the PassDBResult to their zero values
// This is used when returning a PassDBResult to the pool
// It implements the Resettable interface
func (p *PassDBResult) Reset() {
	// Reset bool fields
	p.Authenticated = false
	p.UserFound = false

	// Reset string field
	p.BackendName = ""

	// Reset pointer fields to nil
	p.AccountField = nil
	p.TOTPSecretField = nil
	p.TOTPRecoveryField = nil
	p.UniqueUserIDField = nil
	p.DisplayNameField = nil

	// Reset Backend field
	p.Backend = 0

	// Reset map fields to nil
	p.Attributes = nil
	p.AdditionalFeatures = nil
}

// IsPassDBResult returns true to identify this as a PassDBResult
// This implements the PoolablePassDBResult interface from the localcache package
func (p *PassDBResult) IsPassDBResult() bool {
	return true
}

type (
	// PassDBOption
	// This type specifies the signature of a password database.
	PassDBOption func(auth *AuthState) (*PassDBResult, error)

	// PassDBMap is a struct type that represents a mapping between a backend type and a PassDBOption function.
	// It is used in the verifyPassword method of the AuthState struct to perform password verification against multiple databases.
	// The backend field represents the type of database backend (definitions.Backend), and the fn field represents the PassDBOption function.
	// The PassDBOption function takes an AuthState pointer as input and returns a PassDBResult pointer and an error.
	// The PassDBResult pointer contains the result of the password verification process.
	// This struct is used to store the database mappings in an array and loop through them in the verifyPassword method.
	PassDBMap struct {
		backend definitions.Backend
		fn      PassDBOption
	}
)

type (
	// AccountList is a slice of strings containing the list of all user accounts.
	AccountList []string

	// AccountListOption is the function signature for an account Database.
	AccountListOption func(a *AuthState) (AccountList, error)

	// AccountListMap is a struct type that represents a mapping between a backend and an account list option function for authentication.
	AccountListMap struct {
		backend definitions.Backend
		fn      AccountListOption
	}
)

// WebAuthnCredentialDBFunc defines a signature for WebAuthn credential object lookups
type WebAuthnCredentialDBFunc func(uniqueUserID string) ([]webauthn.Credential, error)

// AddTOTPSecretFunc is a function signature that takes a *AuthState and *TOTPSecret as arguments and returns an error.
type AddTOTPSecretFunc func(auth *AuthState, totp *mfa.TOTPSecret) (err error)

var BackendServers = NewBackendServer()

// String returns an AuthState object as string excluding the user password.
func (a *AuthState) String() string {
	var result string

	value := reflect.ValueOf(*a)
	typeOfValue := value.Type()

	for index := range value.NumField() {
		switch typeOfValue.Field(index).Name {
		case "GUID":
			continue
		case "Password":
			if config.GetEnvironment().GetDevMode() {
				result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
			} else {
				result += fmt.Sprintf(" %s='<hidden>'", typeOfValue.Field(index).Name)
			}
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result[1:]
}

// SetUsername sets the username for the AuthState instance to the given value.
func (a *AuthState) SetUsername(username string) {
	a.Username = username
}

// SetPassword sets the password for the AuthState instance.
func (a *AuthState) SetPassword(password string) {
	a.Password = password
}

// SetClientIP sets the client's IP address in the AuthState structure.
func (a *AuthState) SetClientIP(clientIP string) {
	a.ClientIP = clientIP
}

// SetClientPort sets the client's port information to the provided clientPort value.
func (a *AuthState) SetClientPort(clientPort string) {
	a.XClientPort = clientPort
}

// SetClientHost sets the client host value in the AuthState instance.
func (a *AuthState) SetClientHost(clientHost string) {
	a.ClientHost = clientHost
}

// SetClientID sets the client ID for the authentication state using the provided clientID string.
func (a *AuthState) SetClientID(clientID string) {
	a.XClientID = clientID
}

// SetSSLSessionID sets the SSL session ID for the AuthState instance.
func (a *AuthState) SetSSLSessionID(sslSessionID string) {
	a.XSSLSessionID = sslSessionID
}

// SetSSLClientVerify sets the SSL client verification value for the AuthState.
func (a *AuthState) SetSSLClientVerify(sslClientVerify string) {
	a.XSSLClientVerify = sslClientVerify
}

// SetSSLClientDN sets the distinguished name (DN) of the SSL client in the AuthState struct.
func (a *AuthState) SetSSLClientDN(sslClientDN string) {
	a.XSSLClientDN = sslClientDN
}

// SetSSLClientCN sets the value of the SSL client common name (CN) for the AuthState instance.
func (a *AuthState) SetSSLClientCN(sslClientCN string) {
	a.XSSLClientCN = sslClientCN
}

// SetSSLIssuer sets the issuer for the XSSL certificate in the AuthState.
func (a *AuthState) SetSSLIssuer(xSSLIssuer string) {
	a.XSSLIssuer = xSSLIssuer
}

// SetSSLClientNotBefore sets the SSL client certificate's "Not Before" value in the AuthState.
func (a *AuthState) SetSSLClientNotBefore(sslClientNotBefore string) {
	a.XSSLClientNotBefore = sslClientNotBefore
}

// SetSSLClientNotAfter sets the XSSLClientNotAfter field with the provided SSL client expiration date.
func (a *AuthState) SetSSLClientNotAfter(sslClientNotAfter string) {
	a.XSSLClientNotAfter = sslClientNotAfter
}

// SetSSLSubjectDN sets the SSL subject distinguished name to the provided string value.
func (a *AuthState) SetSSLSubjectDN(sslSubjectDN string) {
	a.XSSLSubjectDN = sslSubjectDN
}

// SetSSLIssuerDN sets the X.509 SSL issuer distinguished name for the AuthState.
func (a *AuthState) SetSSLIssuerDN(xSSLIssuerDN string) {
	a.XSSLIssuerDN = xSSLIssuerDN
}

// SetSSLClientSubjectDN sets the subject distinguished name (DN) for the SSL client in the AuthState object.
func (a *AuthState) SetSSLClientSubjectDN(sslClientSubjectDN string) {
	a.XSSLClientSubjectDN = sslClientSubjectDN
}

// SetSSLClientIssuerDN sets the SSL client issuer distinguished name for the authentication state.
func (a *AuthState) SetSSLClientIssuerDN(sslClientIssuerDN string) {
	a.XSSLClientIssuerDN = sslClientIssuerDN
}

// SetSSLCipher sets the SSL cipher suite for the current authentication state.
func (a *AuthState) SetSSLCipher(sslCipher string) {
	a.XSSLCipher = sslCipher
}

// SetSSLSerial sets the SSL serial number for the AuthState instance.
func (a *AuthState) SetSSLSerial(sslSerial string) {
	a.SSLSerial = sslSerial
}

// SetSSLFingerprint sets the SSL fingerprint for the AuthState instance. It updates the SSLFingerprint field with the provided value.
func (a *AuthState) SetSSLFingerprint(sslFingerprint string) {
	a.SSLFingerprint = sslFingerprint
}

// SetOIDCCID sets the OIDC Client ID for the AuthState instance. It updates the OIDCCID field with the provided value.
func (a *AuthState) SetOIDCCID(oidcCID string) {
	a.OIDCCID = oidcCID
}

// SetNoAuth configures the authentication state to enable or disable "NoAuth" mode based on the provided boolean value.
func (a *AuthState) SetNoAuth(noAuth bool) {
	a.NoAuth = noAuth
}

// SetProtocol sets the protocol for the AuthState using the given Protocol configuration.
func (a *AuthState) SetProtocol(protocol *config.Protocol) {
	a.Protocol = protocol
}

// SetLoginAttempts sets the number of login attempts for the AuthState instance.
func (a *AuthState) SetLoginAttempts(loginAttempts uint) {
	a.LoginAttempts = loginAttempts
}

// SetMethod sets the authentication method for the AuthState instance by assigning it to the Method field.
func (a *AuthState) SetMethod(method string) {
	a.Method = &method
}

// SetUserAgent sets the UserAgent field for the AuthState with the provided userAgent value.
func (a *AuthState) SetUserAgent(userAgent string) {
	a.UserAgent = &userAgent
}

// SetLocalIP sets the local IP address for the AuthState instance.
func (a *AuthState) SetLocalIP(localIP string) {
	a.XLocalIP = localIP
}

// SetLocalPort sets the local port for the AuthState instance to the given port string.
func (a *AuthState) SetLocalPort(port string) {
	a.XPort = port
}

// SetSSL sets the XSSL property of the AuthState to the provided SSL value.
func (a *AuthState) SetSSL(ssl string) {
	a.XSSL = ssl
}

// SetSSLProtocol sets the SSL protocol version to be used for the connection by updating the XSSLProtocol field.
func (a *AuthState) SetSSLProtocol(sslProtocol string) {
	a.XSSLProtocol = sslProtocol
}

// GetGUID retrieves the GUID from the AuthState. Returns an empty string if the GUID is nil.
func (a *AuthState) GetGUID() string {
	if a.GUID == nil {
		return ""
	}

	return *a.GUID
}

// GetUsername retrieves the username from the AuthState structure.
func (a *AuthState) GetUsername() string {
	return a.Username
}

// GetPassword retrieves the password stored in the AuthState instance. It returns the password as a string.
func (a *AuthState) GetPassword() string {
	return a.Password
}

// GetProtocol retrieves the configured Protocol for the AuthState. If no Protocol is set, it returns a default Protocol instance.
func (a *AuthState) GetProtocol() *config.Protocol {
	if a.Protocol == nil {
		a.Protocol = &config.Protocol{}
	}

	return a.Protocol
}

// GetTOTPSecretField retrieves the TOTP secret field from the AuthState. Returns an empty string if the field is nil.
func (a *AuthState) GetTOTPSecretField() string {
	if a.TOTPSecretField == nil {
		return ""
	}

	return *a.TOTPSecretField
}

// GetTOTPRecoveryField retrieves the TOTP recovery field value from AuthState. Returns an empty string if not set.
func (a *AuthState) GetTOTPRecoveryField() string {
	if a.TOTPRecoveryField == nil {
		return ""
	}

	return *a.TOTPRecoveryField
}

// GetUniqueUserIDField retrieves the value of the UniqueUserIDField if set; returns an empty string otherwise.
func (a *AuthState) GetUniqueUserIDField() string {
	if a.UniqueUserIDField == nil {
		return ""
	}

	return *a.UniqueUserIDField
}

// GetDisplayNameField retrieves the display name field from the AuthState. Returns an empty string if it's nil.
func (a *AuthState) GetDisplayNameField() string {
	if a.DisplayNameField == nil {
		return ""
	}

	return *a.DisplayNameField
}

// GetUsedPassDBBackend returns the currently used backend for password database operations.
func (a *AuthState) GetUsedPassDBBackend() definitions.Backend {
	return a.UsedPassDBBackend
}

// GetAttributes retrieves the stored database attributes from the AuthState and returns them as a AttributeMapping.
func (a *AuthState) GetAttributes() bktype.AttributeMapping {
	return a.Attributes
}

// GetAdditionalLogs returns a slice of additional logs associated with the AuthState instance.
func (a *AuthState) GetAdditionalLogs() []any {
	return a.AdditionalLogs
}

// GetClientIP returns the client's IP address stored in the AuthState instance.
func (a *AuthState) GetClientIP() string {
	return a.ClientIP
}

// LogLineTemplate constructs a key-value slice for logging authentication state and related metadata.
func (a *AuthState) LogLineTemplate(status string, endpoint string) []any {
	var keyvals []any

	if a.StatusMessage == "" {
		a.StatusMessage = "OK"
	}

	mode := "auth"
	if a.NoAuth {
		mode = "no-auth"
	}

	backendName := definitions.NotAvailable
	if a.BackendName != "" {
		backendName = a.BackendName
	}

	keyvals = []any{
		definitions.LogKeyGUID, util.WithNotAvailable(*a.GUID),
		definitions.LogKeyMode, mode,
		definitions.LogKeyBackendName, backendName,
		definitions.LogKeyProtocol, util.WithNotAvailable(a.Protocol.String()),
		definitions.LogKeyOIDCCID, util.WithNotAvailable(a.OIDCCID),
		definitions.LogKeyLocalIP, util.WithNotAvailable(a.XLocalIP),
		definitions.LogKeyPort, util.WithNotAvailable(a.XPort),
		definitions.LogKeyClientIP, util.WithNotAvailable(a.ClientIP),
		definitions.LogKeyClientPort, util.WithNotAvailable(a.XClientPort),
		definitions.LogKeyClientHost, util.WithNotAvailable(a.ClientHost),
		definitions.LogKeyTLSSecure, util.WithNotAvailable(a.XSSLProtocol),
		definitions.LogKeyTLSCipher, util.WithNotAvailable(a.XSSLCipher),
		definitions.LogKeyAuthMethod, util.WithNotAvailable(*a.Method),
		definitions.LogKeyUsername, util.WithNotAvailable(a.Username),
		definitions.LogKeyUsedPassdbBackend, util.WithNotAvailable(a.UsedPassDBBackend.String()),
		definitions.LogKeyLoginAttempts, a.LoginAttempts,
		definitions.LogKeyPasswordsAccountSeen, a.PasswordsAccountSeen,
		definitions.LogKeyPasswordsTotalSeen, a.PasswordsTotalSeen,
		definitions.LogKeyUserAgent, util.WithNotAvailable(*a.UserAgent),
		definitions.LogKeyClientID, util.WithNotAvailable(a.XClientID),
		definitions.LogKeyBruteForceName, util.WithNotAvailable(a.BruteForceName),
		definitions.LogKeyFeatureName, util.WithNotAvailable(a.FeatureName),
		definitions.LogKeyStatusMessage, util.WithNotAvailable(a.StatusMessage),
		definitions.LogKeyUriPath, endpoint,
		definitions.LogKeyStatus, util.WithNotAvailable(status),
		definitions.LogKeyAuthorized, a.Authorized,
		definitions.LogKeyAuthenticatedBool, a.Authenticated,
		definitions.LogKeyLatency, fmt.Sprintf("%v", time.Since(a.StartTime)),
	}

	if len(a.AdditionalLogs) > 0 && len(a.AdditionalLogs)%2 == 0 {
		// Pre-allocate the keyvals slice to avoid continuous reallocation
		keyvalsLen := len(keyvals)
		newKeyvals := make([]any, keyvalsLen+len(a.AdditionalLogs))
		copy(newKeyvals, keyvals)
		keyvals = newKeyvals[:keyvalsLen]

		for index := range a.AdditionalLogs {
			keyvals = append(keyvals, a.AdditionalLogs[index])
		}
	}

	return keyvals
}

// LogLineProcessingTemplate generates and returns a list of key-value pairs for logging session-related details.
func (a *AuthState) LogLineProcessingTemplate(endpoint string) []any {
	var keyvals []any

	mode := "auth"
	if a.NoAuth {
		mode = "no-auth"
	}

	keyvals = []any{
		definitions.LogKeyGUID, util.WithNotAvailable(*a.GUID),
		definitions.LogKeyMode, mode,
		definitions.LogKeyProtocol, util.WithNotAvailable(a.Protocol.String()),
		definitions.LogKeyOIDCCID, util.WithNotAvailable(a.OIDCCID),
		definitions.LogKeyLocalIP, util.WithNotAvailable(a.XLocalIP),
		definitions.LogKeyPort, util.WithNotAvailable(a.XPort),
		definitions.LogKeyClientIP, util.WithNotAvailable(a.ClientIP),
		definitions.LogKeyClientPort, util.WithNotAvailable(a.XClientPort),
		definitions.LogKeyClientHost, util.WithNotAvailable(a.ClientHost),
		definitions.LogKeyTLSSecure, util.WithNotAvailable(a.XSSLProtocol),
		definitions.LogKeyTLSCipher, util.WithNotAvailable(a.XSSLCipher),
		definitions.LogKeyAuthMethod, util.WithNotAvailable(*a.Method),
		definitions.LogKeyUsername, util.WithNotAvailable(a.Username),
		definitions.LogKeyUserAgent, util.WithNotAvailable(*a.UserAgent),
		definitions.LogKeyClientID, util.WithNotAvailable(a.XClientID),
		definitions.LogKeyUriPath, endpoint,
	}

	return keyvals
}

// GetAccount returns the account value from the AuthState object. If the account field is not set or the account
// value is not found in the attributes, an empty string is returned
func (a *AuthState) GetAccount() string {
	if a.AccountField == nil {
		return ""
	}

	if account, okay := a.Attributes[*a.AccountField]; okay {
		if value, assertOk := account[definitions.LDAPSingleValue].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetAccountOk returns the account name of a user. If there is no account, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *AuthState) GetAccountOk() (string, bool) {
	account := a.GetAccount()

	return account, account != ""
}

// GetTOTPSecret returns the TOTP secret for a user. If there is no secret, it returns the empty string "".
func (a *AuthState) GetTOTPSecret() string {
	if a.TOTPSecretField == nil {
		return ""
	}

	if totpSecret, okay := a.Attributes[a.GetTOTPSecretField()]; okay {
		if value, assertOk := totpSecret[definitions.LDAPSingleValue].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetTOTPSecretOk returns the TOTP secret for a user. If there is no secret, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *AuthState) GetTOTPSecretOk() (string, bool) {
	totpSecret := a.GetTOTPSecret()

	return totpSecret, totpSecret != ""
}

// GetUniqueUserID returns the unique WebAuthn user identifier for a user. If there is no id, it returns the empty string "".
func (a *AuthState) GetUniqueUserID() string {
	if a.UniqueUserIDField == nil {
		return ""
	}

	if webAuthnUserID, okay := a.Attributes[a.GetUniqueUserIDField()]; okay {
		if value, assertOk := webAuthnUserID[definitions.LDAPSingleValue].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetUniqueUserIDOk returns the unique identifier for a user. If there is no id, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *AuthState) GetUniqueUserIDOk() (string, bool) {
	uniqueUserID := a.GetUniqueUserID()

	return uniqueUserID, uniqueUserID != ""
}

// GetDisplayName returns the display name for a user. If there is no account, it returns the empty string "".
func (a *AuthState) GetDisplayName() string {
	if a.DisplayNameField == nil {
		return ""
	}

	if account, okay := a.Attributes[a.GetDisplayNameField()]; okay {
		if value, assertOk := account[definitions.SliceWithOneElement].(string); assertOk {
			return value
		}
	}

	return ""
}

// GetDisplayNameOk returns the display name of a user. If there is no account, it returns the empty string "". A boolean
// is set to return a "found" flag.
func (a *AuthState) GetDisplayNameOk() (string, bool) {
	displayName := a.GetDisplayName()

	return displayName, displayName != ""
}

// AuthOK is the general method to indicate authentication success.
func (a *AuthState) AuthOK(ctx *gin.Context) {
	setCommonHeaders(ctx, a)

	switch a.Service {
	case definitions.ServNginx:
		setNginxHeaders(ctx, a)
	case definitions.ServHeader:
		setHeaderHeaders(ctx, a)
	case definitions.ServJSON:
		sendAuthResponse(ctx, a)
	}

	handleLogging(ctx, a)

	// Only authentication attempts
	if !(a.NoAuth || a.ListAccounts) {
		stats.GetMetrics().GetAcceptedProtocols().WithLabelValues(a.Protocol.Get()).Inc()
		stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelSuccess).Inc()

		if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
			return
		}
	}
}

// setCommonHeaders sets common headers for the given gin.Context and AuthState.
// It sets the "Auth-Status" header to "OK" and the "X-Nauthilus-Session" header to the GUID of the AuthState.
// If the AuthState's Service is not definitions.ServBasic, and the HaveAccountField flag is true,
// it retrieves the account from the AuthState and sets the "Auth-User" header
func setCommonHeaders(ctx *gin.Context, auth *AuthState) {
	ctx.Header("Auth-Status", "OK")
	ctx.Header("X-Nauthilus-Session", *auth.GUID)

	if auth.Service != definitions.ServBasic {
		if account, found := auth.GetAccountOk(); found {
			ctx.Header("Auth-User", account)
		}
	}

	cachedAuth := ctx.GetBool(definitions.CtxLocalCacheAuthKey)

	if cachedAuth {
		ctx.Header("X-Nauthilus-Memory-Cache", "Hit")
	} else {
		ctx.Header("X-Nauthilus-Memory-Cache", "Miss")
	}
}

// setNginxHeaders sets the appropriate headers for the given gin.Context and AuthState based on the configuration and feature flags.
// If the definitions.FeatureBackendServersMonitoring feature is enabled, it checks if the AuthState's UsedBackendAddress and UsedBackendPort are set.
// If they are, it sets the "Auth-Server" header to the UsedBackendAddress and the "Auth-Port" header to the UsedBackendPort.
// If the definitions.FeatureBackendServersMonitoring feature is disabled, it checks the AuthState's Protocol.
// If the Protocol is definitions.ProtoSMTP, it sets the "Auth-Server" header to the SMTPBackendAddress and the "Auth-Port" header to the SMTPBackendPort.
// If the Protocol is definitions.ProtoIMAP, it sets the "Auth-Server" header to the IMAPBackendAddress and the "Auth-Port" header to the IMAPBackendPort.
// If the Protocol is definitions.ProtoPOP3, it sets the "Auth-Server" header to the POP3BackendAddress and the "Auth-Port" header to the POP3BackendPort.
func setNginxHeaders(ctx *gin.Context, auth *AuthState) {
	if config.GetFile().HasFeature(definitions.FeatureBackendServersMonitoring) {
		if BackendServers.GetTotalServers() == 0 {
			ctx.Header("Auth-Status", "Internal failure")
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, "No backend servers found for backend_server_monitoring feature",
				definitions.LogKeyInstance, config.GetFile().GetServer().GetInstanceName(),
			)
		} else {
			if auth.UsedBackendIP != "" && auth.UsedBackendPort > 0 {
				ctx.Header("Auth-Server", auth.UsedBackendIP)
				ctx.Header("Auth-Port", fmt.Sprintf("%d", auth.UsedBackendPort))
			}
		}
	} else {
		switch auth.Protocol.Get() {
		case definitions.ProtoSMTP:
			ctx.Header("Auth-Server", config.GetEnvironment().GetSMTPBackendAddress())
			ctx.Header("Auth-Port", fmt.Sprintf("%d", config.GetEnvironment().GetSMTPBackendPort()))
		case definitions.ProtoIMAP:
			ctx.Header("Auth-Server", config.GetEnvironment().GetIMAPBackendAddress())
			ctx.Header("Auth-Port", fmt.Sprintf("%d", config.GetEnvironment().GetIMAPBackendPort()))
		case definitions.ProtoPOP3:
			ctx.Header("Auth-Server", config.GetEnvironment().GetPOP3BackendAddress())
			ctx.Header("Auth-Port", fmt.Sprintf("%d", config.GetEnvironment().GetPOP3BackendPort()))
		}
	}
}

// setHeaderHeaders sets the specified headers in the given gin.Context based on the attributes in the AuthState object.
// It iterates through the attributes and calls the handleAttributeValue function for each attribute.
//
// Parameters:
// - ctx: The gin.Context object to set the headers on.
// - a: The AuthState object containing the attributes.
//
// Example:
//
//	a := &AuthState{
//	    SearchAttributes: map[string][]any{
//	        "Attribute1": []any{"Value1"},
//	        "Attribute2": []any{"Value2_1", "Value2_2"},
//	    },
//	}
//	setHeaderHeaders(ctx, a)
//
// Resulting headers in ctx:
// - X-Nauthilus-Attribute1: "Value1"
// - X-Nauthilus-Attribute2: "Value2_1,Value2_2"
func setHeaderHeaders(ctx *gin.Context, auth *AuthState) {
	if auth.Attributes != nil && len(auth.Attributes) > 0 {
		for name, value := range auth.Attributes {
			handleAttributeValue(ctx, name, value)
		}
	}
}

// handleAttributeValue sets the value of a header in the given gin.Context based on the name and value provided.
// If the value length is 1, it formats the value as a string and assigns it to the headerValue variable.
// If the value length is greater than 1, it formats each value and joins them with a comma separator, unless the name is "dn",
// in which case it joins them with a semicolon separator.
// Finally, it adds the header "X-Nauthilus-" + name with the value of headerValue to the gin.Context.
// Parameters:
// - ctx: the gin.Context to set the header in
// - name: the name of the header
// - value: the value of the header
func handleAttributeValue(ctx *gin.Context, name string, value []any) {
	var headerValue string

	if valueLen := len(value); valueLen > 0 {
		switch {
		case valueLen == 1:
			headerValue = fmt.Sprintf("%v", value[definitions.LDAPSingleValue])
		default:
			stringValues := formatValues(value)
			separator := ","

			if name == definitions.DistinguishedName {
				separator = ";"
			}

			headerValue = strings.Join(stringValues, separator)
		}

		ctx.Header("X-Nauthilus-"+name, fmt.Sprintf("%v", headerValue))
	}
}

// formatValues takes an array of values and formats them into strings.
// It creates an empty slice of strings called stringValues.
// It then iterates over each value in the "values" array and appends the formatted string representation of that value to stringValues using fmt.Sprintf("%v", values[index]).
// After iterating over all the values, it returns stringValues.
// Example usage:
// values := []any{"one", "two", "three"}
// result := formatValues(values)
// fmt.Println(result) // Output: ["one", "two", "three"]
func formatValues(values []any) []string {
	var stringValues []string

	for index := range values {
		stringValues = append(stringValues, fmt.Sprintf("%v", values[index]))
	}

	return stringValues
}

// sendAuthResponse sends a JSON response with the appropriate headers and content based on the AuthState.
func sendAuthResponse(ctx *gin.Context, auth *AuthState) {
	ctx.JSON(auth.StatusCodeOK, &bktype.PositivePasswordCache{
		AccountField:    auth.AccountField,
		TOTPSecretField: auth.TOTPSecretField,
		Backend:         auth.SourcePassDBBackend,
		Attributes:      auth.Attributes,
	})
}

// handleLogging logs information about the authentication request if the verbosity level is greater than LogLevelWarn.
// It uses the log.Logger to log the information.
// The logged information includes the result of the a.LogLineTemplate() function, which returns either "ok" or an empty string depending on the value of a.NoAuth,
// and the path of the request URL obtained from ctx.Request.URL.Path.
func handleLogging(ctx *gin.Context, auth *AuthState) {
	keyvals := auth.LogLineTemplate(func() string {
		if !auth.NoAuth {
			return "ok"
		}

		return ""
	}(), ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Authentication request was successful")

	level.Info(log.Logger).Log(keyvals...)
}

// logProcessingRequest writes a prominent log line similar to the final one, but for the beginning of request processing.
// It logs all available request-related fields and explicitly sets msg="Processing request" while including the session GUID.
func logProcessingRequest(ctx *gin.Context, auth *AuthState) {
	if auth == nil || ctx == nil {
		return
	}

	keyvals := auth.LogLineProcessingTemplate(ctx.Request.URL.Path)

	// Add a human-readable message field as requested
	keyvals = append(keyvals, definitions.LogKeyMsg, "Processing incoming request")

	level.Info(log.Logger).Log(keyvals...)
}

// increaseLoginAttempts increments the number of login attempts for the AuthState object.
// If the number of login attempts exceeds the maximum value allowed (MaxUint8), it sets it to the maximum value.
// If the AuthState service is equal to ServNginx and the number of login attempts is less than the maximum login attempts specified in the GetEnvironment() configuration,
// it increments the number of login attempts by one.
// The usage example of this method can be found in the AuthFail function.
func (a *AuthState) increaseLoginAttempts() {
	if a.LoginAttempts > math.MaxUint8 {
		a.LoginAttempts = math.MaxUint8
	}

	if a.Service == definitions.ServNginx {
		if a.LoginAttempts < uint(config.GetEnvironment().GetMaxLoginAttempts()) {
			a.LoginAttempts++
		}
	}
}

// calculateWaitDelay calculates the wait delay based on maxWaitDelay and loginAttempt using the hyperbolic tangent function.
func calculateWaitDelay(maxWaitDelay, loginAttempt uint) int {
	scale := 0.03

	return int(float64(maxWaitDelay) * math.Tanh(scale*float64(loginAttempt)))
}

// setFailureHeaders sets the failure headers for the given authentication context.
// It sets the "Auth-Status" header to the value of definitions.PasswordFail constant.
// It sets the "X-Nauthilus-Session" header to the value of the authentication's GUID field.
// It updates the StatusMessage of the authentication to definitions.PasswordFail.
//
// If the Service field of the authentication is equal to global.ServUserInfo, it also sets the following headers:
//   - "X-User-Found" header to the string representation of the UserFound field of the authentication
//   - If the PasswordHistory field is not nil, it responds with a JSON representation of the PasswordHistory.
//     If the PasswordHistory field is nil, it responds with an empty JSON object.
//
// If the Service field is not equal to global.ServUserInfo, it responds with the StatusMessage of the authentication as plain text.
func (a *AuthState) setFailureHeaders(ctx *gin.Context) {
	if a.StatusMessage == "" {
		a.StatusMessage = definitions.PasswordFail
	}

	ctx.Header("Auth-Status", a.StatusMessage)
	ctx.Header("X-Nauthilus-Session", *a.GUID)

	switch a.Service {
	case definitions.ServHeader, definitions.ServNginx, definitions.ServJSON:
		maxWaitDelay := viper.GetUint("nginx_wait_delay")

		if maxWaitDelay > 0 {
			waitDelay := calculateWaitDelay(maxWaitDelay, a.LoginAttempts)

			ctx.Header("Auth-Wait", fmt.Sprintf("%v", waitDelay))
		}

		// Do not include password history in responses; always return JSON null on failure
		ctx.JSON(a.StatusCodeFail, nil)
	default:
		ctx.String(a.StatusCodeFail, a.StatusMessage)
	}
}

// loginAttemptProcessing performs processing for a failed login attempt.
// It checks the verbosity level in the GetEnvironment() configuration and logs the failed login attempt if it is greater than LogLevelWarn.
// It then increments the LoginsCounter with the LabelFailure.
//
// Example usage:
//
//	a := &AuthState{}
//	ctx := &gin.Context{}
//	a.loginAttemptProcessing(ctx)
func (a *AuthState) loginAttemptProcessing(ctx *gin.Context) {
	keyvals := a.LogLineTemplate("fail", ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Authentication request has failed")

	level.Info(log.Logger).Log(keyvals...)

	stats.GetMetrics().GetRejectedProtocols().WithLabelValues(a.Protocol.Get()).Inc()
	stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelFailure).Inc()
}

// AuthFail handles the failure of authentication.
// It increases the login attempts, sets failure headers on the context, and performs login attempt processing.
func (a *AuthState) AuthFail(ctx *gin.Context) {
	a.increaseLoginAttempts()
	a.setFailureHeaders(ctx)
	a.loginAttemptProcessing(ctx)
}

// setSMPTHeaders sets SMTP headers in the specified `gin.Context` if the `Service` is `ServNginx` and the `Protocol` is `ProtoSMTP`.
// It adds the `Auth-Error-Code` header with the value `TempFailCode` from the declaration package.
//
// Example usage:
//
//	a.setSMPTHeaders(ctx)
func (a *AuthState) setSMPTHeaders(ctx *gin.Context) {
	if a.Service == definitions.ServNginx && a.Protocol.Get() == definitions.ProtoSMTP {
		ctx.Header("Auth-Error-Code", definitions.TempFailCode)
	}
}

// AuthTempFail sends a temporary failure response with the provided reason and logs the error.
func (a *AuthState) AuthTempFail(ctx *gin.Context, reason string) {
	ctx.Header("Auth-Status", reason)
	ctx.Header("X-Nauthilus-Session", *a.GUID)
	a.setSMPTHeaders(ctx)

	a.StatusMessage = reason

	if a.Service == definitions.ServJSON {
		ctx.JSON(a.StatusCodeInternalError, gin.H{"error": reason})

		return
	}

	ctx.String(a.StatusCodeInternalError, a.StatusMessage)

	keyvals := a.LogLineTemplate("tempfail", ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Temporary server problem")

	level.Info(log.Logger).Log(keyvals...)
}

// IsMasterUser checks whether the current user is a master user based on the MasterUser configuration in the GetFile().
// It returns true if MasterUser is enabled and the number of occurrences of the delimiter in the Username is equal to 1, otherwise it returns false.
func (a *AuthState) IsMasterUser() bool {
	if config.GetFile().GetServer().GetMasterUser().IsEnabled() {
		if strings.Count(a.Username, config.GetFile().GetServer().GetMasterUser().GetDelimiter()) == 1 {
			parts := strings.Split(a.Username, config.GetFile().GetServer().GetMasterUser().GetDelimiter())
			if len(parts[0]) > 0 && len(parts[1]) > 0 {
				return true
			}
		}
	}

	return false
}

// IsInNetwork checks an IP address against a network and returns true if it matches.
func (a *AuthState) IsInNetwork(networkList []string) (matchIP bool) {
	return util.IsInNetwork(networkList, *a.GUID, a.ClientIP)
}

// verifyPassword takes in an array of PassDBMap and performs the following steps:
// - Check if there are any password databases available
// - Iterate over each password database and call the corresponding function
// - Log debug information for each database and its result
// - Handle any backend errors and store them in a map
// - If there is no error, authenticate the user using the result returned by the database function
// - If authentication is successful or NoAuth flag is set, return the passDBResult and nil error
//
// Parameters:
// - passDBs: an array of PassDBMap which contains the backend type and the corresponding function to be called
//
// Return values:
// - passDBResult: a pointer to a PassDBResult struct which contains the authentication result
// - err: an error that occurred during the verification process
func (a *AuthState) verifyPassword(ctx *gin.Context, passDBs []*PassDBMap) (*PassDBResult, error) {
	var (
		passDBResult *PassDBResult
		err          error
	)

	configErrors := make(map[definitions.Backend]error, len(passDBs))
	for passDBIndex, passDB := range passDBs {
		passDBResult, err = passDB.fn(a)
		logDebugModule(a, passDB, passDBResult)

		if err != nil {
			err = handleBackendErrors(passDBIndex, passDBs, passDB, err, a, configErrors)
			if err != nil {
				break
			}
		} else {
			err = processPassDBResult(ctx, passDBResult, a, passDB)
			if err != nil || a.UserFound {
				break
			}
		}
	}

	// Enforce authentication
	if a.NoAuth && passDBResult != nil && passDBResult.UserFound {
		passDBResult.Authenticated = true
	}

	return passDBResult, err
}

// logDebugModule logs debug information about the authentication process.
//
// Parameters:
//   - a: The AuthState object associated with the authentication process.
//   - passDB: The PassDBMap object representing the password database.
//   - passDBResult: The PassDBResult object containing the result of the authentication process.
//
// The logDebugModule function calls the util.DebugModule function to log the debug information.
// It passes the module declaration (definitions.DbgAuth) as the first parameter, followed by key-value pairs of additional information.
// The key-value pairs include "session" as the key and a.GUID as the value, "passdb" as the key and passDB.backend.String() as the value,
// and "result" as the key and fmt.Sprintf("%v", passDBResult) as the value.
//
// Example Usage:
//
//	logDebugModule(a, passDB, passDBResult)
//
// This function uses the util.DebugModule function from the package to log the debug information.
func logDebugModule(auth *AuthState, passDB *PassDBMap, passDBResult *PassDBResult) {
	util.DebugModule(
		definitions.DbgAuth,
		definitions.LogKeyGUID, auth.GUID,
		"passdb", passDB.backend.String(),
		"result", fmt.Sprintf("%v", passDBResult))
}

// handleBackendErrors handles the errors that occur during backend processing.
// It checks if the error is a configuration error for SQL, LDAP, or Lua backends and adds them to the configErrors map.
// If all password databases have been processed and there are configuration errors, it calls the checkAllBackends function.
// If the error is not a configuration error, it logs the error using the Logger.
// It returns the error unchanged.
func handleBackendErrors(passDBIndex int, passDBs []*PassDBMap, passDB *PassDBMap, err error, auth *AuthState, configErrors map[definitions.Backend]error) error {
	if stderrors.Is(err, errors.ErrLDAPConfig) || stderrors.Is(err, errors.ErrLuaConfig) {
		configErrors[passDB.backend] = err

		// After all password databases were running,  check if SQL, LDAP and Lua  backends have configuration errors.
		if passDBIndex == len(passDBs)-1 {
			err = checkAllBackends(configErrors, auth)
		}
	} else {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, auth.GUID, "passdb", passDB.backend.String(), definitions.LogKeyMsg, err)
	}

	return err
}

// After all password databases were running, check if SQL, LDAP and Lua backends have configuration errors.
func checkAllBackends(configErrors map[definitions.Backend]error, auth *AuthState) (err error) {
	var allConfigErrors = true

	for _, err = range configErrors {
		if err == nil {
			allConfigErrors = false

			break
		}
	}

	// If all (real) Database backends failed, we must return with a temporary failure
	if allConfigErrors {
		err = errors.ErrAllBackendConfigError
		level.Error(log.Logger).Log(definitions.LogKeyGUID, auth.GUID, "passdb", "all", definitions.LogKeyMsg, err)
	}

	return err
}

// processPassDBResult updates the passDBResult based on the provided passDB
// and the AuthState object a.
// If passDBResult is nil, it returns an error of type errors.ErrNoPassDBResult.
// It then calls the util.DebugModule function to log debug information.
// Next, it calls the updateAuthentication function to update the fields of a based on the values in passDBResult.
// If the UserFound field of passDBResult is true, it sets the UserFound field of a to true.
// Finally, it returns the updated passDBResult and nil error.
func processPassDBResult(ctx *gin.Context, passDBResult *PassDBResult, auth *AuthState, passDB *PassDBMap) error {
	if passDBResult == nil {
		return errors.ErrNoPassDBResult
	}

	util.DebugModule(
		definitions.DbgAuth,
		definitions.LogKeyGUID, auth.GUID,
		"passdb", passDB.backend.String(),
		definitions.LogKeyUsername, auth.Username,
		"passdb_result", fmt.Sprintf("%+v", *passDBResult),
	)

	updateAuthentication(ctx, auth, passDBResult, passDB)

	return nil
}

// updateAuthentication updates the fields of the AuthState struct with the values from the PassDBResult struct.
// It checks if each field in passDBResult is not nil and if it is not nil, it updates the corresponding field in the AuthState struct.
// It also updates the SourcePassDBBackend and UsedPassDBBackend fields of the AuthState struct with the values from passDBResult.Backend and passDB.backend respectively.
// It returns the updated PassDBResult struct.
func updateAuthentication(ctx *gin.Context, auth *AuthState, passDBResult *PassDBResult, passDB *PassDBMap) {
	if passDBResult.UserFound {
		auth.UserFound = true

		auth.SourcePassDBBackend = passDBResult.Backend
		auth.BackendName = passDBResult.BackendName
		auth.UsedPassDBBackend = passDB.backend
	}

	if passDBResult.AccountField != nil {
		auth.AccountField = passDBResult.AccountField
	}

	if passDBResult.TOTPSecretField != nil {
		auth.TOTPSecretField = passDBResult.TOTPSecretField
	}

	if passDBResult.UniqueUserIDField != nil {
		auth.UniqueUserIDField = passDBResult.UniqueUserIDField
	}

	if passDBResult.DisplayNameField != nil {
		auth.DisplayNameField = passDBResult.DisplayNameField
	}

	if passDBResult.Attributes != nil && len(passDBResult.Attributes) > 0 {
		auth.Attributes = passDBResult.Attributes
	}

	// Handle AdditionalFeatures if they exist in the PassDBResult
	if passDBResult.AdditionalFeatures != nil && len(passDBResult.AdditionalFeatures) > 0 {
		if auth.HTTPClientContext != nil {
			// Set AdditionalFeatures in the gin.Context
			ctx.Set(definitions.CtxAdditionalFeaturesKey, passDBResult.AdditionalFeatures)
		}
	}
}

// SetStatusCodes sets different status codes for various services.
func (a *AuthState) SetStatusCodes(service string) {
	switch service {
	case definitions.ServNginx:
		a.StatusCodeOK = http.StatusOK
		a.StatusCodeInternalError = http.StatusOK
		a.StatusCodeFail = http.StatusOK
	default:
		a.StatusCodeOK = http.StatusOK
		a.StatusCodeInternalError = http.StatusInternalServerError
		a.StatusCodeFail = http.StatusForbidden
	}
}

// userExists checks if a user exists by looking up their account in Redis using the provided username.
// It returns true if the account name is found, otherwise false.
// An error is returned if there are issues during the Redis lookup.
func (a *AuthState) userExists() (bool, error) {
	accountName, err := backend.LookupUserAccountFromRedis(a.HTTPClientContext, a.Username)
	if err != nil {
		return false, err
	}

	return accountName != "", nil
}

// refreshUserAccount updates the user account information from the cache.
// It sets the account field and attributes if they are nil and the account name is found.
func (a *AuthState) refreshUserAccount() (accountName string) {
	accountName = backend.GetUserAccountFromCache(a.HTTPClientContext, a.Username, *a.GUID)
	if accountName == "" {
		return
	}

	if a.AccountField == nil && a.Attributes == nil {
		accountField := definitions.MetaUserAccount
		attributes := make(bktype.AttributeMapping)

		a.AccountField = &accountField
		attributes[definitions.MetaUserAccount] = []any{accountName}
		a.Attributes = attributes
	}

	return
}

// GetAccountField returns the value of the AccountField field in the AuthState struct.
// If the AccountField field is nil, it returns an empty string.
func (a *AuthState) GetAccountField() string {
	if a.AccountField == nil {
		return ""
	}

	return *a.AccountField
}

// executeLuaPostAction is a helper function that executes a Lua post action with the given parameters.
// It is designed to be run in a goroutine and takes copies of all necessary values to avoid nil pointer dereferences.
func executeLuaPostAction(
	context *lualib.Context,
	httpRequest *http.Request,
	guid string,
	noAuth bool,
	service string,
	clientIP string,
	clientPort string,
	clientHost string,
	clientID string,
	localIP string,
	localPort string,
	userAgent string,
	username string,
	accountName string,
	accountField string,
	uniqueUserID string,
	displayName string,
	password string,
	protocol string,
	oidccid string,
	bruteForceName string,
	featureName string,
	statusMessage string,
	xSSL string,
	xSSLSessionID string,
	xSSLClientVerify string,
	xSSLClientDN string,
	xSSLClientCN string,
	xSSLIssuer string,
	xSSLClientNotBefore string,
	xSSLClientNotAfter string,
	xSSLSubjectDN string,
	xSSLIssuerDN string,
	xSSLClientSubjectDN string,
	xSSLClientIssuerDN string,
	xSSLProtocol string,
	xSSLCipher string,
	sSLSerial string,
	sSLFingerprint string,
	userFound bool,
	authenticated bool,
	bfClientNetHint string,
	bfRepeatingHint bool,
) {
	stopTimer := stats.PrometheusTimer(definitions.PromPostAction, "lua_post_action_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	finished := make(chan action.Done)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Derive client_net and repeating for the Post-Action so that ClickHouse also receives these fields even when the dedicated brute-force action is not used.
	// Prefer hints computed during the brute-force path if available.
	clientNet := bfClientNetHint
	isRepeating := bfRepeatingHint

	if config.GetFile().HasFeature(definitions.FeatureBruteForce) && clientIP != "" {
		// Check whether the protocol is enabled for brute-force processing
		bfProtoEnabled := false
		for _, p := range config.GetFile().GetServer().GetBruteForceProtocols() {
			if p.Get() == protocol {
				bfProtoEnabled = true

				break
			}
		}

		if bfProtoEnabled {
			ip := net.ParseIP(clientIP)
			if ip != nil {
				var (
					foundRepeatingNet string
					foundRepeating    bool
					bestCIDRRepeating uint = 0 // larger prefix = more specific
					bestCIDRFallback  uint = 0 // for clientNet fallback if no hash-hit is found
				)

				for i := range config.GetFile().GetBruteForceRules() {
					r := &config.GetFile().GetBruteForceRules()[i]

					// FilterByProtocol
					if len(r.FilterByProtocol) > 0 && protocol != "" {
						matched := false
						for _, fp := range r.FilterByProtocol {
							if fp == protocol {
								matched = true

								break
							}
						}

						if !matched {
							continue
						}
					}

					// FilterByOIDCCID
					if len(r.FilterByOIDCCID) > 0 && oidccid != "" {
						matched := false
						for _, cid := range r.FilterByOIDCCID {
							if cid == oidccid {
								matched = true

								break
							}
						}

						if !matched {
							continue
						}
					}

					// IP version
					if ip.To4() != nil {
						if !r.IPv4 {
							continue
						}
					} else if ip.To16() != nil {
						if !r.IPv6 {
							continue
						}
					} else {
						continue
					}

					if r.CIDR > 0 {
						if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", clientIP, r.CIDR)); err == nil && n != nil {
							candidate := n.String()

							// 1) Historical hit in the pre-result hash map?
							if !isRepeating {
								key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey

								stats.GetMetrics().GetRedisReadCounter().Inc()

								if exists, err := rediscli.GetClient().GetReadHandle().HExists(httpRequest.Context(), key, candidate).Result(); err == nil && exists {
									if r.CIDR > bestCIDRRepeating {
										bestCIDRRepeating = r.CIDR
										foundRepeatingNet = candidate
									}

									foundRepeating = true
								}
							}

							// 2) Fallback: choose the most specific network as clientNet if no hash hit is found (only if no hint was provided)
							if bfClientNetHint == "" && (clientNet == "" || r.CIDR > bestCIDRFallback) {
								bestCIDRFallback = r.CIDR
								clientNet = candidate
							}
						}
					}
				}

				if foundRepeating {
					isRepeating = true
					if foundRepeatingNet != "" {
						clientNet = foundRepeatingNet
					}
				}
			}
		}
	}

	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = isRepeating
	commonRequest.UserFound = userFound
	commonRequest.Authenticated = authenticated
	commonRequest.NoAuth = noAuth
	commonRequest.BruteForceCounter = 0
	commonRequest.Service = service
	commonRequest.Session = guid
	commonRequest.ClientIP = clientIP
	commonRequest.ClientPort = clientPort
	commonRequest.ClientNet = clientNet
	commonRequest.ClientHost = clientHost
	commonRequest.ClientID = clientID
	commonRequest.LocalIP = localIP
	commonRequest.LocalPort = localPort
	commonRequest.UserAgent = userAgent
	commonRequest.Username = username
	commonRequest.Account = accountName
	commonRequest.AccountField = accountField
	commonRequest.UniqueUserID = uniqueUserID
	commonRequest.DisplayName = displayName
	commonRequest.Password = password
	commonRequest.Protocol = protocol
	commonRequest.OIDCCID = oidccid
	commonRequest.BruteForceName = bruteForceName
	commonRequest.FeatureName = featureName
	commonRequest.StatusMessage = &statusMessage
	commonRequest.XSSL = xSSL
	commonRequest.XSSLSessionID = xSSLSessionID
	commonRequest.XSSLClientVerify = xSSLClientVerify
	commonRequest.XSSLClientDN = xSSLClientDN
	commonRequest.XSSLClientCN = xSSLClientCN
	commonRequest.XSSLIssuer = xSSLIssuer
	commonRequest.XSSLClientNotBefore = xSSLClientNotBefore
	commonRequest.XSSLClientNotAfter = xSSLClientNotAfter
	commonRequest.XSSLSubjectDN = xSSLSubjectDN
	commonRequest.XSSLIssuerDN = xSSLIssuerDN
	commonRequest.XSSLClientSubjectDN = xSSLClientSubjectDN
	commonRequest.XSSLClientIssuerDN = xSSLClientIssuerDN
	commonRequest.XSSLProtocol = xSSLProtocol
	commonRequest.XSSLCipher = xSSLCipher
	commonRequest.SSLSerial = sSLSerial
	commonRequest.SSLFingerprint = sSLFingerprint

	action.RequestChan <- &action.Action{
		LuaAction:     definitions.LuaActionPost,
		Context:       context,
		FinishedChan:  finished,
		HTTPRequest:   httpRequest,
		CommonRequest: commonRequest,
	}

	<-finished

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)
}

// PostLuaAction sends a Lua action to be executed asynchronously.
func (a *AuthState) PostLuaAction(passDBResult *PassDBResult) {
	if !config.GetFile().HaveLuaActions() {
		return
	}

	// Make sure we have all the required values and they're not nil
	if a.GUID == nil || a.UserAgent == nil || a.Protocol == nil || a.HTTPClientContext == nil || a.Context == nil {
		return
	}

	// Get account name and check if user was found
	accountName := a.GetAccount()
	userFound := passDBResult.UserFound || accountName != ""

	// Make a copy of the status message
	statusMessageCopy := a.StatusMessage

	// Start a goroutine with copies of all necessary values
	go executeLuaPostAction(
		a.Context,
		a.HTTPClientContext.Request,
		*a.GUID,
		a.NoAuth,
		a.Service,
		a.ClientIP,
		a.XClientPort,
		a.ClientHost,
		a.XClientID,
		a.XLocalIP,
		a.XPort,
		*a.UserAgent,
		a.Username,
		accountName,
		a.GetAccountField(),
		a.GetUniqueUserID(),
		a.GetDisplayName(),
		a.Password,
		a.Protocol.Get(),
		a.OIDCCID,
		a.BruteForceName,
		a.FeatureName,
		statusMessageCopy,
		a.XSSL,
		a.XSSLSessionID,
		a.XSSLClientVerify,
		a.XSSLClientDN,
		a.XSSLClientCN,
		a.XSSLIssuer,
		a.XSSLClientNotBefore,
		a.XSSLClientNotAfter,
		a.XSSLSubjectDN,
		a.XSSLIssuerDN,
		a.XSSLClientSubjectDN,
		a.XSSLClientIssuerDN,
		a.XSSLProtocol,
		a.XSSLCipher,
		a.SSLSerial,
		a.SSLFingerprint,
		userFound,
		passDBResult.Authenticated,
		a.BFClientNet,
		a.BFRepeating,
	)
}

// HaveMonitoringFlag checks if the provided flag exists in the MonitoringFlags slice of the AuthState object.
// It iterates over the MonitoringFlags slice and returns true if the flag is found, otherwise it returns false.
func (a *AuthState) HaveMonitoringFlag(flag definitions.Monitoring) bool {
	for _, setFlag := range a.MonitoringFlags {
		if setFlag == flag {
			return true
		}
	}

	return false
}

// sfAuthResult encapsulates the auth result along with the LeaderID so that
// followers can determine if they were leader or follower for logging.
// It can also carry an optional Envelope to hydrate follower state.
type sfAuthResult struct {
	AuthResult definitions.AuthResult
	LeaderID   string
	Envelope   *sfAuthEnvelope
}

// sfAuthEnvelope is a rich result used for distributed singleflight to carry
// not only the AuthResult but also all relevant user attributes and backend info.
type sfAuthEnvelope struct {
	Version    int                    `json:"v"`
	AuthResult definitions.AuthResult `json:"ar"`

	UserFound     bool `json:"uf"`
	Authenticated bool `json:"au"`

	BackendName         string              `json:"bn,omitempty"`
	SourcePassDBBackend definitions.Backend `json:"sb,omitempty"`
	UsedPassDBBackend   definitions.Backend `json:"ub,omitempty"`

	AccountField    string `json:"af,omitempty"`
	UniqueUserID    string `json:"uid,omitempty"`
	DisplayName     string `json:"dn,omitempty"`
	TOTPSecretField string `json:"totp,omitempty"`

	Attributes      bktype.AttributeMapping `json:"attr,omitempty"`
	AdditionalFeat  map[string]any          `json:"feat,omitempty"`
	LeaderSessionID string                  `json:"ls,omitempty"`

	StatusMessage string `json:"sm,omitempty"`
}

// sfWriteEnvelope writes the rich envelope to Redis with a short TTL.
func (a *AuthState) sfWriteEnvelope(ctx context.Context, rdb redis.UniversalClient, resKey string, env *sfAuthEnvelope) error {
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	b, err := json.Marshal(env)
	if err != nil {
		return err
	}

	return rdb.Set(ctx, resKey, b, definitions.RedisSFResultTTL).Err()
}

// sfReadEnvelope reads a rich envelope from Redis. It supports backward compatibility
// with legacy integer-only values by converting them into a minimal envelope.
func (a *AuthState) sfReadEnvelope(ctx context.Context, rdb redis.UniversalClient, resKey string) (*sfAuthEnvelope, bool, error) {
	stats.GetMetrics().GetRedisReadCounter().Inc()

	data, err := rdb.Get(ctx, resKey).Bytes()
	if stderrors.Is(err, redis.Nil) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, err
	}

	// Try legacy integer format first
	if len(data) > 0 {
		if v, convErr := strconv.Atoi(string(data)); convErr == nil {
			return &sfAuthEnvelope{Version: 0, AuthResult: definitions.AuthResult(v)}, true, nil
		}
	}

	var env sfAuthEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, false, err
	}

	if env.Version == 0 {
		env.Version = 1
	}

	return &env, true, nil
}

// applyEnvelope hydrates the AuthState with data from the envelope.
func (a *AuthState) applyEnvelope(env *sfAuthEnvelope) {
	if env == nil {
		return
	}

	if env.StatusMessage != "" {
		a.StatusMessage = env.StatusMessage
	}

	if env.UserFound {
		a.UserFound = true
		a.SourcePassDBBackend = env.SourcePassDBBackend
		a.UsedPassDBBackend = env.UsedPassDBBackend
		a.BackendName = env.BackendName
	}

	if env.AccountField != "" {
		af := env.AccountField
		a.AccountField = &af
	}

	if env.UniqueUserID != "" {
		uid := env.UniqueUserID
		a.UniqueUserIDField = &uid
	}

	if env.DisplayName != "" {
		dn := env.DisplayName
		a.DisplayNameField = &dn
	}

	if env.TOTPSecretField != "" {
		totp := env.TOTPSecretField
		a.TOTPSecretField = &totp
	}

	if env.Attributes != nil && len(env.Attributes) > 0 {
		a.Attributes = env.Attributes
	}

	if env.AdditionalFeat != nil && a.HTTPClientContext != nil {
		a.HTTPClientContext.Set(definitions.CtxAdditionalFeaturesKey, env.AdditionalFeat)
	}

	if env.Authenticated {
		localcache.AuthCache.Set(a.Username, true)
	}
}

// buildEnvelopeFromState builds an envelope from the current AuthState and result.
func (a *AuthState) buildEnvelopeFromState(r definitions.AuthResult) *sfAuthEnvelope {
	env := &sfAuthEnvelope{
		Version:             1,
		AuthResult:          r,
		UserFound:           a.UserFound,
		BackendName:         a.BackendName,
		SourcePassDBBackend: a.SourcePassDBBackend,
		UsedPassDBBackend:   a.UsedPassDBBackend,
		StatusMessage:       a.StatusMessage,
	}

	// Best effort for authenticated flag
	env.Authenticated = r == definitions.AuthResultOK

	if a.AccountField != nil {
		env.AccountField = *a.AccountField
	}

	if a.UniqueUserIDField != nil {
		env.UniqueUserID = *a.UniqueUserIDField
	}

	if a.DisplayNameField != nil {
		env.DisplayName = *a.DisplayNameField
	}

	if a.TOTPSecretField != nil {
		env.TOTPSecretField = *a.TOTPSecretField
	}

	if a.Attributes != nil && len(a.Attributes) > 0 {
		env.Attributes = a.Attributes
	}

	if a.HTTPClientContext != nil {
		if v, ok := a.HTTPClientContext.Get(definitions.CtxAdditionalFeaturesKey); ok {
			if m, ok2 := v.(map[string]any); ok2 {
				env.AdditionalFeat = m
			}
		}
	}

	return env
}

// --- Distributed singleflight (Redis) helpers ---

// sfKeyHash returns a short hash for the strict singleflight key to use in Redis keys.
func (a *AuthState) sfKeyHash() string {
	sum := sha1.Sum([]byte(a.generateSingleflightKey()))

	return hex.EncodeToString(sum[:])
}

// sfRedisKeys builds the Redis keys (result, lock) and channel name for a given auth request.
func (a *AuthState) sfRedisKeys() (resKey, lockKey, ch string) {
	suf := a.sfKeyHash()

	return definitions.RedisSFPrefixResult + suf, definitions.RedisSFPrefixLock + suf, definitions.RedisSFPrefixChannel + suf
}

// sfReadResult reads a short-lived AuthResult from Redis. Returns (result, found, error).
func (a *AuthState) sfReadResult(ctx context.Context, rdb redis.UniversalClient, resKey string) (definitions.AuthResult, bool, error) {
	stats.GetMetrics().GetRedisReadCounter().Inc()

	s, err := rdb.Get(ctx, resKey).Result()
	if stderrors.Is(err, redis.Nil) {
		return 0, false, nil
	}

	if err != nil {
		return 0, false, err
	}

	v, convErr := strconv.Atoi(s)
	if convErr != nil {
		return 0, false, convErr
	}

	return definitions.AuthResult(v), true, nil
}

// sfWriteResult writes the AuthResult to Redis with a short TTL.
func (a *AuthState) sfWriteResult(ctx context.Context, rdb redis.UniversalClient, resKey string, r definitions.AuthResult) error {
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	return rdb.Set(ctx, resKey, strconv.Itoa(int(r)), definitions.RedisSFResultTTL).Err()
}

// sfTryLock tries to acquire a short lock in Redis with a random token.
func (a *AuthState) sfTryLock(ctx context.Context, rdb redis.UniversalClient, lockKey string) (token string, ok bool, err error) {
	// lightweight token; uniqueness is sufficient here
	token = fmt.Sprintf("%s-%d", a.Username, time.Now().UnixNano())

	stats.GetMetrics().GetRedisWriteCounter().Inc()

	ok, err = rdb.SetNX(ctx, lockKey, token, definitions.RedisSFLockTTL).Result()

	return
}

// sfUnlock releases the lock if the token still matches (best effort).
func (a *AuthState) sfUnlock(ctx context.Context, lockKey, token string) {
	// Use central Redis Lua script executor which uploads scripts and tracks stats
	_, _ = rediscli.ExecuteScript(ctx, "UnlockIfTokenMatches", rediscli.LuaScripts["UnlockIfTokenMatches"], []string{lockKey}, token)
}

// sfPubSubWait subscribes to a channel and waits for a wakeup, checking the result key after subscribe and upon messages.
func (a *AuthState) sfPubSubWait(ctx context.Context, rdb redis.UniversalClient, channel string, check func() (definitions.AuthResult, bool, error)) (definitions.AuthResult, bool) {
	stats.GetMetrics().GetRedisReadCounter().Inc()

	pubsub := rdb.Subscribe(ctx, channel)
	defer pubsub.Close()

	// After subscribing, immediately check for an already present result
	if r, ok, err := check(); err == nil && ok {
		return r, true
	}

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return 0, false
		case msg := <-ch:
			if msg == nil {
				return 0, false
			}

			if r, ok, err := check(); err == nil && ok {
				return r, true
			}
		}
	}
}

// HandlePassword handles the authentication process for the password flow.
// It performs common validation checks and then proceeds based on the value of ctx.Value(definitions.CtxLocalCacheAuthKey).
// If it is true, it calls the handleLocalCache function.
// Otherwise, it calls the handleBackendTypes function to determine the cache usage, backend position, and password databases.
// In the next step, it calls the authenticateUser function to perform further control flow based on cache usage and authentication status.
// Finally, it returns the authResult which indicates the authentication result of the process.
func (a *AuthState) HandlePassword(ctx *gin.Context) (authResult definitions.AuthResult) {
	// Common validation checks
	if authResult = a.usernamePasswordChecks(); authResult != definitions.AuthResultUnset {
		return
	}

	if !(a.HaveMonitoringFlag(definitions.MonInMemory) || a.IsMasterUser()) && ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		return a.handleLocalCache(ctx)
	}

	// In-process singleflight deduplication (backchannel only)
	key := a.generateSingleflightKey()
	reqCtx := ctx.Request.Context()

	// Distributed result shortcut (cluster-wide): if another instance already finished
	// this key very recently, use its result immediately to avoid extra work.
	var redisWrite redis.UniversalClient
	var redisRead redis.UniversalClient

	// Option A: allow disabling distributed dedup via configuration (default: disabled)
	distEnabled := config.GetFile().GetServer().GetDedup().IsDistributedEnabled()
	if distEnabled {
		if rc := rediscli.GetClient(); rc != nil {
			redisWrite = rc.GetWriteHandle()
			redisRead = rc.GetReadHandle()

			if redisRead != nil {
				resKey, _, _ := a.sfRedisKeys()
				if env, ok, _ := a.sfReadEnvelope(reqCtx, redisRead, resKey); ok {
					// Take distributed result with full attributes
					a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "dist_follower")

					if env.LeaderSessionID != "" {
						a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeaderSession, env.LeaderSessionID)
					}

					a.applyEnvelope(env)

					return env.AuthResult
				}
			}
		}
	}

	// Prepare per-request ID for leadership detection (prefer GUID)
	reqID := ""
	if a.GUID != nil {
		reqID = *a.GUID
	} else {
		reqID = fmt.Sprintf("no-guid-%d", time.Now().UnixNano())
	}

	// Derive wait deadline from request context, with a small safety cap if none
	var timer *time.Timer

	if dl, ok := reqCtx.Deadline(); ok {
		d := time.Until(dl)
		if d <= 0 {
			backchanSF.Forget(key)

			return definitions.AuthResultTempFail
		}

		timer = time.NewTimer(d)
	} else {
		timer = time.NewTimer(definitions.SingleflightWaitCap)
	}

	defer timer.Stop()

	// Allow disabling in-process singleflight via config (default: enabled)
	inProcEnabled := config.GetFile().GetServer().GetDedup().IsInProcessEnabled()
	if !inProcEnabled {
		// Skip in-process dedup; optionally use distributed coordination if enabled
		if distEnabled && redisWrite != nil {
			resKey, lockKey, chName := a.sfRedisKeys()
			if token, got, _ := a.sfTryLock(reqCtx, redisWrite, lockKey); got {
				defer a.sfUnlock(reqCtx, lockKey, token)

				useCache, backendPos, passDBs := a.handleBackendTypes()
				r := a.authenticateUser(ctx, useCache, backendPos, passDBs)
				env := a.buildEnvelopeFromState(r)
				env.LeaderSessionID = reqID
				_ = a.sfWriteEnvelope(reqCtx, redisWrite, resKey, env)
				_ = redisWrite.Publish(reqCtx, chName, "1").Err()

				a.applyEnvelope(env)
				a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "leader")

				return r
			}

			if r, ok := a.sfPubSubWait(reqCtx, redisWrite, chName, func() (definitions.AuthResult, bool, error) {
				env, ok, err := a.sfReadEnvelope(reqCtx, redisRead, resKey)
				if err != nil || !ok {
					return 0, false, err
				}

				a.applyEnvelope(env)

				return env.AuthResult, true, nil
			}); ok {
				a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "follower")

				return r
			}
			// Timeout/cancel: fall through to local compute
		}

		useCache, backendPos, passDBs := a.handleBackendTypes()
		res := a.authenticateUser(ctx, useCache, backendPos, passDBs)
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "fallback_no_inproc")

		return res
	}

	ch := backchanSF.DoChan(key, func() (any, error) {
		// If distributed dedup is enabled and Redis is available, coordinate across instances
		if distEnabled && redisWrite != nil {
			resKey, lockKey, chName := a.sfRedisKeys()

			if token, got, _ := a.sfTryLock(reqCtx, redisWrite, lockKey); got {
				defer a.sfUnlock(reqCtx, lockKey, token)

				useCache, backendPos, passDBs := a.handleBackendTypes()
				r := a.authenticateUser(ctx, useCache, backendPos, passDBs)
				env := a.buildEnvelopeFromState(r)

				// Include leader session ID so followers can log it
				env.LeaderSessionID = reqID

				_ = a.sfWriteEnvelope(reqCtx, redisWrite, resKey, env)
				_ = redisWrite.Publish(reqCtx, chName, "1").Err()

				return sfAuthResult{AuthResult: r, LeaderID: reqID, Envelope: env}, nil
			}

			// Didn't get the lock: wait via Pub/Sub for result, then read once
			var leaderID string
			var envCaptured *sfAuthEnvelope

			if r, ok := a.sfPubSubWait(reqCtx, redisWrite, chName, func() (definitions.AuthResult, bool, error) {
				env, ok, err := a.sfReadEnvelope(reqCtx, redisRead, resKey)
				if err != nil || !ok {
					return 0, false, err
				}

				// Rehydrate state from leader envelope
				a.applyEnvelope(env)

				leaderID = env.LeaderSessionID
				envCaptured = env

				return env.AuthResult, true, nil
			}); ok {
				return sfAuthResult{AuthResult: r, LeaderID: leaderID, Envelope: envCaptured}, nil
			}
			// Timeout/cancel: fallthrough to compute locally
		}

		useCache, backendPos, passDBs := a.handleBackendTypes()
		res := a.authenticateUser(ctx, useCache, backendPos, passDBs)
		env := a.buildEnvelopeFromState(res)

		// Leader returns its reqID for followers to compare
		return sfAuthResult{AuthResult: res, LeaderID: reqID, Envelope: env}, nil
	})

	select {
	case r := <-ch:
		if r.Err != nil {
			return definitions.AuthResultTempFail
		}

		sfa := r.Val.(sfAuthResult)
		if sfa.Envelope != nil {
			a.applyEnvelope(sfa.Envelope)
		}

		role := "follower"
		if sfa.LeaderID == reqID {
			role = "leader"
		}

		// Log leadership role for large log output
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, role)

		// If we are a follower and the leader ID is known, log it
		if sfa.LeaderID != "" && sfa.LeaderID != reqID {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeaderSession, sfa.LeaderID)
		}

		return sfa.AuthResult
	case <-reqCtx.Done():
		// Client disconnected or context canceled: stop waiting and attempt direct auth as fallback
		backchanSF.Forget(key)

		useCache, backendPos, passDBs := a.handleBackendTypes()
		res := a.authenticateUser(ctx, useCache, backendPos, passDBs)

		// Log fallback as follower information as requested
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "fallback_ctx_canceled")

		return res
	case <-timer.C:
		// Wait cap/deadline reached: stop waiting and attempt direct auth as fallback
		backchanSF.Forget(key)

		useCache, backendPos, passDBs := a.handleBackendTypes()
		res := a.authenticateUser(ctx, useCache, backendPos, passDBs)

		// Log fallback info
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "fallback_timeout")

		return res
	}
}

// usernamePasswordChecks performs checks on the Username and Password fields of the AuthState object.
// It logs debug messages for empty username or empty password cases.
// It returns definitions.AuthResultEmptyUsername if the username is empty.
// It returns definitions.AuthResultEmptyPassword if the password is empty.
// Otherwise, it returns definitions.AuthResultUnset.
// Usage example:
//
//	func (a *AuthState) handlePassword(ctx *gin.Context) (authResult global.AuthResult) {
//		a.usernamePasswordChecks()
//		...
//	}
//
// Dependencies:
// - util.DebugModule
// - definitions.AuthResult
// - definitions.DbgAuth
// - definitions.LogKeyGUID
// - definitions.LogKeyMsg
func (a *AuthState) usernamePasswordChecks() definitions.AuthResult {
	if a.Username == "" {
		util.DebugModule(definitions.DbgAuth, definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "Empty username")

		return definitions.AuthResultEmptyUsername
	}

	if !a.NoAuth && a.Password == "" {
		util.DebugModule(definitions.DbgAuth, definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "Empty password")

		return definitions.AuthResultEmptyPassword
	}

	return definitions.AuthResultUnset
}

// handleLocalCache handles the local cache authentication logic for the AuthState object.
// It sets the operation mode and initializes the passDBResult.
// Then, it filters the authentication result through the Lua filter.
// After that, the PostLuaAction is executed on the passDBResult.
// Finally, it returns the authResult of type definitions.AuthResult.
func (a *AuthState) handleLocalCache(ctx *gin.Context) definitions.AuthResult {
	a.SetOperationMode(ctx)

	passDBResult := a.initializePassDBResult()

	// Since this path is a confirmed positive hit from the in-memory cache,
	// the PassDB stage has already decided previously. Reflect that in AuthState
	// so final logs include authn=true for cache hits.
	a.Authenticated = true

	authResult := definitions.AuthResultOK

	if !(a.Protocol.Get() == definitions.ProtoOryHydra) {
		authResult = a.FilterLua(passDBResult, ctx)

		a.PostLuaAction(passDBResult)
	}

	return authResult
}

// initializePassDBResult initializes a new instance of PassDBResult with values from the AuthState object.
// It sets Authenticated and UserFound to true and copies the values of AccountField, TOTPSecretField, TOTPRecoveryField,
// UniqueUserIDField, DisplayNameField, Backend, and Attributes from the AuthState object.
// The initialized PassDBResult instance is returned.
func (a *AuthState) initializePassDBResult() *PassDBResult {
	result := GetPassDBResultFromPool()

	result.Authenticated = true
	result.UserFound = true
	result.AccountField = a.AccountField
	result.TOTPSecretField = a.TOTPSecretField
	result.TOTPRecoveryField = a.TOTPRecoveryField
	result.UniqueUserIDField = a.UniqueUserIDField
	result.DisplayNameField = a.DisplayNameField
	result.Backend = a.UsedPassDBBackend
	result.Attributes = a.Attributes

	return result
}

// handleBackendTypes initializes and populates variables related to backend types.
// The `backendPos` map stores the position of each backend type in the configuration list.
// The `useCache` boolean indicates whether the Cache backend type is used. It is set to true if at least one Cache backend is found in the configuration.
// The `passDBs` slice holds the PassDBMap objects associated with each backend type in the configuration.
// This method loops through the `config.GetFile().GetServer().Backends` slice and processes each Backend object to determine the backend type. It populates the `backendPos` map with the backend type
func (a *AuthState) handleBackendTypes() (useCache bool, backendPos map[definitions.Backend]int, passDBs []*PassDBMap) {
	backendPos = make(map[definitions.Backend]int)

	for index, backendType := range config.GetFile().GetServer().GetBackends() {
		db := backendType.Get()
		switch db {
		case definitions.BackendCache:
			if !(a.HaveMonitoringFlag(definitions.MonCache) || a.IsMasterUser()) {
				passDBs = a.appendBackend(passDBs, definitions.BackendCache, CachePassDB)
				useCache = true
			}
		case definitions.BackendLDAP:
			if !config.GetFile().LDAPHavePoolOnly(backendType.GetName()) {
				mgr := NewLDAPManager(backendType.GetName())
				passDBs = a.appendBackend(passDBs, definitions.BackendLDAP, mgr.PassDB)
			}
		case definitions.BackendLua:
			mgr := NewLuaManager(backendType.GetName())
			passDBs = a.appendBackend(passDBs, definitions.BackendLua, mgr.PassDB)
		case definitions.BackendUnknown:
		case definitions.BackendLocalCache:
		}

		backendPos[db] = index
	}

	return useCache, backendPos, passDBs
}

// appendBackend appends a new PassDBMap object to the passDBs slice.
// Parameters:
// - passDBs: the slice of PassDBMap objects to append to
// - backendType: the definitions.Backend value representing the backend type
// - backendFunction: the PassDBOption function to assign to the PassDBMap object
// Returns:
// - The modified passDBs slice with the new PassDBMap object appended
func (a *AuthState) appendBackend(passDBs []*PassDBMap, backendType definitions.Backend, backendFunction PassDBOption) []*PassDBMap {
	return append(passDBs, &PassDBMap{
		backendType,
		backendFunction,
	})
}

// processVerifyPassword verifies the user's password against multiple databases.
// It logs detailed information in case of errors and returns the result of the password verification process.
func (a *AuthState) processVerifyPassword(ctx *gin.Context, passDBs []*PassDBMap) (*PassDBResult, error) {
	passDBResult, err := a.verifyPassword(ctx, passDBs)
	if err != nil {
		var detailedError *errors.DetailedError

		if stderrors.As(err, &detailedError) {
			logs := []any{
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, detailedError.Error(),
				definitions.LogKeyErrorDetails, detailedError.GetDetails(),
			}

			if len(a.AdditionalLogs) > 0 && len(a.AdditionalLogs)%2 == 0 {
				logs = append(logs, a.AdditionalLogs...)
			}

			level.Error(log.Logger).Log(logs...)
		} else {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err.Error())
		}
	}

	return passDBResult, err
}

// processUserFound handles the processing when a user is found in the database, updates user account in Redis, and processes password history.
// It returns the account name and any error encountered during the process.
func (a *AuthState) processUserFound(passDBResult *PassDBResult) (accountName string, err error) {
	var bm bruteforce.BucketManager

	if a.UserFound {
		accountName, err = a.updateUserAccountInRedis()
		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err.Error())
		}

		if !passDBResult.Authenticated {
			bm = bruteforce.NewBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP).
				WithUsername(a.Username).
				WithPassword(a.Password).
				WithAccountName(accountName)

			// Set the protocol if available
			if a.Protocol != nil && a.Protocol.Get() != "" {
				bm = bm.WithProtocol(a.Protocol.Get())
			}

			// Set the OIDC Client ID if available
			if a.OIDCCID != "" {
				bm = bm.WithOIDCCID(a.OIDCCID)
			}

			bm.ProcessPWHist()
		}
	}

	return
}

// isCacheInCorrectPosition checks if the cache backend is positioned before the used password database backend.
func (a *AuthState) isCacheInCorrectPosition(backendPos map[definitions.Backend]int) bool {
	return backendPos[definitions.BackendCache] < backendPos[a.UsedPassDBBackend]
}

// getUsedBackend returns the cache name backend based on the used password database backend.
func (a *AuthState) getUsedBackend() (definitions.CacheNameBackend, error) {
	var usedBackend definitions.CacheNameBackend

	switch a.UsedPassDBBackend {
	case definitions.BackendLDAP:
		usedBackend = definitions.CacheLDAP
	case definitions.BackendLua:
		usedBackend = definitions.CacheLua
	case definitions.BackendUnknown:
	case definitions.BackendCache:
	case definitions.BackendLocalCache:
	default:
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "Unable to get the cache name backend.")

		return usedBackend, errors.ErrIncorrectCache
	}

	return usedBackend, nil
}

// getCacheName retrieves the cache name associated with the given backend, based on the protocol configured for the AuthState.
func (a *AuthState) getCacheName(usedBackend definitions.CacheNameBackend) (cacheName string, err error) {
	cacheNames := backend.GetCacheNames(a.Protocol.Get(), usedBackend)
	if len(cacheNames) != 1 {
		level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "Cache names are not correct")

		return "", errors.ErrIncorrectCache
	}

	cacheName = cacheNames.GetStringSlice()[definitions.SliceWithOneElement]

	return
}

// createPositivePasswordCache constructs a PositivePasswordCache containing user authentication details.
func (a *AuthState) createPositivePasswordCache() *bktype.PositivePasswordCache {
	return &bktype.PositivePasswordCache{
		AccountField:      a.AccountField,
		TOTPSecretField:   a.TOTPSecretField,
		UniqueUserIDField: a.UniqueUserIDField,
		DisplayNameField:  a.DisplayNameField,
		Password: func() string {
			if a.Password != "" {
				passwordShort := util.GetHash(util.PreparePassword(a.Password))

				return passwordShort
			}

			return ""
		}(),
		Backend:    a.SourcePassDBBackend,
		Attributes: a.Attributes,
	}
}

// saveUserPositiveCache stores a positive authentication result in the Redis cache if the account name is not empty.
func (a *AuthState) saveUserPositiveCache(ppc *bktype.PositivePasswordCache, cacheName, accountName string) {
	if accountName != "" {
		redisUserKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + cacheName + ":" + accountName

		if ppc.Password != "" {
			go backend.SaveUserDataToRedis(a.HTTPClientContext, *a.GUID, redisUserKey, config.GetFile().GetServer().Redis.PosCacheTTL, ppc)
		}
	}
}

// processCacheUserLoginOk updates the user cache with a positive authentication result.
// It retrieves the backend used during authentication and the respective cache name to save the user information.
func (a *AuthState) processCacheUserLoginOk(accountName string) error {
	usedBackend, err := a.getUsedBackend()
	if err != nil {
		return err
	}

	cacheName, err := a.getCacheName(usedBackend)
	if err != nil {
		return err
	}

	a.saveUserPositiveCache(
		a.createPositivePasswordCache(),
		cacheName,
		accountName,
	)

	return nil
}

// processCacheUserLoginFail processes the cache update when a user login fails. It logs the event and updates the failure counter.
func (a *AuthState) processCacheUserLoginFail(ctx *gin.Context, accountName string) {
	var bm bruteforce.BucketManager

	util.DebugModule(
		definitions.DbgAuth,
		definitions.LogKeyGUID, a.GUID,
		"account", accountName,
		"authenticated", false,
		definitions.LogKeyMsg, "Calling saveFailedPasswordCounterInRedis()",
	)

	// Increase counters (burst-deduplicated)
	bm = bruteforce.NewBucketManager(ctx.Request.Context(), *a.GUID, a.ClientIP).
		WithUsername(a.Username).
		WithPassword(a.Password).
		WithAccountName(accountName)

	ttl := time.Second
	argTTL := strconv.FormatInt(int64(ttl.Seconds()), 10)
	burstKey := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisBFBurstPrefix + a.sfKeyHash()

	if res, err := rediscli.ExecuteScript(ctx.Request.Context(), "IncrementAndExpire", rediscli.LuaScripts["IncrementAndExpire"], []string{burstKey}, argTTL); err == nil {
		if v, ok := res.(int64); ok && v == 1 {
			bm.SaveFailedPasswordCounterInRedis()
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "bf_burst_leader")
		} else {
			a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "bf_burst_follower")
		}
	} else {
		// Fail-open: still count, but log error as follower for visibility
		bm.SaveFailedPasswordCounterInRedis()
		a.AdditionalLogs = append(a.AdditionalLogs, definitions.LogKeyLeadership, "bf_burst_leader")
	}
}

// processCache updates the relevant user cache entries based on authentication results from password databases.
func (a *AuthState) processCache(ctx *gin.Context, authenticated bool, accountName string, useCache bool, backendPos map[definitions.Backend]int) error {
	var bm bruteforce.BucketManager

	if !a.NoAuth && useCache && a.isCacheInCorrectPosition(backendPos) {
		if authenticated {
			err := a.processCacheUserLoginOk(accountName)
			if err != nil {
				return err
			}
		} else {
			a.processCacheUserLoginFail(ctx, accountName)
		}

		bm = bruteforce.NewBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP).
			WithUsername(a.Username).
			WithPassword(a.Password).
			WithAccountName(accountName)

		// Set the protocol if available
		if a.Protocol != nil && a.Protocol.Get() != "" {
			bm = bm.WithProtocol(a.Protocol.Get())
		}

		// Set the OIDC Client ID if available
		if a.OIDCCID != "" {
			bm = bm.WithOIDCCID(a.OIDCCID)
		}

		bm.LoadAllPasswordHistories()

		a.LoginAttempts = bm.GetLoginAttempts()
		a.PasswordsAccountSeen = bm.GetPasswordsAccountSeen()
		a.PasswordsTotalSeen = bm.GetPasswordsTotalSeen()
	}

	return nil
}

// authenticateUser manages the post-verification steps in the authentication process.
// It first verifies the password provided by the user. If the verification fails, it logs the error and returns temporary failure.
// If the cache is being used and the user is not excluded from authentication, it ensures that the cache backend precedes the used backend.
// If the verification is successful, user data is saved to Redis. If it fails, it increases the brute force counter.
// It then tries to get all password histories of the user. If the user is not found, it updates the brute force buckets counter,
// call post Lua action and return authentication failure.
// It also checks if the user is found during password verification, if true, it sets a new username to the user.
// Afterward, it applies a Lua filter to the result and calls the post Lua action, and finally, it returns the authentication result.
func (a *AuthState) authenticateUser(ctx *gin.Context, useCache bool, backendPos map[definitions.Backend]int, passDBs []*PassDBMap) definitions.AuthResult {
	var (
		accountName  string
		authResult   definitions.AuthResult
		passDBResult *PassDBResult
		err          error
	)

	if passDBResult, err = a.processVerifyPassword(ctx, passDBs); err != nil {
		// tempfail: no backend decision could be made
		a.Authenticated = false

		return definitions.AuthResultTempFail
	}

	if accountName, err = a.processUserFound(passDBResult); err != nil {
		// treat as tempfail
		a.Authenticated = false

		return definitions.AuthResultTempFail
	}

	if err = a.processCache(ctx, passDBResult.Authenticated, accountName, useCache, backendPos); err != nil {
		// tempfail during cache processing
		a.Authenticated = false

		return definitions.AuthResultTempFail
	}

	if passDBResult.Authenticated {
		if !(a.HaveMonitoringFlag(definitions.MonInMemory) || a.IsMasterUser()) {
			localcache.LocalCache.Set(a.generateLocalCacheKey(), passDBResult, config.GetEnvironment().GetLocalCacheAuthTTL())
		}

		a.Authenticated = true
		authResult = definitions.AuthResultOK
	} else {
		a.UpdateBruteForceBucketsCounter(ctx)

		a.Authenticated = false
		authResult = definitions.AuthResultFail
	}

	if !(a.Protocol.Get() == definitions.ProtoOryHydra) {
		authResult = a.FilterLua(passDBResult, ctx)

		a.PostLuaAction(passDBResult)
	}

	return authResult
}

// FilterLua calls Lua filters which can change the backend result.
func (a *AuthState) FilterLua(passDBResult *PassDBResult, ctx *gin.Context) definitions.AuthResult {
	if !config.GetFile().HaveLuaFilters() {
		// No filters configured → treat as authorized
		a.Authorized = true

		if passDBResult.Authenticated {
			return definitions.AuthResultOK
		}

		return definitions.AuthResultFail
	}

	stopTimer := stats.PrometheusTimer(definitions.PromFilter, "lua_filter_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	BackendServers.mu.RLock()

	backendServers := BackendServers.backendServer

	util.DebugModule(definitions.DbgFeature, definitions.LogKeyMsg, fmt.Sprintf("Active backend servers: %d", len(backendServers)))

	BackendServers.mu.RUnlock()

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = false // unavailable
	commonRequest.UserFound = passDBResult.UserFound
	commonRequest.Authenticated = passDBResult.Authenticated
	commonRequest.NoAuth = a.NoAuth
	commonRequest.BruteForceCounter = 0 // unavailable
	commonRequest.Service = a.Service
	commonRequest.Session = *a.GUID
	commonRequest.ClientIP = a.ClientIP
	commonRequest.ClientPort = a.XClientPort
	commonRequest.ClientNet = "" // unavailable
	commonRequest.ClientHost = a.ClientHost
	commonRequest.ClientID = a.XClientID
	commonRequest.UserAgent = *a.UserAgent
	commonRequest.LocalIP = a.XLocalIP
	commonRequest.LocalPort = a.XPort
	commonRequest.Username = a.Username
	commonRequest.Account = a.GetAccount()
	commonRequest.AccountField = a.GetAccountField()
	commonRequest.UniqueUserID = a.GetUniqueUserID()
	commonRequest.DisplayName = a.GetDisplayName()
	commonRequest.Password = a.Password
	commonRequest.Protocol = a.Protocol.String()
	commonRequest.OIDCCID = a.OIDCCID
	commonRequest.BruteForceName = "" // unavailable
	commonRequest.FeatureName = ""    // unavailable
	commonRequest.StatusMessage = &a.StatusMessage
	commonRequest.XSSL = a.XSSL
	commonRequest.XSSLSessionID = a.XSSLSessionID
	commonRequest.XSSLClientVerify = a.XSSLClientVerify
	commonRequest.XSSLClientDN = a.XSSLClientDN
	commonRequest.XSSLClientCN = a.XSSLClientCN
	commonRequest.XSSLIssuer = a.XSSLIssuer
	commonRequest.XSSLClientNotBefore = a.XSSLClientNotBefore
	commonRequest.XSSLClientNotAfter = a.XSSLClientNotAfter
	commonRequest.XSSLSubjectDN = a.XSSLSubjectDN
	commonRequest.XSSLIssuerDN = a.XSSLIssuerDN
	commonRequest.XSSLClientSubjectDN = a.XSSLClientSubjectDN
	commonRequest.XSSLClientIssuerDN = a.XSSLClientIssuerDN
	commonRequest.XSSLProtocol = a.XSSLProtocol
	commonRequest.XSSLCipher = a.XSSLCipher
	commonRequest.SSLSerial = a.SSLSerial
	commonRequest.SSLFingerprint = a.SSLFingerprint

	filterRequest := &filter.Request{
		BackendServers:     backendServers,
		UsedBackendAddress: &a.UsedBackendIP,
		UsedBackendPort:    &a.UsedBackendPort,
		Logs:               nil,
		Context:            a.Context,
		CommonRequest:      commonRequest,
	}

	filterResult, luaBackendResult, removeAttributes, err := filterRequest.CallFilterLua(ctx)
	if err != nil {
		if !stderrors.Is(err, errors.ErrNoFiltersDefined) {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err.Error())

			// Return the CommonRequest to the pool even if there's an error
			lualib.PutCommonRequest(commonRequest)

			// error during filter execution → not authorized
			a.Authorized = false

			return definitions.AuthResultTempFail
		}

		// Explicitly authorized when no filters are defined
		a.Authorized = true
	} else {
		if filterRequest.Logs != nil && len(*filterRequest.Logs) > 0 {
			// Pre-allocate the AdditionalLogs slice to avoid continuous reallocation
			additionalLogsLen := len(a.AdditionalLogs)
			newAdditionalLogs := make([]any, additionalLogsLen+len(*filterRequest.Logs))
			copy(newAdditionalLogs, a.AdditionalLogs)
			a.AdditionalLogs = newAdditionalLogs[:additionalLogsLen]

			for index := range *filterRequest.Logs {
				a.AdditionalLogs = append(a.AdditionalLogs, (*filterRequest.Logs)[index])
			}
		}

		if statusMessage := filterRequest.StatusMessage; *statusMessage != a.StatusMessage {
			a.StatusMessage = *statusMessage
		}

		for _, attributeName := range removeAttributes {
			delete(a.Attributes, attributeName)
		}

		if luaBackendResult != nil {
			// XXX: We currently only support changing attributes from the AuthState object.
			if (*luaBackendResult).Attributes != nil {
				for key, value := range (*luaBackendResult).Attributes {
					if keyName, assertOk := key.(string); assertOk {
						if _, okay := a.Attributes[keyName]; !okay {
							a.Attributes[keyName] = []any{value}
						}
					}
				}
			}
		}

		if filterResult {
			a.Authorized = false

			// Return the CommonRequest to the pool before returning
			lualib.PutCommonRequest(commonRequest)

			return definitions.AuthResultFail
		}

		// filters accepted → authorized
		a.Authorized = true

		a.UsedBackendIP = *filterRequest.UsedBackendAddress
		a.UsedBackendPort = *filterRequest.UsedBackendPort
	}

	// Return the CommonRequest to the pool
	lualib.PutCommonRequest(commonRequest)

	if passDBResult.Authenticated {
		return definitions.AuthResultOK
	}

	return definitions.AuthResultFail
}

// ListUserAccounts returns the list of all known users from the account databases.
func (a *AuthState) ListUserAccounts() (accountList AccountList) {
	var accounts []*AccountListMap

	// Pre-allocate the accounts slice to avoid continuous reallocation
	// This is a conservative estimate, we'll allocate based on the number of backends
	accountList = make(AccountList, 0, 100)

	a.Protocol.Set("account-provider")

	for _, backendType := range config.GetFile().GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			mgr := NewLDAPManager(backendType.GetName())
			accounts = append(accounts, &AccountListMap{
				definitions.BackendLDAP,
				mgr.AccountDB,
			})
		case definitions.BackendLua:
			mgr := NewLuaManager(backendType.GetName())
			accounts = append(accounts, &AccountListMap{
				definitions.BackendLua,
				mgr.AccountDB,
			})
		case definitions.BackendUnknown:
		case definitions.BackendCache:
		case definitions.BackendLocalCache:
		}
	}

	for _, accountDB := range accounts {
		result, err := accountDB.fn(a)

		util.DebugModule(definitions.DbgAuth, definitions.LogKeyGUID, a.GUID, "backendType", accountDB.backend.String(), "result", fmt.Sprintf("%v", result))

		if err == nil {
			accountList = append(accountList, result...)
		} else {
			var detailedError *errors.DetailedError
			if stderrors.As(err, &detailedError) {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, detailedError.Error(),
					definitions.LogKeyErrorDetails, detailedError.GetDetails())
			} else {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err)
			}
		}
	}

	return accountList
}

// String returns the string for a PassDBResult object.
func (p *PassDBResult) String() string {
	var result string

	value := reflect.ValueOf(*p)
	typeOfValue := value.Type()

	for index := range value.NumField() {
		result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
	}

	return result[1:]
}

// updateUserAccountInRedis returns the user account value from the user Redis hash. If none was found, a new entry in
// the hash table is created.
func (a *AuthState) updateUserAccountInRedis() (accountName string, err error) {
	var (
		assertOk bool
		accounts []string
		values   []any
	)

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserHashKey

	accountName = backend.GetUserAccountFromCache(a.HTTPClientContext, a.Username, *a.GUID)
	if accountName != "" {
		return
	}

	if a.AccountField != nil {
		if values, assertOk = a.Attributes[*a.AccountField]; !assertOk {
			return "", errors.ErrNoAccount
		}

		// Pre-allocate the accounts slice to avoid continuous reallocation
		accounts = make([]string, 0, len(values))
		for index := range values {
			accounts = append(accounts, values[index].(string))
		}

		sort.Sort(sort.StringSlice(accounts))

		accountName = strings.Join(accounts, ":")

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		err = rediscli.GetClient().GetWriteHandle().HSet(a.HTTPClientContext, key, a.Username, accountName).Err()
	}

	return
}

// HasJWTRole checks if the user has the specified role in their JWT token.
// It retrieves the JWT claims from the context and checks if the user has the required role.
// If JWT authentication is not enabled or no claims are found, it returns false.
func (a *AuthState) HasJWTRole(ctx *gin.Context, role string) bool {
	// Check if JWT auth is enabled
	if !config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
		return false
	}

	// Use the jwtutil package to check if the user has the required role
	return jwtutil.HasRole(ctx, role)
}

// SetOperationMode sets the operation mode of the AuthState object based on the "mode" query parameter from the provided gin context.
// It retrieves the GUID from the gin context and uses it for logging purposes.
// The operation mode can be "no-auth" or "list-accounts".
// If the mode is "no-auth", it sets the NoAuth field of the AuthState object to true.
// If the mode is "list-accounts", it sets the ListAccounts field of the AuthState object to true.
// The function "util.DebugModule" is used for logging debug messages with the appropriate module name and function name.
// Example usage of SetOperationMode:
//
//	a.setOperationMode(ctx)
//
//	func setupAuth(ctx *gin.Context, auth *AuthState) {
//	  //...
//	  auth.setOperationMode(ctx)
//	}
func (a *AuthState) SetOperationMode(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	// We reset flags, because they might have been cached in the in-memory cahce.
	a.NoAuth = false
	a.ListAccounts = false
	a.MonitoringFlags = []definitions.Monitoring{}

	switch ctx.Query("mode") {
	case "no-auth":
		util.DebugModule(definitions.DbgAuth, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "mode=no-auth")

		// Check if JWT is enabled and user has the required role
		if config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
			if a.HasJWTRole(ctx, "user_info") {
				a.NoAuth = true
			} else {
				level.Warn(log.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "JWT user does not have the 'user_info' role required for no-auth mode",
				)
			}
		} else {
			a.NoAuth = true
		}
	case "list-accounts":
		util.DebugModule(definitions.DbgAuth, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "mode=list-accounts")

		// Check if JWT is enabled and user has the required role
		if config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
			if a.HasJWTRole(ctx, "list_accounts") {
				a.ListAccounts = true
			} else {
				level.Warn(log.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "JWT user does not have the 'list_accounts' role required for list-accounts mode",
				)
			}
		} else {
			a.ListAccounts = true
		}
	}

	if ctx.Query("in-memory") == "0" {
		a.MonitoringFlags = append(a.MonitoringFlags, definitions.MonInMemory)
	}

	if ctx.Query("cache") == "0" {
		a.MonitoringFlags = append(a.MonitoringFlags, definitions.MonCache)
	}
}

// setupHeaderBasedAuth sets up the authentication based on the headers in the request.
// It takes the context and the authentication object as parameters.
// It retrieves the GUID value from the context using definitions.CtxGUIDKey and casts it to a string.
// It retrieves the "Auth-User" and "Auth-Pass" headers from the request and assigns them to the username and password fields of the authentication object.
// It sets the protocol field of the authentication object by calling the Set method on auth.Protocol with the value of the "Auth-Protocol" header.
// It parses the "Auth-Login-Attempt" header as an integer and assigns it to the loginAttempts variable.
// If there is an error parsing the header or the loginAttempts is negative, it sets loginAttempts to 0.
// It assigns the loginAttempts value to the loginAttempts field of the authentication object using an immediately invoked function expression (IIFE).
// It retrieves the "Auth-Method" header from the request and assigns it to the method variable.
// It checks the "mode" query parameter in the context.
// If it is set to "no-auth", it sets the NoAuth field of the authentication object to true.
// If it is set to "list-accounts", it sets the ListAccounts field of the authentication object to true.
// It calls the withClientInfo, withLocalInfo, withUserAgent, and withXSSL methods on the authentication object to set additional fields based on the context.
func setupHeaderBasedAuth(ctx *gin.Context, auth State) {
	// Nginx header, see: https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html#protocol
	auth.SetUsername(ctx.GetHeader(config.GetFile().GetUsername()))
	auth.SetPassword(ctx.GetHeader(config.GetFile().GetPassword()))

	encoded := ctx.GetHeader(config.GetFile().GetPasswordEncoded())
	if encoded == "1" {
		password := auth.GetPassword()

		padding := len(password) % 4
		if padding > 0 {
			password += string(bytes.Repeat([]byte("="), 4-padding))
		}

		if decodedPassword, err := base64.URLEncoding.DecodeString(password); err != nil {
			auth.SetPassword("")

			ctx.Error(errors.ErrPasswordEncoding)
		} else {
			auth.SetPassword(string(decodedPassword))
		}
	}

	auth.GetProtocol().Set(ctx.GetHeader(config.GetFile().GetProtocol()))
	auth.SetLoginAttempts(func() uint {
		loginAttempts, err := strconv.Atoi(ctx.GetHeader(config.GetFile().GetLoginAttempt()))
		if err != nil {
			return 0
		}

		if loginAttempts < 0 {
			loginAttempts = 0
		}

		return uint(loginAttempts)
	}())

	auth.SetMethod(ctx.GetHeader(config.GetFile().GetAuthMethod()))
	auth.WithClientInfo(ctx)
	auth.WithLocalInfo(ctx)
	auth.WithUserAgent(ctx)
	auth.WithXSSL(ctx)
}

// processApplicationXWWWFormUrlencoded processes the application/x-www-form-urlencoded data from the request context and updates the AuthState object.
// It extracts the values for the fields method, realm, user_agent, username, password, protocol, port, tls, and security from the request form.
// If the realm field is not empty, it appends "@" + realm to the username field in the AuthState object.
// It sets the method, user_agent, username, usernameOrig, password, protocol, xLocalIP, xPort, xSSL, and xSSLProtocol fields in the AuthState object.
func processApplicationXWWWFormUrlencoded(ctx *gin.Context, auth State) {
	realm := ctx.PostForm("realm")
	if len(realm) > 0 {
		username := auth.GetUsername()
		username += "@" + realm

		auth.SetUsername(username)
	}

	auth.SetMethod(ctx.PostForm("method"))
	auth.SetUserAgent(ctx.PostForm("user_agent"))
	auth.SetUsername(ctx.PostForm("username"))
	auth.SetPassword(ctx.PostForm("password"))
	auth.SetProtocol(config.NewProtocol(ctx.PostForm("protocol")))
	auth.SetLocalIP(definitions.Localhost4)
	auth.SetLocalPort(ctx.PostForm("port"))
	auth.SetSSL(ctx.PostForm("tls"))
	auth.SetSSLProtocol(ctx.PostForm("security"))
}

// processApplicationJSON takes a gin Context and an AuthState object.
// It attempts to bind the JSON payload from the Context to a JSONRequest object.
// If there is an error in the binding process, it sets the error type to "gin.ErrorTypeBind" and returns.
// Otherwise, it calls the setAuthenticationFields function with the AuthState object and the JSONRequest object,
// and sets additional fields in the AuthState object using the XSSL method.
func processApplicationJSON(ctx *gin.Context, auth State) {
	var jsonRequest authdto.Request

	if err := ctx.ShouldBindJSON(&jsonRequest); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	setAuthenticationFields(auth, &jsonRequest)

	// If no user_agent provided via JSON, fallback to HTTP header
	if jsonRequest.UserAgent == "" {
		auth.WithUserAgent(ctx)
	}

	// Apply DNS resolution logic after setting client IP
	if authState, ok := auth.(*AuthState); ok {
		authState.postResolvDNS(ctx)
	}
}

// setAuthenticationFields updates the provided authentication state with data from the request, if available.
func setAuthenticationFields(auth State, request *authdto.Request) {
	if request.Method != "" {
		auth.SetMethod(request.Method)
	}

	if request.UserAgent != "" {
		auth.SetUserAgent(request.UserAgent)
	}

	if request.ClientID != "" {
		auth.SetClientID(request.ClientID)
	}

	if request.Username != "" {
		auth.SetUsername(request.Username)
	}

	if request.Password != "" {
		auth.SetPassword(request.Password)
	}

	if request.ClientIP != "" {
		auth.SetClientIP(request.ClientIP)
	}

	if request.ClientPort != "" {
		auth.SetClientPort(request.ClientPort)
	}

	if request.ClientHostname != "" {
		auth.SetClientHost(request.ClientHostname)
	}

	if request.LocalIP != "" {
		auth.SetLocalIP(request.LocalIP)
	}

	if request.LocalPort != "" {
		auth.SetLocalPort(request.LocalPort)
	}

	if request.Protocol != "" {
		auth.SetProtocol(config.NewProtocol(request.Protocol))
	}

	if request.XSSL != "" {
		auth.SetSSL(request.XSSL)
	}

	if request.XSSLSessionID != "" {
		auth.SetSSLSessionID(request.XSSLSessionID)
	}

	if request.XSSLClientVerify != "" {
		auth.SetSSLClientVerify(request.XSSLClientVerify)
	}

	if request.XSSLClientDN != "" {
		auth.SetSSLClientDN(request.XSSLClientDN)
	}

	if request.XSSLClientCN != "" {
		auth.SetSSLClientCN(request.XSSLClientCN)
	}

	if request.XSSLIssuer != "" {
		auth.SetSSLIssuer(request.XSSLIssuer)
	}

	if request.XSSLClientNotBefore != "" {
		auth.SetSSLClientNotBefore(request.XSSLClientNotBefore)
	}

	if request.XSSLClientNotAfter != "" {
		auth.SetSSLClientNotAfter(request.XSSLClientNotAfter)
	}

	if request.XSSLSubjectDN != "" {
		auth.SetSSLSubjectDN(request.XSSLSubjectDN)
	}

	if request.XSSLIssuerDN != "" {
		auth.SetSSLIssuerDN(request.XSSLIssuerDN)
	}

	if request.XSSLClientSubjectDN != "" {
		auth.SetSSLClientSubjectDN(request.XSSLClientSubjectDN)
	}

	if request.XSSLClientIssuerDN != "" {
		auth.SetSSLClientIssuerDN(request.XSSLClientIssuerDN)
	}

	if request.XSSLProtocol != "" {
		auth.SetSSLProtocol(request.XSSLProtocol)
	}

	if request.XSSLCipher != "" {
		auth.SetSSLCipher(request.XSSLCipher)
	}

	if request.SSLSerial != "" {
		auth.SetSSLSerial(request.SSLSerial)
	}

	if request.SSLFingerprint != "" {
		auth.SetSSLFingerprint(request.SSLFingerprint)
	}

	if request.OIDCCID != "" {
		auth.SetOIDCCID(request.OIDCCID)
	}
}

// setupBodyBasedAuth takes a Context and an AuthState object as input.
// It retrieves the "Content-Type" header from the Context.
// If the "Content-Type" starts with "application/x-www-form-urlencoded",
// it calls the processApplicationXWWWFormUrlencoded function passing the Context and AuthState object.
// If the "Content-Type" is "application/json",
// it calls the processApplicationJSON function passing the Context and AuthState object.
// If neither of the above conditions match, it sets the error associated with unsupported media type
// and sets the error type to gin.ErrorTypeBind on the Context.
func setupBodyBasedAuth(ctx *gin.Context, auth State) {
	if ctx.Request.Method == "POST" {
		contentType := ctx.GetHeader("Content-Type")

		if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
			processApplicationXWWWFormUrlencoded(ctx, auth)
		} else if contentType == "application/json" {
			processApplicationJSON(ctx, auth)
		} else {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Unsupported media type"})
			ctx.Error(errors.ErrUnsupportedMediaType).SetType(gin.ErrorTypeBind)
		}
	}
}

// setupHTTPBasicAuth sets up basic authentication for HTTP requests.
// It takes in a gin.Context object and a pointer to an AuthState object.
// It calls the withClientInfo, withLocalInfo, withUserAgent, and withXSSL methods of the AuthState object to set client, local, user-agent, and X-SSL information, respectively
func setupHTTPBasicAuth(ctx *gin.Context, auth State) {
	// NOTE: We must get username and password later!
	auth.WithClientInfo(ctx)
	auth.WithLocalInfo(ctx)
	auth.WithUserAgent(ctx)
	auth.WithXSSL(ctx)
}

// InitMethodAndUserAgent initializes the authentication method and user agent fields if they are not already set.
func (a *AuthState) InitMethodAndUserAgent() State {
	if a.Method == nil {
		method := ""
		a.Method = &method
	}

	if a.UserAgent == nil {
		userAgent := ""
		a.UserAgent = &userAgent
	}

	return a
}

// setupAuth sets up the authentication based on the service parameter in the gin context.
// It takes the gin context and an AuthState struct as input.
//
// If the service parameter is "nginx" or "header", it calls the setupHeaderBasedAuth function.
// If the service parameter is "saslauthd", it calls the setupBodyBasedAuth function.
// If the service parameter is "basicauth", it calls the setupHTTPBasicAuth function.
//
// After setting up the authentication, it calls the withDefaults method on the AuthState struct.
//
// Example usage:
//
//	auth := &AuthState{}
//	ctx := gin.Context{}
//	ctx.SetParam("service", "nginx")
//	setupAuth(&ctx, auth)
func setupAuth(ctx *gin.Context, auth State) {
	auth.SetProtocol(&config.Protocol{})

	svc := ctx.GetString(definitions.CtxServiceKey)
	switch svc {
	case definitions.ServNginx, definitions.ServHeader:
		setupHeaderBasedAuth(ctx, auth)
	case definitions.ServSaslauthd, definitions.ServJSON:
		setupBodyBasedAuth(ctx, auth)
	case definitions.ServBasic:
		setupHTTPBasicAuth(ctx, auth)
	}

	if ctx.Query("mode") != "list-accounts" && svc != definitions.ServBasic {
		if !util.ValidateUsername(auth.GetUsername()) {
			auth.SetUsername("")
			ctx.Error(errors.ErrInvalidUsername)
		}
	}

	auth.InitMethodAndUserAgent()
	auth.WithDefaults(ctx)
	auth.SetOperationMode(ctx)
}

// NewAuthStateWithSetup creates a new instance of the AuthState struct.
// It takes a gin.Context object as a parameter and sets it as the HTTPClientContext field of the AuthState struct.
// If an error occurs while setting the StatusCode field using the SetStatusCodes function, it logs the error and returns nil.
// Otherwise, it calls the setupAuth function to setup the AuthState struct based on the service parameter from the gin.Context object.
// Finally, it returns the created AuthState struct.
func NewAuthStateWithSetup(ctx *gin.Context) State {
	auth := NewAuthStateFromContext(ctx)

	svc := ctx.GetString(definitions.CtxServiceKey)
	if svc == "" {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return nil
	}

	auth.SetStatusCodes(svc)
	setupAuth(ctx, auth)

	// prominent early log: show all incoming data including session GUID
	if a, ok := auth.(*AuthState); ok {
		logProcessingRequest(ctx, a)
	}

	if ctx.Errors.Last() != nil {
		return nil
	}

	return auth
}

// NewAuthStateFromContext initializes and returns an AuthState using the provided gin.Context.
// It gets an AuthState from the pool, sets the context to a copied HTTPClientContext and assigns the current time to the StartTime field.
func NewAuthStateFromContext(ctx *gin.Context) State {
	auth := authStatePool.Get().(*AuthState)
	auth.StartTime = time.Now()
	auth.HTTPClientContext = ctx.Copy()

	return auth
}

// PutAuthState returns an AuthState to the pool after resetting it
func PutAuthState(auth State) {
	if auth == nil {
		return
	}

	a, ok := auth.(*AuthState)
	if !ok {
		return
	}

	a.reset()
	authStatePool.Put(a)
}

// WithDefaults sets default values for the AuthState structure including the GUID session value.
func (a *AuthState) WithDefaults(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	guidStr := ctx.GetString(definitions.CtxGUIDKey)

	a.GUID = &guidStr
	a.UsedPassDBBackend = definitions.BackendUnknown
	a.PasswordsAccountSeen = 0
	a.Service = ctx.GetString(definitions.CtxServiceKey)
	a.Context = ctx.MustGet(definitions.CtxDataExchangeKey).(*lualib.Context)

	// Default flags
	a.Authenticated = false // not decided yet
	a.Authorized = true     // default allow unless a filter rejects

	if a.Service == definitions.ServBasic {
		a.Protocol.Set(definitions.ProtoHTTP)
	}

	if a.Protocol.Get() == "" {
		a.Protocol.Set(definitions.ProtoDefault)
	}

	return a
}

// WithLocalInfo adds the local IP and -port headers to the AuthState structure.
func (a *AuthState) WithLocalInfo(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	a.XLocalIP = ctx.GetHeader(config.GetFile().GetLocalIP())
	a.XPort = ctx.GetHeader(config.GetFile().GetLocalPort())

	return a
}

// postResolvDNS resolves the client IP to a host name if DNS client IP resolution is enabled in the configuration.
func (a *AuthState) postResolvDNS(ctx *gin.Context) {
	if config.GetFile().GetServer().GetDNS().GetResolveClientIP() {
		stopTimer := stats.PrometheusTimer(definitions.PromDNS, definitions.DNSResolvePTR)

		a.ClientHost = util.ResolveIPAddress(ctx, a.ClientIP)

		if stopTimer != nil {
			stopTimer()
		}
	}
}

// WithClientInfo adds the client IP, -port and -ID headers to the AuthState structure.
func (a *AuthState) WithClientInfo(ctx *gin.Context) State {
	var err error

	if a == nil {
		return nil
	}

	a.OIDCCID = ctx.GetHeader(config.GetFile().GetOIDCCID())
	a.ClientIP = ctx.GetHeader(config.GetFile().GetClientIP())
	a.XClientPort = ctx.GetHeader(config.GetFile().GetClientPort())
	a.XClientID = ctx.GetHeader(config.GetFile().GetClientID())
	a.ClientHost = ctx.GetHeader(config.GetFile().GetClientHost())

	if a.ClientIP == "" {
		// This might be valid if HAproxy v2 support is enabled
		if config.GetFile().GetServer().IsHAproxyProtocolEnabled() {
			a.ClientIP, a.XClientPort, err = net.SplitHostPort(ctx.Request.RemoteAddr)
			if err != nil {
				level.Error(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, err.Error())
			}

			util.ProcessXForwardedFor(ctx, &a.ClientIP, &a.XClientPort, &a.XSSL)
		}
	}

	a.postResolvDNS(ctx)

	return a
}

// WithUserAgent adds the User-Agent header to the AuthState structure.
func (a *AuthState) WithUserAgent(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	userAgent := ctx.Request.UserAgent()

	a.UserAgent = &userAgent

	return a
}

// WithXSSL adds HAProxy header processing to the AuthState structure.
func (a *AuthState) WithXSSL(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	a.XSSL = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSL())
	a.XSSLSessionID = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLSessionID())
	a.XSSLClientVerify = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLVerify())
	a.XSSLClientDN = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLSubject())
	a.XSSLClientCN = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLClientCN())
	a.XSSLIssuer = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLIssuer())
	a.XSSLClientNotBefore = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLClientNotBefore())
	a.XSSLClientNotAfter = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLClientNotAfter())
	a.XSSLSubjectDN = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLSubjectDN())
	a.XSSLIssuerDN = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLIssuerDN())
	a.XSSLClientSubjectDN = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLClientSubjectDN())
	a.XSSLClientIssuerDN = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLClientIssuerDN())
	a.XSSLCipher = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLCipher())
	a.XSSLProtocol = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLProtocol())
	a.SSLSerial = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLSerial())
	a.SSLFingerprint = ctx.GetHeader(config.GetFile().GetServer().GetDefaultHTTPRequestHeader().GetSSLFingerprint())

	return a
}

// generateLocalCacheKey generates a string key used for caching the AuthState object in the local cache.
// The key is constructed by concatenating the Username, Password and  Service values using a null character ('\0')
// as a separator.
func (a *AuthState) generateLocalCacheKey() string {
	return fmt.Sprintf("%s\000%s\000%s\000%s\000%s",
		a.Username,
		a.Password,
		a.Service,
		a.Protocol.Get(),
		func() string {
			if a.ClientIP == "" {
				return "0.0.0.0"
			}

			return a.ClientIP
		}(),
	)
}

// generateSingleflightKey builds a strict deduplication key for backchannel singleflight.
// Fields: service, protocol, username, account, client_ip, local_ip, local_port, ssl_flag, [oidcCID], pw_short
func (a *AuthState) generateSingleflightKey() string {
	// Try to enrich account if present in cache already
	account := a.refreshUserAccount()
	if account == "" {
		account = a.GetAccount()
	}

	clientIP := a.ClientIP
	if clientIP == "" {
		clientIP = "0.0.0.0"
	}

	sslFlag := "0"
	if a.XSSL != "" || a.XSSLProtocol != "" {
		sslFlag = "1"
	}

	// Short password hash (same function as for positive password cache)
	pwShort := util.GetHash(util.PreparePassword(a.Password))

	sep := "\x00"
	base := a.Service + sep + a.Protocol.Get() + sep + a.Username + sep + account + sep + clientIP + sep + a.XLocalIP + sep + a.XPort + sep + sslFlag

	if a.OIDCCID != "" {
		base = base + sep + a.OIDCCID
	}

	// Include password short hash last to avoid cross-password dedup
	return base + sep + pwShort
}

// GetFromLocalCache retrieves the AuthState object from the local cache using the generateLocalCacheKey() as the key.
// If the object is found in the cache, it updates the fields of the current AuthState object with the cached values.
// It also sets the a.GUID field with the original value to avoid losing the GUID from the previous object.
// If the a.HTTPClientContext field is not nil, it sets it to nil and restores it after updating the AuthState object.
// It sets the a.UsedPassDBBackend field to BackendLocalCache to indicate that the cache was used.
// Finally, it sets the "local_cache_auth" key to true in the gin.Context using ctx.Set() and returns true if the object is found in the cache; otherwise, it returns false.
func (a *AuthState) GetFromLocalCache(ctx *gin.Context) bool {
	if a.HaveMonitoringFlag(definitions.MonInMemory) {
		return false
	}

	if value, found := localcache.LocalCache.Get(a.generateLocalCacheKey()); found {
		passDBResult := value.(*PassDBResult)

		updateAuthentication(ctx, a, passDBResult, &PassDBMap{
			backend: definitions.BackendLocalCache,
			fn:      nil,
		})

		// Set AdditionalFeatures in the gin.Context if they exist in the cached result
		if passDBResult.AdditionalFeatures != nil && len(passDBResult.AdditionalFeatures) > 0 {
			ctx.Set(definitions.CtxAdditionalFeaturesKey, passDBResult.AdditionalFeatures)
		}

		ctx.Set(definitions.CtxLocalCacheAuthKey, true)

		return found
	} else {
		return false
	}
}

// PreproccessAuthRequest preprocesses the authentication request by checking if the request is already in the local cache.
// If not found in the cache, it checks if the request is a brute force attack and updates the brute force counter.
// It then performs a post Lua action and triggers a failed authentication response.
// If a brute force attack is detected, it returns true, otherwise false.
func (a *AuthState) PreproccessAuthRequest(ctx *gin.Context) (reject bool) {
	if found := a.GetFromLocalCache(ctx); !found {
		stats.GetMetrics().GetCacheMisses().Inc()

		if a.CheckBruteForce(ctx) {
			a.UpdateBruteForceBucketsCounter(ctx)
			result := GetPassDBResultFromPool()
			a.PostLuaAction(result)
			PutPassDBResultToPool(result)
			a.AuthFail(ctx)

			return true
		}
	} else {
		stats.GetMetrics().GetCacheHits().Inc()
	}

	return false
}
