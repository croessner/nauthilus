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
	"encoding/base64"
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
	"github.com/croessner/nauthilus/server/bruteforce/ml"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/jwtutil"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/webauthn"
	openapi "github.com/ory/hydra-client-go/v2"
	"github.com/spf13/viper"
)

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

// JSONRequest is a data structure containing the details of a client's request in JSON format.
type JSONRequest struct {
	// Username is the identifier of the client/user sending the request.
	Username string `json:"username" binding:"required"`

	// Password is the authentication credential of the client/user sending the request.
	Password string `json:"password,omitempty"`

	// ClientIP is the IP address of the client/user making the request.
	ClientIP string `json:"client_ip,omitempty"`

	// ClientPort is the port number from which the client/user is sending the request.
	ClientPort string `json:"client_port,omitempty"`

	// ClientHostname is the hostname of the client which is sending the request.
	ClientHostname string `json:"client_hostname,omitempty"`

	// ClientID is the unique identifier of the client/user, usually assigned by the application.
	ClientID string `json:"client_id,omitempty"`

	// LocalIP is the IP address of the server or endpoint receiving the request.
	LocalIP string `json:"local_ip,omitempty"`

	// LocalPort is the port number of the server or endpoint receiving the request.
	LocalPort string `json:"local_port,omitempty"`

	// Service is the specific service that the client/user is trying to access with the request.
	Service string `json:"service"`

	// Method is the HTTP method used in the request (i.e., PLAIN, LOGIN, etc.)
	Method string `json:"method,omitempty"`

	// AuthLoginAttempt is a flag indicating if the request is an attempt to authenticate (login). This is expressed as an unsigned integer where applicable flags/types are usually interpreted from the application's specific logic.
	AuthLoginAttempt uint `json:"auth_login_attempt,omitempty"`

	XSSL                string `json:"ssl,omitempty"`
	XSSLSessionID       string `json:"ssl_session_id,omitempty"`
	XSSLClientVerify    string `json:"ssl_client_verify,omitempty"`
	XSSLClientDN        string `json:"ssl_client_dn,omitempty"`
	XSSLClientCN        string `json:"ssl_client_cn,omitempty"`
	XSSLIssuer          string `json:"ssl_issuer,omitempty"`
	XSSLClientNotBefore string `json:"ssl_client_notbefore,omitempty"`
	XSSLClientNotAfter  string `json:"ssl_client_notafter,omitempty"`
	XSSLSubjectDN       string `json:"ssl_subject_dn,omitempty"`
	XSSLIssuerDN        string `json:"ssl_issuer_dn,omitempty"`
	XSSLClientSubjectDN string `json:"ssl_client_subject_dn,omitempty"`
	XSSLClientIssuerDN  string `json:"ssl_client_issuer_dn,omitempty"`
	XSSLProtocol        string `json:"ssl_protocol,omitempty"`
	XSSLCipher          string `json:"ssl_cipher,omitempty"`

	// SSLSerial represents the serial number of an SSL certificate as a string.
	SSLSerial string `json:"ssl_serial,omitempty"`

	// SSLFingerprint represents the fingerprint of an SSL certificate.
	SSLFingerprint string `json:"ssl_fingerprint,omitempty"`

	// OIDCCID represents the OIDC Client ID used for authentication.
	OIDCCID string `json:"oidc_cid,omitempty"`
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

	// GetOauth2SubjectAndClaims retrieves the OAuth2 subject and claims for a given OAuth2 client.
	// Returns the subject as a string and the claims as a map.
	GetOauth2SubjectAndClaims(oauth2Client openapi.OAuth2Client) (string, map[string]any)

	// PreproccessAuthRequest preprocesses the authentication request and determines if it should be rejected.
	PreproccessAuthRequest(ctx *gin.Context) bool

	// UpdateBruteForceBucketsCounter increments counters to track brute-force attack attempts for the associated client IP.
	UpdateBruteForceBucketsCounter()

	// HandleAuthentication processes the primary authentication logic based on the request context and service parameters.
	HandleAuthentication(ctx *gin.Context)

	// HandlePassword processes the password-based authentication for a user and returns the authentication result.
	HandlePassword(ctx *gin.Context) definitions.AuthResult

	// HandleSASLAuthdAuthentication processes authentication requests using the SASL auth daemon protocol.
	HandleSASLAuthdAuthentication(ctx *gin.Context)

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
type AddTOTPSecretFunc func(auth *AuthState, totp *TOTPSecret) (err error)

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
		definitions.LogKeyLatency, fmt.Sprintf("%v", time.Now().Sub(a.StartTime)),
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

		// Record successful login for ML training if ML is enabled
		if config.GetEnvironment().GetExperimentalML() {
			mlBM := ml.NewMLBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP).
				WithUsername(a.Username).WithPassword(a.Password)

			// Set NoAuth flag
			if mlManager, ok := mlBM.(*ml.MLBucketManager); ok {
				mlManager.SetNoAuth(a.NoAuth)
			}

			// Set the protocol if available
			if a.Protocol != nil && a.Protocol.Get() != "" {
				mlBM = mlBM.WithProtocol(a.Protocol.Get())
			}

			// Set the OIDC Client ID if available
			if a.OIDCCID != "" {
				mlBM = mlBM.WithOIDCCID(a.OIDCCID)
			}

			// Check if additional features are available from the Context
			if a.Context != nil {
				if features := lualib.GetAdditionalFeatures(a.HTTPClientContext); features != nil {
					mlBM = mlBM.WithAdditionalFeatures(features)
				}
			}

			if mlManager, ok := mlBM.(*ml.MLBucketManager); ok {
				// Create a new method in MLBucketManager to record successful logins
				mlManager.RecordSuccessfulLogin()
			}
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
	level.Info(log.Logger).Log(auth.LogLineTemplate(func() string {
		if !auth.NoAuth {
			return "ok"
		}

		return ""
	}(), ctx.Request.URL.Path)...)
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

		if a.PasswordHistory != nil {
			ctx.JSON(a.StatusCodeFail, *a.PasswordHistory)
		} else {
			ctx.JSON(a.StatusCodeFail, nil)
		}
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
	level.Info(log.Logger).Log(a.LogLineTemplate("fail", ctx.Request.URL.Path)...)

	stats.GetMetrics().GetRejectedProtocols().WithLabelValues(a.Protocol.Get()).Inc()
	stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelFailure).Inc()
}

// AuthFail handles the failure of authentication.
// It increases the login attempts, sets failure headers on the context, and performs login attempt processing.
func (a *AuthState) AuthFail(ctx *gin.Context) {
	setHeaderHeaders(ctx, a)

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

// AuthTempFail sets the necessary headers and status message for temporary authentication failure.
// If the service is "user", it also sets headers specific to user information.
// After setting the headers, it returns the appropriate response based on the service.
// If the service is not "user", it returns an internal server error response with the status message.
// If the service is "user", it calls the sendAuthResponse method to set additional headers and returns.
//
// Parameters:
// - ctx: The gin context object.
// - reason: The reason for the authentication failure.
//
// Usage example:
//
//	  func (a *AuthState) handleAuthentication(ctx *gin.Context) {
//	    ...
//	    a.authTempFail(ctx, global.TempFailDefault)
//	    ...
//	  }
//	  func (a *AuthState) handleSASLAuthdAuthentication(ctx *gin.Context) {
//		   ...
//	    a.authTempFail(ctx, global.TempFailDefault)
//	    ...
//	  }
//
// Declaration and usage of AuthTempFail:
//
//	A: func (a *AuthState) authTempFail(ctx *gin.Context, reason string) {
//	  ...
//	}
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

	level.Info(log.Logger).Log(a.LogLineTemplate("tempfail", ctx.Request.URL.Path)...)
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
func (a *AuthState) verifyPassword(passDBs []*PassDBMap) (*PassDBResult, error) {
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
			err = processPassDBResult(passDBResult, a, passDB)
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
func processPassDBResult(passDBResult *PassDBResult, auth *AuthState, passDB *PassDBMap) error {
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

	updateAuthentication(auth, passDBResult, passDB)

	return nil
}

// updateAuthentication updates the fields of the AuthState struct with the values from the PassDBResult struct.
// It checks if each field in passDBResult is not nil and if it is not nil, it updates the corresponding field in the AuthState struct.
// It also updates the SourcePassDBBackend and UsedPassDBBackend fields of the AuthState struct with the values from passDBResult.Backend and passDB.backend respectively.
// It returns the updated PassDBResult struct.
func updateAuthentication(auth *AuthState, passDBResult *PassDBResult, passDB *PassDBMap) {
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
			auth.HTTPClientContext.Set(definitions.CtxAdditionalFeaturesKey, passDBResult.AdditionalFeatures)
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
) {
	stopTimer := stats.PrometheusTimer(definitions.PromPostAction, "lua_post_action_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	finished := make(chan action.Done)

	// Get a CommonRequest from the pool
	commonRequest := lualib.GetCommonRequest()

	// Set the fields
	commonRequest.Debug = config.GetFile().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	commonRequest.Repeating = false
	commonRequest.UserFound = userFound
	commonRequest.Authenticated = authenticated
	commonRequest.NoAuth = noAuth
	commonRequest.BruteForceCounter = 0
	commonRequest.Service = service
	commonRequest.Session = guid
	commonRequest.ClientIP = clientIP
	commonRequest.ClientPort = clientPort
	commonRequest.ClientNet = "" // unavailable
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

	useCache, backendPos, passDBs := a.handleBackendTypes()

	// Further control flow based on whether cache is used and authentication status
	authResult = a.authenticateUser(ctx, useCache, backendPos, passDBs)

	return authResult
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
func (a *AuthState) processVerifyPassword(passDBs []*PassDBMap) (*PassDBResult, error) {
	passDBResult, err := a.verifyPassword(passDBs)
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
			if config.GetEnvironment().GetExperimentalML() {
				bm = ml.NewMLBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP).
					WithUsername(a.Username).
					WithPassword(a.Password).
					WithAccountName(accountName)

				// Set NoAuth flag
				if mlManager, ok := bm.(*ml.MLBucketManager); ok {
					mlManager.SetNoAuth(a.NoAuth)
				}

				// Set the protocol if available
				if a.Protocol != nil && a.Protocol.Get() != "" {
					bm = bm.WithProtocol(a.Protocol.Get())
				}

				// Set the OIDC Client ID if available
				if a.OIDCCID != "" {
					bm = bm.WithOIDCCID(a.OIDCCID)
				}
			} else {
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
func (a *AuthState) processCacheUserLoginFail(accountName string) {
	var bm bruteforce.BucketManager

	util.DebugModule(
		definitions.DbgAuth,
		definitions.LogKeyGUID, a.GUID,
		"account", accountName,
		"authenticated", false,
		definitions.LogKeyMsg, "Calling saveFailedPasswordCounterInRedis()",
	)

	// Increase counters
	if config.GetEnvironment().GetExperimentalML() {
		bm = ml.NewMLBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP).
			WithUsername(a.Username).
			WithPassword(a.Password).
			WithAccountName(accountName)

		// Set NoAuth flag
		if mlManager, ok := bm.(*ml.MLBucketManager); ok {
			mlManager.SetNoAuth(a.NoAuth)
		}

		// Set the protocol if available
		if a.Protocol != nil && a.Protocol.Get() != "" {
			bm = bm.WithProtocol(a.Protocol.Get())
		}

		// Set the OIDC Client ID if available
		if a.OIDCCID != "" {
			bm = bm.WithOIDCCID(a.OIDCCID)
		}
	} else {
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
	}

	bm.SaveFailedPasswordCounterInRedis()
}

// processCache updates the relevant user cache entries based on authentication results from password databases.
func (a *AuthState) processCache(authenticated bool, accountName string, useCache bool, backendPos map[definitions.Backend]int) error {
	var bm bruteforce.BucketManager

	if !a.NoAuth && useCache && a.isCacheInCorrectPosition(backendPos) {
		if authenticated {
			err := a.processCacheUserLoginOk(accountName)
			if err != nil {
				return err
			}
		} else {
			a.processCacheUserLoginFail(accountName)
		}

		if config.GetEnvironment().GetExperimentalML() {
			bm = ml.NewMLBucketManager(a.HTTPClientContext, *a.GUID, a.ClientIP).
				WithUsername(a.Username).
				WithPassword(a.Password).
				WithAccountName(accountName)

			// Set NoAuth flag
			if mlManager, ok := bm.(*ml.MLBucketManager); ok {
				mlManager.SetNoAuth(a.NoAuth)
			}

			// Set the protocol if available
			if a.Protocol != nil && a.Protocol.Get() != "" {
				bm = bm.WithProtocol(a.Protocol.Get())
			}

			// Set the OIDC Client ID if available
			if a.OIDCCID != "" {
				bm = bm.WithOIDCCID(a.OIDCCID)
			}
		} else {
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

	if passDBResult, err = a.processVerifyPassword(passDBs); err != nil {
		return definitions.AuthResultTempFail
	}

	if accountName, err = a.processUserFound(passDBResult); err != nil {
		return definitions.AuthResultTempFail
	}

	if err = a.processCache(passDBResult.Authenticated, accountName, useCache, backendPos); err != nil {
		return definitions.AuthResultTempFail
	}

	if passDBResult.Authenticated {
		if !(a.HaveMonitoringFlag(definitions.MonInMemory) || a.IsMasterUser()) {
			// Get AdditionalFeatures from the gin.Context and add them to the PassDBResult before caching
			if a.HTTPClientContext != nil {
				if features := lualib.GetAdditionalFeatures(a.HTTPClientContext); features != nil {
					passDBResult.AdditionalFeatures = features
				}
			}

			localcache.LocalCache.Set(a.generateLocalChacheKey(), passDBResult, config.GetEnvironment().GetLocalCacheAuthTTL())
		}

		authResult = definitions.AuthResultOK
	} else {
		a.UpdateBruteForceBucketsCounter()

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

			return definitions.AuthResultTempFail
		}
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
			// Return the CommonRequest to the pool before returning
			lualib.PutCommonRequest(commonRequest)

			return definitions.AuthResultFail
		}

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
			if !config.GetFile().LDAPHavePoolOnly(backendType.GetName()) {
				mgr := NewLDAPManager(backendType.GetName())
				accounts = append(accounts, &AccountListMap{
					definitions.BackendLDAP,
					mgr.AccountDB,
				})
			}
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
	var jsonRequest *JSONRequest

	if err := ctx.ShouldBindJSON(&jsonRequest); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	setAuthenticationFields(auth, jsonRequest)

	// Apply DNS resolution logic after setting client IP
	if authState, ok := auth.(*AuthState); ok {
		authState.postResolvDNS(ctx)
	}
}

// setAuthenticationFields populates the fields of the AuthState struct with values from the JSONRequest.
// It takes a pointer to the AuthState struct and a pointer to the JSONRequest struct as input.
// It sets the values of the Method, UserAgent, Username, Password, ClientIP, XClientPort,
// ClientHost, XLocalIP, XPort, and Service fields of the AuthState struct with the corresponding values
// from the JSONRequest struct.
// It then returns the pointer to the modified AuthState struct.
//
// Example usage:
// auth := &AuthState{}
//
//		request := &JSONRequest{
//		    Method:          "POST",
//		    ClientID:        "client123",
//		    Username:        "john",
//		    Password:        "password",
//		    ClientIP:        "192.168.1.100",
//		    ClientPort:      "8080",
//		    ClientHostname:  "example.com",
//		    LocalIP:         "127.0.0.1",
//		    LocalPort:       "3000",
//		    Service:         "auth",
//		    AuthLoginAttempt: 1,
//	     ...
//		}
//
// setAuthenticationFields(auth, request)
// // After the function call, the fields of auth would be populated with the values from request
func setAuthenticationFields(auth State, request *JSONRequest) {
	auth.SetMethod(request.Method)
	auth.SetUserAgent(request.ClientID)
	auth.SetUsername(request.Username)
	auth.SetPassword(request.Password)
	auth.SetClientIP(request.ClientIP)
	auth.SetClientPort(request.ClientPort)
	auth.SetClientHost(request.ClientHostname)
	auth.SetLocalIP(request.LocalIP)
	auth.SetLocalPort(request.LocalPort)
	auth.SetProtocol(config.NewProtocol(request.Service))
	auth.SetSSL(request.XSSL)
	auth.SetSSLSessionID(request.XSSLSessionID)
	auth.SetSSLClientVerify(request.XSSLClientVerify)
	auth.SetSSLClientDN(request.XSSLClientDN)
	auth.SetSSLClientCN(request.XSSLClientCN)
	auth.SetSSLIssuer(request.XSSLIssuer)
	auth.SetSSLClientNotBefore(request.XSSLClientNotBefore)
	auth.SetSSLClientNotAfter(request.XSSLClientNotAfter)
	auth.SetSSLSubjectDN(request.XSSLSubjectDN)
	auth.SetSSLIssuerDN(request.XSSLIssuerDN)
	auth.SetSSLClientSubjectDN(request.XSSLClientSubjectDN)
	auth.SetSSLClientIssuerDN(request.XSSLIssuerDN)
	auth.SetSSLProtocol(request.XSSLProtocol)
	auth.SetSSLCipher(request.XSSLCipher)
	auth.SetSSLSerial(request.SSLSerial)
	auth.SetSSLFingerprint(request.SSLFingerprint)
	auth.SetOIDCCID(request.OIDCCID)
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

	switch ctx.Param("service") {
	case definitions.ServNginx, definitions.ServHeader:
		setupHeaderBasedAuth(ctx, auth)
	case definitions.ServSaslauthd, definitions.ServJSON:
		setupBodyBasedAuth(ctx, auth)
	case definitions.ServBasic:
		setupHTTPBasicAuth(ctx, auth)
	}

	if ctx.Query("mode") != "list-accounts" && ctx.Param("service") != definitions.ServBasic {
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

	auth.SetStatusCodes(ctx.Param("service"))
	setupAuth(ctx, auth)

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
	a.Service = ctx.Param("service")
	a.Context = ctx.MustGet(definitions.CtxDataExchangeKey).(*lualib.Context)

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

// processClaim processes a claim and updates the claims map with the claimName and claimValue.
// If the claimValue is not empty and found in the Attributes map of the AuthState object,
// the claimValue is set in the claims map with the claimName as key.
// Otherwise, a warning is logged.
//
// Parameters:
// - claimName: The name of the claim to process.
// - claimValue: The value of the claim to process.
// - claims: The map to update with the processed claim.
func (a *AuthState) processClaim(claimName string, claimValue string, claims map[string]any) {
	if claimValue != "" {
		if value, found := a.Attributes[claimValue]; found {
			if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
				claims[claimName] = arg

				return
			}
		}

		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, a.GUID,
			definitions.LogKeyMsg, fmt.Sprintf("Claim '%s' malformed or not returned from database", claimName),
		)
	}
}

// Custom logic to apply string claims
func applyClaim(claimKey string, attributeKey string, auth *AuthState, claims map[string]any, claimHandlers []ClaimHandler) {
	var success bool

	if attributeValue, found := auth.Attributes[attributeKey]; found {
		for _, handler := range claimHandlers {
			if t := reflect.TypeOf(attributeValue).Kind(); t == handler.Type {
				success = handler.ApplyFunc(attributeValue, claims, claimKey)
				if success {
					break
				}
			}
		}
	}

	if !success {
		level.Warn(log.Logger).Log(
			definitions.LogKeyGUID, auth.GUID,
			definitions.LogKeyMsg, fmt.Sprintf("Claim '%s' malformed or not returned from Database", claimKey),
		)
	}
}

// processClientClaims processes the client claims by iterating over a map of claim names and values.
// The claim names and corresponding values to process are defined in the claimChecks map.
// For each claim, it calls the processClaim method to apply any necessary processing logic and update the claims map.
// Finally, it returns the updated claims map.
//
// Parameters:
// - client: a pointer to the config.Oauth2Client structure representing the client configuration
// - claims: a map[string]any representing the client claims
//
// Returns:
// - a map[string]any representing the updated client claims
//
// Example usage:
//
//	clientClaims := make(map[string]any)
//	updatedClaims := a.processClientClaims(&oauth2Client, clientClaims)
//	fmt.Println(updatedClaims)
func (a *AuthState) processClientClaims(client *config.Oauth2Client, claims map[string]any) map[string]any {
	// Claim names to process
	claimChecks := map[string]string{
		definitions.ClaimName:              client.Claims.Name,
		definitions.ClaimGivenName:         client.Claims.GivenName,
		definitions.ClaimFamilyName:        client.Claims.FamilyName,
		definitions.ClaimMiddleName:        client.Claims.MiddleName,
		definitions.ClaimNickName:          client.Claims.NickName,
		definitions.ClaimPreferredUserName: client.Claims.PreferredUserName,
		definitions.ClaimProfile:           client.Claims.Profile,
		definitions.ClaimWebsite:           client.Claims.Website,
		definitions.ClaimPicture:           client.Claims.Picture,
		definitions.ClaimEmail:             client.Claims.Email,
		definitions.ClaimGender:            client.Claims.Gender,
		definitions.ClaimBirtDate:          client.Claims.Birthdate,
		definitions.ClaimZoneInfo:          client.Claims.ZoneInfo,
		definitions.ClaimLocale:            client.Claims.Locale,
		definitions.ClaimPhoneNumber:       client.Claims.PhoneNumber,
	}

	for claimName, claimVal := range claimChecks {
		a.processClaim(claimName, claimVal, claims)
	}

	return claims
}

// applyClientClaimHandlers applies claim handlers to client claims and returns the modified claims.
func (a *AuthState) applyClientClaimHandlers(client *config.Oauth2Client, claims map[string]any) map[string]any {
	claimHandlers := []ClaimHandler{
		{
			Type: reflect.String,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if strValue, ok := value.(string); ok {
					if claimKey == definitions.ClaimEmailVerified || claimKey == definitions.ClaimPhoneNumberVerified {
						if boolean, err := strconv.ParseBool(strValue); err == nil {
							claims[claimKey] = boolean

							return true
						}
					} else if claimKey == definitions.ClaimAddress {
						claims[claimKey] = struct {
							Formatted string `json:"formatted"`
						}{Formatted: strValue}

						return true
					}
				}

				return false
			},
		},
		{
			Type: reflect.Bool,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if boolValue, ok := value.(bool); ok {
					claims[claimKey] = boolValue

					return true
				}

				return false
			},
		},
		{
			Type: reflect.Float64,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if floatValue, ok := value.(float64); ok {
					claims[claimKey] = floatValue

					return true
				}

				return false
			},
		},
	}

	claimKeys := map[string]string{
		definitions.ClaimEmailVerified:       client.Claims.EmailVerified,
		definitions.ClaimPhoneNumberVerified: client.Claims.PhoneNumberVerified,
		definitions.ClaimAddress:             client.Claims.Address,
		definitions.ClaimUpdatedAt:           client.Claims.UpdatedAt,
	}

	for claimKey, attrKey := range claimKeys {
		if attrKey != "" {
			applyClaim(claimKey, attrKey, a, claims, claimHandlers)
		}
	}

	return claims
}

// processGroupsClaim processes the groups claim for the specified index in the OAuth2 clients configuration.
// It checks if the claim is defined and retrieves the corresponding value from the AuthState object's Attributes.
// If the value is found and is of type string, it adds it to the provided `claims` map with the key `ClaimGroups`.
// It sets the `valueApplied` flag to true if the value is successfully applied to the `claims` map.
// If the value is not found or is not of type string, it logs a warning message.
// The purpose of the method is to populate the groups claim in the `claims` map for the given OAuth2 client.
//
// Parameters:
// - index: The index of the OAuth2 client in the configuration.
// - claims: The `claims` map to populate with the groups claim.
//
// Example usage:
// ```go
// clientIndex := 0
// claims := make(map[string]any)
// authentication.processGroupsClaim(clientIndex, claims)
// ```
//
// Note: This method relies on the following declarations:
// - `config.GetFile().Oauth2.Clients`: The OAuth2 clients configuration.
// - `a.SearchAttributes`: The AuthState object's Attributes map.
// - `util.DebugModule`: A function for logging debug messages.
// - `global.DbgModule`, `global.LogKeyGUID`, `global.ClaimGroups`, `log.Logger`, `definitions.LogKeyMsg`: Various declarations used internally in the method.
func (a *AuthState) processGroupsClaim(index int, claims map[string]any) {
	valueApplied := false

	if config.GetFile().GetOauth2().Clients[index].Claims.Groups != "" {
		if value, found := a.Attributes[config.GetFile().GetOauth2().Clients[index].Claims.Groups]; found {
			var stringSlice []string

			util.DebugModule(
				definitions.DbgAuth,
				definitions.LogKeyGUID, a.GUID,
				"groups", fmt.Sprintf("%#v", value),
			)

			for anyIndex := range value {
				if arg, assertOk := value[anyIndex].(string); assertOk {
					stringSlice = append(stringSlice, arg)
				}
			}

			claims[definitions.ClaimGroups] = stringSlice
			valueApplied = true
		}

		if !valueApplied {
			level.Warn(log.Logger).Log(
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, fmt.Sprintf("Claim '%s' malformed or not returned from Database", definitions.ClaimGroups),
			)
		}
	}
}

// processCustomClaims processes custom claims for a specific scope and OAuth2 client.
// It retrieves the custom claim names and types from the configuration and checks if
// the client has defined values for those claims. If so, it converts the claim value
// to the corresponding type and adds it to the claims map.
//
// Parameters:
// - scopeIndex: the index of the custom scope to process
// - oauth2Client: the OAuth2 client to process claims for
// - claims: the map to store the processed claims
//
// Example usage:
// ```
// auth := &AuthState{}
// processCustomClaims(0, oauth2Client, auth.Claims)
// ```
func (a *AuthState) processCustomClaims(scopeIndex int, oauth2Client openapi.OAuth2Client, claims map[string]any) {
	var claim any

	customScope := config.GetFile().GetOauth2().CustomScopes[scopeIndex]

	for claimIndex := range customScope.Claims {
		customClaimName := customScope.Claims[claimIndex].Name
		customClaimType := customScope.Claims[claimIndex].Type

		for clientIndex := range config.GetFile().GetOauth2().Clients {
			if config.GetFile().GetOauth2().Clients[clientIndex].ClientId != oauth2Client.GetClientId() {
				continue
			}

			assertOk := false
			if claim, assertOk = config.GetFile().GetOauth2().Clients[clientIndex].Claims.CustomClaims[customClaimName]; !assertOk {
				break
			}

			if claimValue, assertOk := claim.(string); assertOk {
				if value, found := a.Attributes[claimValue]; found {
					util.DebugModule(
						definitions.DbgAuth,
						definitions.LogKeyGUID, a.GUID,
						"custom_claim_name", customClaimName,
						"custom_claim_type", customClaimType,
						"value", fmt.Sprintf("%#v", value),
					)

					switch customClaimType {
					case definitions.ClaimTypeString:
						if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							claims[customClaimName] = arg
						}
					case definitions.ClaimTypeFloat:
						if arg, assertOk := value[definitions.SliceWithOneElement].(float64); assertOk {
							claims[customClaimName] = arg
						} else if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							if number, err := strconv.ParseFloat(arg, 64); err == nil {
								claims[customClaimName] = number
							}
						}
					case definitions.ClaimTypeInteger:
						if arg, assertOk := value[definitions.SliceWithOneElement].(int64); assertOk {
							claims[customClaimName] = arg
						} else if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							if number, err := strconv.ParseInt(arg, 0, 64); err == nil {
								claims[customClaimName] = number
							}
						}
					case definitions.ClaimTypeBoolean:
						if arg, assertOk := value[definitions.SliceWithOneElement].(bool); assertOk {
							claims[customClaimName] = arg
						} else if arg, assertOk := value[definitions.SliceWithOneElement].(string); assertOk {
							if boolean, err := strconv.ParseBool(arg); err == nil {
								claims[customClaimName] = boolean
							}
						}
					default:
						level.Error(log.Logger).Log(
							definitions.LogKeyGUID, a.GUID,
							"custom_claim_name", customClaimName,
							definitions.LogKeyMsg, fmt.Sprintf("Unknown type '%s'", customClaimType),
						)
					}
				}
			}

			break
		}
	}
}

// GetOauth2SubjectAndClaims retrieves the subject and claims for an OAuth2 client. It takes an OAuth2 client as a
// parameter and returns the subject and claims as a string and a map
func (a *AuthState) GetOauth2SubjectAndClaims(oauth2Client openapi.OAuth2Client) (string, map[string]any) {
	var (
		okay    bool
		index   int
		subject string
		client  config.Oauth2Client
		claims  map[string]any
	)

	if config.GetFile().GetOauth2() != nil {
		claims = make(map[string]any)

		clientIDFound := false

		for index, client = range config.GetFile().GetOauth2().Clients {
			if client.ClientId == oauth2Client.GetClientId() {
				clientIDFound = true

				util.DebugModule(
					definitions.DbgAuth,
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, fmt.Sprintf("Found client_id: %+v", client),
				)

				claims = a.processClientClaims(&client, claims)
				claims = a.applyClientClaimHandlers(&client, claims)
				a.processGroupsClaim(index, claims)

				break //exit loop once first matching client found
			}
		}

		for scopeIndex := range config.GetFile().GetOauth2().CustomScopes {
			a.processCustomClaims(scopeIndex, oauth2Client, claims)
		}

		if client.Subject != "" {
			var value []any

			if value, okay = a.Attributes[client.Subject]; !okay {
				level.Info(log.Logger).Log(
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, fmt.Sprintf(
						"SearchAttributes did not contain requested field '%s'",
						client.Subject,
					),
					"attributes", func() string {
						var attributes []string

						for key := range a.Attributes {
							attributes = append(attributes, key)
						}

						return strings.Join(attributes, ", ")
					}(),
				)
			} else if _, okay = value[definitions.SliceWithOneElement].(string); okay {
				subject = value[definitions.SliceWithOneElement].(string)
			}
		}

		if !clientIDFound {
			level.Warn(log.Logger).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "No client_id section found")
		}
	} else {
		// Default result, if no oauth2/clients definition is found
		subject = *a.AccountField
	}

	return subject, claims
}

// generateLocalChacheKey generates a string key used for caching the AuthState object in the local cache.
// The key is constructed by concatenating the Username, Password and  Service values using a null character ('\0')
// as a separator.
func (a *AuthState) generateLocalChacheKey() string {
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

// GetFromLocalCache retrieves the AuthState object from the local cache using the generateLocalChacheKey() as the key.
// If the object is found in the cache, it updates the fields of the current AuthState object with the cached values.
// It also sets the a.GUID field with the original value to avoid losing the GUID from the previous object.
// If the a.HTTPClientContext field is not nil, it sets it to nil and restores it after updating the AuthState object.
// It sets the a.UsedPassDBBackend field to BackendLocalCache to indicate that the cache was used.
// Finally, it sets the "local_cache_auth" key to true in the gin.Context using ctx.Set() and returns true if the object is found in the cache; otherwise, it returns false.
func (a *AuthState) GetFromLocalCache(ctx *gin.Context) bool {
	if a.HaveMonitoringFlag(definitions.MonInMemory) {
		return false
	}

	if value, found := localcache.LocalCache.Get(a.generateLocalChacheKey()); found {
		passDBResult := value.(*PassDBResult)

		updateAuthentication(a, passDBResult, &PassDBMap{
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

		if a.CheckBruteForce() {
			a.UpdateBruteForceBucketsCounter()
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
