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
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sort"
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
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/spf13/viper"
	"golang.org/x/sync/singleflight"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"go.opentelemetry.io/otel/attribute"
)

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

type AuthDeps struct {
	Cfg    config.File
	Env    config.Environment
	Logger *slog.Logger
	Redis  rediscli.Client
}

// AuthState represents a struct that holds information related to an authentication process.
type AuthState struct {
	// deps holds the injected runtime dependencies for this auth request.
	// It must be initialized by the request-boundary constructor.
	deps AuthDeps

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

	// attempts holds the centralized LoginAttemptManager. It is kept private to
	// ensure that mutations go through dedicated helpers and invariants stay intact.
	attempts *defaultLoginAttemptManager

	// StatusCodeOk is the HTTP status code that is set by SetStatusCodes.
	StatusCodeOK int

	// StatusCodeInternalError is the HTTP status code that is set by SetStatusCodes.
	StatusCodeInternalError int

	// StatusCodeFail is the HTTP status code that is set by SetStatusCodes.
	StatusCodeFail int

	// GUID is a global unique identifier inherited in all functions and methods that deal with the
	// authentication process. It is necessary to track log lines belonging to one request.
	GUID string

	// Method is set by the "Auth-Method" HTTP request header (Nginx protocol). It is typically something like "plain"
	// or "login".
	Method string

	// AccountField is the name of either an SQL field name or an LDAP attribute that was used to retrieve a user account.
	AccountField string

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
	UserAgent string

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
	TOTPSecret string

	// TOTPSecretField is the SQL field or LDAP attribute that resolves the TOTP secret for two-factor authentication.
	TOTPSecretField string

	// TOTPRecoveryField NYI
	TOTPRecoveryField string

	// UniqueUserIDField is a string representing a unique user identifier.
	UniqueUserIDField string

	// DisplayNameField is the display name of a user
	DisplayNameField string

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

	// attributesMu protects the Attributes map against concurrent writes and write-vs-iterate scenarios.
	// Note: Go maps are not safe for concurrent writes. We currently lock around mutation sites
	// (e.g., Lua filter), which eliminates fatal "concurrent map writes". Reads may still happen
	// without a lock where acceptable for performance; extend locking to reads if needed.
	attributesMu sync.RWMutex

	// Protocol is set by the HTTP request header "Auth-Protocol" (Nginx protocol).
	Protocol *config.Protocol

	// HTTPClientContext tracks the context for an HTTP client connection.
	HTTPClientContext *gin.Context

	// HTTPClientRequest represents the underlying HTTP request to be sent by the client.
	HTTPClientRequest *http.Request

	// MonitoringFlags is a slice of definitions.Monitoring that is used to skip certain steps while processing an authentication request.
	MonitoringFlags []definitions.Monitoring

	// MasterUserMode is a flag for a backend to indicate a master user mode is ongoing.
	MasterUserMode bool

	*bruteforce.PasswordHistory
	*lualib.Context
}

func (a *AuthState) cfg() config.File {
	if a != nil && a.deps.Cfg != nil {
		return a.deps.Cfg
	}

	return getDefaultConfigFile()
}

func (a *AuthState) env() config.Environment {
	if a != nil && a.deps.Env != nil {
		return a.deps.Env
	}

	return getDefaultEnvironment()
}

func (a *AuthState) logger() *slog.Logger {
	if a != nil && a.deps.Logger != nil {
		return a.deps.Logger
	}

	return getDefaultLogger()
}

func (a *AuthState) redis() rediscli.Client {
	if a != nil && a.deps.Redis != nil {
		return a.deps.Redis
	}

	return getDefaultRedisClient()
}

var _ State = (*AuthState)(nil)

// PassDBResult is used in all password databases to store final results of an authentication process.
type PassDBResult struct {
	// Authenticated is a flag that is set if a user was not only found, but also succeeded authentication.
	Authenticated bool

	// UserFound is a flag that is set if the user was found in a password Database.
	UserFound bool

	// BackendName specifies the name of the backend that authenticated or found the user in the password database.
	BackendName string

	// AccountField is the SQL field or LDAP attribute that was used for the user account.
	AccountField string

	// TOTPSecretField is set by the Database which has found the user.
	TOTPSecretField string

	// TOTPRecoveryField NYI
	TOTPRecoveryField string

	// UniqueUserIDField is a string representing a unique user identifier.
	UniqueUserIDField string

	// DisplayNameField is the display name of a user
	DisplayNameField string

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
	p.AccountField = ""
	p.TOTPSecretField = ""
	p.TOTPRecoveryField = ""
	p.UniqueUserIDField = ""
	p.DisplayNameField = ""

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
			if getDefaultEnvironment().GetDevMode() {
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

// GetFailCount returns the current number of failed login attempts using the
// centralized manager if available. If the manager is not initialized, it
// falls back to the legacy field. This method is used for logging
// current_password_retries to ensure the value represents the number of
// failures (0-based), not the 1-based attempt ordinal.
func (a *AuthState) GetFailCount() uint {
	if a == nil {
		return 0
	}

	if lam := a.ensureLAM(); lam != nil {
		return lam.FailCount()
	}

	return a.LoginAttempts
}

// SetMethod sets the authentication method for the AuthState instance by assigning it to the Method field.
func (a *AuthState) SetMethod(method string) {
	a.Method = method
}

// SetUserAgent sets the UserAgent field for the AuthState with the provided userAgent value.
func (a *AuthState) SetUserAgent(userAgent string) {
	a.UserAgent = userAgent
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
	return a.GUID
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
	return a.TOTPSecretField
}

// GetTOTPRecoveryField retrieves the TOTP recovery field value from AuthState. Returns an empty string if not set.
func (a *AuthState) GetTOTPRecoveryField() string {
	return a.TOTPRecoveryField
}

// GetUniqueUserIDField retrieves the value of the UniqueUserIDField if set; returns an empty string otherwise.
func (a *AuthState) GetUniqueUserIDField() string {
	return a.UniqueUserIDField
}

// GetDisplayNameField retrieves the display name field from the AuthState. Returns an empty string if it's nil.
func (a *AuthState) GetDisplayNameField() string {
	return a.DisplayNameField
}

// GetUsedPassDBBackend returns the currently used backend for password database operations.
func (a *AuthState) GetUsedPassDBBackend() definitions.Backend {
	return a.UsedPassDBBackend
}

// GetAttributes retrieves the stored database attributes from the AuthState and returns them as a AttributeMapping.
func (a *AuthState) GetAttributes() bktype.AttributeMapping {
	return a.Attributes
}

// GetAttributesCopy returns a deep copy of the Attributes map to avoid aliasing across components.
// The copy is made under a read lock; callers may safely mutate the returned map.
func (a *AuthState) GetAttributesCopy() bktype.AttributeMapping {
	a.attributesMu.RLock()
	defer a.attributesMu.RUnlock()

	if a.Attributes == nil {
		return nil
	}

	cp := make(bktype.AttributeMapping, len(a.Attributes))
	for k, v := range a.Attributes {
		if v != nil {
			vv := make([]any, len(v))
			copy(vv, v)
			cp[k] = vv
		} else {
			cp[k] = nil
		}
	}

	return cp
}

// DeleteAttribute removes the attribute with the given name from the AuthState in a concurrency-safe manner.
// It is safe to call from multiple goroutines.
func (a *AuthState) DeleteAttribute(name string) {
	if a == nil || name == "" {
		return
	}

	a.attributesMu.Lock()
	if a.Attributes != nil {
		delete(a.Attributes, name)
	}

	a.attributesMu.Unlock()
}

// SetAttributeIfAbsent sets the attribute to a single-value slice if it does not exist yet.
// This mirrors typical usage where scripts want to add an attribute only when missing.
// It allocates the Attributes map lazily and is concurrency-safe.
func (a *AuthState) SetAttributeIfAbsent(name string, value any) {
	if a == nil || name == "" {
		return
	}

	a.attributesMu.Lock()
	if a.Attributes == nil {
		a.Attributes = make(bktype.AttributeMapping)
	}

	if _, ok := a.Attributes[name]; !ok {
		a.Attributes[name] = []any{value}
	}

	a.attributesMu.Unlock()
}

// ReplaceAllAttributes replaces the entire Attributes map with a deep copy of the provided map, under write lock.
// Passing nil will set Attributes to nil.
func (a *AuthState) ReplaceAllAttributes(m bktype.AttributeMapping) {
	a.attributesMu.Lock()
	defer a.attributesMu.Unlock()

	if m == nil {
		a.Attributes = nil

		return
	}

	cp := make(bktype.AttributeMapping, len(m))
	for k, v := range m {
		if v != nil {
			vv := make([]any, len(v))
			copy(vv, v)
			cp[k] = vv
		} else {
			cp[k] = nil
		}
	}

	a.Attributes = cp
}

// GetAttribute returns the attribute slice and a boolean indicating presence, under a read lock.
func (a *AuthState) GetAttribute(name string) ([]any, bool) {
	a.attributesMu.RLock()
	defer a.attributesMu.RUnlock()

	if a.Attributes == nil {
		return nil, false
	}

	v, ok := a.Attributes[name]

	return v, ok
}

// RangeAttributes iterates over all attributes under a read lock and calls fn for each key/value.
// If fn returns false, iteration stops early.
func (a *AuthState) RangeAttributes(fn func(string, []any) bool) {
	a.attributesMu.RLock()
	defer a.attributesMu.RUnlock()
	for k, v := range a.Attributes {
		if !fn(k, v) {
			return
		}
	}
}

// GetAdditionalLogs returns a slice of additional logs associated with the AuthState instance.
func (a *AuthState) GetAdditionalLogs() []any {
	return a.AdditionalLogs
}

// GetClientIP returns the client's IP address stored in the AuthState instance.
func (a *AuthState) GetClientIP() string {
	return a.ClientIP
}

// GetAccount returns the account value from the AuthState object. If the account field is not set or the account
// value is not found in the attributes, an empty string is returned
func (a *AuthState) GetAccount() string {
	// Prefer value stored in the Gin context for the current request
	// to avoid redundant cache/Redis lookups within the same request.
	if a != nil && a.HTTPClientContext != nil {
		if v := a.HTTPClientContext.GetString(definitions.CtxAccountKey); v != "" {
			return v
		}
	}

	if account, okay := a.GetAttribute(a.AccountField); okay {
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
	if totpSecret, okay := a.GetAttribute(a.GetTOTPSecretField()); okay {
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
	if webAuthnUserID, okay := a.GetAttribute(a.GetUniqueUserIDField()); okay {
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
	if account, okay := a.GetAttribute(a.GetDisplayNameField()); okay {
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

// increaseLoginAttempts increments the number of login attempts for the AuthState object.
// If the number of login attempts exceeds the maximum value allowed (MaxUint8), it sets it to the maximum value.
// If the AuthState service is equal to ServNginx and the number of login attempts is less than the maximum login attempts specified in the GetEnvironment() configuration,
// it increments the number of login attempts by one.
// The usage example of this method can be found in the AuthFail function.
func (a *AuthState) increaseLoginAttempts() {
	lam := a.ensureLAM()
	if lam == nil {
		return
	}

	// Delegate to the centralized manager
	lam.OnAuthFailure()

	// Mirror back to legacy field (FailCount semantics)
	a.LoginAttempts = lam.FailCount()
}

// SyncLoginAttemptsFromBucket updates the internal login attempt manager from a
// brute-force bucket value and mirrors the FailCount to the legacy field.
// The bucket is considered authoritative over header hints.
func (a *AuthState) SyncLoginAttemptsFromBucket(counter uint) {
	lam := a.ensureLAM()
	if lam == nil {
		a.LoginAttempts = counter

		return
	}

	lam.InitFromBucket(counter)
	a.LoginAttempts = lam.FailCount()
}

// ResetLoginAttemptsOnSuccess resets the internal fail counter after a
// successful authentication. This affects only the in-process view; any
// persistent brute-force storage remains managed by the brute-force subsystem.
func (a *AuthState) ResetLoginAttemptsOnSuccess() {
	lam := a.ensureLAM()
	if lam == nil {
		a.LoginAttempts = 0
		return
	}

	lam.OnAuthSuccess()
	a.LoginAttempts = lam.FailCount()
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
	ctx.Header("X-Nauthilus-Session", a.GUID)

	switch a.Service {
	case definitions.ServHeader, definitions.ServNginx, definitions.ServJSON:
		maxWaitDelay := viper.GetUint("nginx_wait_delay")

		if maxWaitDelay > 0 {
			waitDelay := bfWaitDelay(maxWaitDelay, a.LoginAttempts)
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

	level.Notice(a.logger()).Log(keyvals...)

	stats.GetMetrics().GetRejectedProtocols().WithLabelValues(a.Protocol.Get()).Inc()
	stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelFailure).Inc()
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

// IsMasterUser checks whether the current user is a master user based on the MasterUser configuration in the GetFile().
// It returns true if MasterUser is enabled and the number of occurrences of the delimiter in the Username is equal to 1, otherwise it returns false.
func (a *AuthState) IsMasterUser() bool {
	cfg := a.cfg()
	mu := cfg.GetServer().GetMasterUser()

	if mu.IsEnabled() {
		delim := mu.GetDelimiter()
		if strings.Count(a.Username, delim) == 1 {
			parts := strings.Split(a.Username, delim)
			if len(parts[0]) > 0 && len(parts[1]) > 0 {
				return true
			}
		}
	}

	return false
}

// IsInNetwork checks an IP address against a network and returns true if it matches.
func (a *AuthState) IsInNetwork(networkList []string) (matchIP bool) {
	return util.IsInNetwork(networkList, a.GUID, a.ClientIP)
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
	if v := getPasswordVerifier(); v != nil {
		return v.Verify(ctx, a, passDBs)
	}

	// No password verifier registered - abort with error
	return nil, errors.ErrUnregisteredComponent
}

// HandleBackendErrors handles the errors that occur during backend processing.
// It checks if the error is a configuration error for SQL, LDAP, or Lua backends and adds them to the configErrors map.
// If all password databases have been processed and there are configuration errors, it calls the checkAllBackends function.
// If the error is not a configuration error, it logs the error using the Logger.
// It returns the error unchanged.
func HandleBackendErrors(passDBIndex int, passDBs []*PassDBMap, passDB *PassDBMap, err error, auth *AuthState, configErrors map[definitions.Backend]error) error {
	if stderrors.Is(err, errors.ErrLDAPConfig) || stderrors.Is(err, errors.ErrLuaConfig) {
		configErrors[passDB.backend] = err

		// After all password databases were running,  check if SQL, LDAP and Lua  backends have configuration errors.
		if passDBIndex == len(passDBs)-1 {
			err = checkAllBackends(configErrors, auth)
		}
	} else {
		level.Error(auth.logger()).Log(
			definitions.LogKeyGUID, auth.GUID,
			"passdb", passDB.backend.String(),
			definitions.LogKeyMsg, "Error occurred during backend processing",
			definitions.LogKeyError, err)
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
		level.Error(auth.logger()).Log(
			definitions.LogKeyGUID, auth.GUID,
			"passdb", "all",
			definitions.LogKeyMsg, "All backends failed",
			definitions.LogKeyError, err,
		)
	}

	return err
}

// ProcessPassDBResult updates the passDBResult based on the provided passDB
// and the AuthState object a.
// If passDBResult is nil, it returns an error of type errors.ErrNoPassDBResult.
// It then calls the util.DebugModule function to log debug information.
// Next, it calls the updateAuthentication function to update the fields of a based on the values in passDBResult.
// If the UserFound field of passDBResult is true, it sets the UserFound field of a to true.
// Finally, it returns the updated passDBResult and nil error.
func ProcessPassDBResult(ctx *gin.Context, passDBResult *PassDBResult, auth *AuthState, passDB *PassDBMap) error {
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

	if passDBResult.AccountField != "" {
		auth.AccountField = passDBResult.AccountField
	}

	if passDBResult.TOTPSecretField != "" {
		auth.TOTPSecretField = passDBResult.TOTPSecretField
	}

	if passDBResult.UniqueUserIDField != "" {
		auth.UniqueUserIDField = passDBResult.UniqueUserIDField
	}

	if passDBResult.DisplayNameField != "" {
		auth.DisplayNameField = passDBResult.DisplayNameField
	}

	if passDBResult.Attributes != nil && len(passDBResult.Attributes) > 0 {
		auth.ReplaceAllAttributes(passDBResult.Attributes)
	}

	// Handle AdditionalFeatures if they exist in the PassDBResult
	if passDBResult.AdditionalFeatures != nil && len(passDBResult.AdditionalFeatures) > 0 {
		// Set AdditionalFeatures in the gin.Context
		ctx.Set(definitions.CtxAdditionalFeaturesKey, passDBResult.AdditionalFeatures)
	}

	// After attributes were applied, derive the authoritative account directly from attributes
	// and mirror it into the Gin context. Do not use GetAccount() here, because that could still
	// prefer a preliminary context value set by earlier middleware. The attribute value must win.
	if vals, ok := auth.GetAttribute(auth.AccountField); ok {
		// We expect a single value string at LDAPSingleValue
		if acc, ok2 := vals[definitions.LDAPSingleValue].(string); ok2 && acc != "" {
			// Update the request-scoped context value and log source
			prev := ctx.GetString(definitions.CtxAccountKey)
			ctx.Set(definitions.CtxAccountKey, acc)

			util.DebugModule(
				definitions.DbgAccount,
				definitions.LogKeyGUID, auth.GUID,
				definitions.LogKeyUsername, auth.Username,
				definitions.LogKeyMsg, "Set account from attributes",
				"prev", prev,
				"new", acc,
				"source", "attribute",
				"changed", prev != acc,
			)

			// Keep Redis nt:USER mapping in sync when attribute-derived account differs.
			// Read the current mapping with a bounded read deadline.
			dReadCtx, cancelRead := util.GetCtxWithDeadlineRedisRead(auth.Ctx())
			current, err := backend.LookupUserAccountFromRedis(dReadCtx, auth.Username)
			cancelRead()

			if err != nil {
				level.Error(getDefaultLogger()).Log(
					definitions.LogKeyGUID, auth.GUID,
					definitions.LogKeyMsg, "Failed to lookup user->account mapping in Redis",
					definitions.LogKeyError, err,
				)
			} else if current == "" || current != acc {
				// Update Redis mapping with a bounded write deadline.
				defer stats.GetMetrics().GetRedisWriteCounter().Inc()

				dWriteCtx, cancelWrite := util.GetCtxWithDeadlineRedisWrite(nil)
				werr := backend.SetUserAccountMapping(dWriteCtx, auth.Username, acc)
				cancelWrite()

				if werr != nil {
					level.Error(getDefaultLogger()).Log(
						definitions.LogKeyGUID, auth.GUID,
						definitions.LogKeyMsg, "Failed to update user->account mapping in Redis",
						definitions.LogKeyError, werr,
					)
				} else {
					util.DebugModule(definitions.DbgAccount,
						definitions.LogKeyGUID, auth.GUID,
						definitions.LogKeyUsername, auth.Username,
						definitions.LogKeyMsg, "Synchronized nt:USER mapping",
						"account", acc,
						"source", "redis-update",
					)
				}
			}
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
	accountName, err := backend.LookupUserAccountFromRedis(a.Ctx(), a.Username)
	if err != nil {
		return false, err
	}

	return accountName != "", nil
}

// refreshUserAccount updates the user account information from the cache.
// It sets the account field and attributes if they are nil and the account name is found.
func (a *AuthState) refreshUserAccount() (accountName string) {
	// If account already present in state/attributes, avoid Redis
	if acc := a.GetAccount(); acc != "" {
		return acc
	}

	// Use request/service context with bounded deadline to avoid leaks and reuse caller context
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(a.Ctx())
	accountName = backend.GetUserAccountFromCache(dCtx, a.Username, a.GUID)
	cancel()

	if accountName == "" {
		return
	}

	// Memoize into state attributes
	if a.AccountField == "" {
		a.AccountField = definitions.MetaUserAccount
	}

	// Set attribute if missing
	if a.Attributes == nil || len(a.Attributes) == 0 {
		attributes := make(bktype.AttributeMapping)
		attributes[definitions.MetaUserAccount] = []any{accountName}
		a.ReplaceAllAttributes(attributes)
	}

	return
}

// GetAccountField returns the value of the AccountField field in the AuthState struct.
// If the AccountField field is nil, it returns an empty string.
func (a *AuthState) GetAccountField() string {
	return a.AccountField
}

// PostLuaAction sends a Lua action to be executed asynchronously.
func (a *AuthState) PostLuaAction(passDBResult *PassDBResult) {
	tr := monittrace.New("nauthilus/auth")
	ctx := a.Ctx()
	lctx, lspan := tr.Start(ctx, "auth.lua.post_action",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
	)

	_ = lctx
	if passDBResult != nil {
		lspan.SetAttributes(
			attribute.Bool("authenticated", passDBResult.Authenticated),
			attribute.Bool("user_found", passDBResult.UserFound),
		)

		if passDBResult.BackendName != "" {
			lspan.SetAttributes(attribute.String("backend", passDBResult.BackendName))
		} else {
			lspan.SetAttributes(attribute.String("backend", passDBResult.Backend.String()))
		}
	}

	defer lspan.End()

	if act := getPostAction(); act != nil {
		act.Run(PostActionInput{View: a.View(), Result: passDBResult})
	}
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

// SFKeyHash returns a short hash for the strict singleflight key to use in Redis keys.
func (a *AuthState) SFKeyHash() string {
	sum := sha1.Sum([]byte(a.generateSingleflightKey()))

	return hex.EncodeToString(sum[:])
}

// HandlePassword handles the authentication process for the password flow.
// Delegate orchestration to the Authenticator to keep responsibilities separated.
func (a *AuthState) HandlePassword(ctx *gin.Context) (authResult definitions.AuthResult) {
	return defaultAuthenticator.Authenticate(ctx, a)
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
	if stop := stats.PrometheusTimer(definitions.PromAuth, "auth_local_cache_path_total"); stop != nil {
		defer stop()
	}

	a.SetOperationMode(ctx)

	passDBResult := a.initializePassDBResult()

	// Since this path is a confirmed positive hit from the in-memory cache,
	// the PassDB stage has already decided previously. Reflect that in AuthState
	// so final logs include authn=true for cache hits.
	a.Authenticated = true

	authResult := definitions.AuthResultOK

	if !(a.Protocol.Get() == definitions.ProtoOryHydra) {
		if lf := getLuaFilter(); lf != nil {
			authResult = lf.Filter(ctx, a.View(), passDBResult)
		}

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
	// Hand out a copy to avoid aliasing with the live AuthState map
	result.Attributes = a.GetAttributesCopy()

	return result
}

// handleBackendTypes initializes and populates variables related to backend types.
// The `backendPos` map stores the position of each backend type in the configuration list.
// The `useCache` boolean indicates whether the Cache backend type is used. It is set to true if at least one Cache backend is found in the configuration.
// The `passDBs` slice holds the PassDBMap objects associated with each backend type in the configuration.
// This method loops through the `config.GetFile().GetServer().Backends` slice and processes each Backend object to determine the backend type. It populates the `backendPos` map with the backend type
func (a *AuthState) handleBackendTypes() (useCache bool, backendPos map[definitions.Backend]int, passDBs []*PassDBMap) {
	backendPos = make(map[definitions.Backend]int)

	cfg := getDefaultConfigFile()

	for index, backendType := range cfg.GetServer().GetBackends() {
		db := backendType.Get()
		switch db {
		case definitions.BackendCache:
			if !(a.HaveMonitoringFlag(definitions.MonCache) || a.IsMasterUser()) {
				passDBs = a.appendBackend(passDBs, definitions.BackendCache, CachePassDB)
				useCache = true
			}
		case definitions.BackendLDAP:
			if !cfg.LDAPHavePoolOnly(backendType.GetName()) {
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
	tr := monittrace.New("nauthilus/auth")
	vctx, vspan := tr.Start(ctx.Request.Context(), "auth.verify",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
	)

	// ensure downstream uses the same context
	ctx.Request = ctx.Request.WithContext(vctx)
	defer vspan.End()

	if stop := stats.PrometheusTimer(definitions.PromAuth, "auth_verify_password_total"); stop != nil {
		defer stop()
	}

	passDBResult, err := a.verifyPassword(ctx, passDBs)
	if passDBResult != nil {
		vspan.SetAttributes(
			attribute.Bool("authenticated", passDBResult.Authenticated),
			attribute.Bool("user_found", passDBResult.UserFound),
		)

		if passDBResult.BackendName != "" {
			vspan.SetAttributes(attribute.String("backend", passDBResult.BackendName))
		} else {
			vspan.SetAttributes(attribute.String("backend", passDBResult.Backend.String()))
		}
	}

	if err != nil {
		vspan.RecordError(err)
	}

	if err != nil {
		var detailedError *errors.DetailedError

		if stderrors.As(err, &detailedError) {
			logs := []any{
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, detailedError.GetDetails(),
				definitions.LogKeyError, detailedError.Error(),
			}

			if len(a.AdditionalLogs) > 0 && len(a.AdditionalLogs)%2 == 0 {
				logs = append(logs, a.AdditionalLogs...)
			}

			level.Error(getDefaultLogger()).Log(
				logs...,
			)
		} else {
			level.Error(getDefaultLogger()).Log(
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, "Error verifying password",
				definitions.LogKeyError, err)
		}
	}

	return passDBResult, err
}

// processUserFound handles the processing when a user is found in the database, updates user account in Redis, and processes password history.
// It returns the account name and any error encountered during the process.
func (a *AuthState) processUserFound(passDBResult *PassDBResult) (accountName string, err error) {
	if stop := stats.PrometheusTimer(definitions.PromAuth, "auth_user_found_total"); stop != nil {
		defer stop()
	}

	var bm bruteforce.BucketManager

	if a.UserFound {
		accountName, err = a.updateUserAccountInRedis()
		if err != nil {
			level.Error(getDefaultLogger()).Log(
				definitions.LogKeyGUID, a.GUID,
				definitions.LogKeyMsg, "Error updating user account in Redis",
				definitions.LogKeyError, err)
		}

		if !passDBResult.Authenticated {
			bm = bruteforce.NewBucketManager(a.Ctx(), a.GUID, a.ClientIP).
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

// GetUsedCacheBackend returns the cache name backend based on the used password database backend.
func (a *AuthState) GetUsedCacheBackend() (definitions.CacheNameBackend, error) {
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
		level.Error(getDefaultLogger()).Log(
			definitions.LogKeyGUID, a.GUID,
			definitions.LogKeyMsg, "Unable to get the cache name backend",
			definitions.LogKeyError, fmt.Errorf("unknown backend type: %s", a.UsedPassDBBackend),
		)

		return usedBackend, errors.ErrIncorrectCache
	}

	return usedBackend, nil
}

// GetCacheNameFor retrieves the cache name associated with the given backend, based on the protocol configured for the AuthState.
func (a *AuthState) GetCacheNameFor(usedBackend definitions.CacheNameBackend) (cacheName string, err error) {
	cacheNames := backend.GetCacheNames(a.Protocol.Get(), usedBackend)
	if len(cacheNames) != 1 {
		level.Error(a.logger()).Log(
			definitions.LogKeyGUID, a.GUID,
			definitions.LogKeyMsg, "Cache names are not correct",
			definitions.LogKeyError, fmt.Errorf("cache names are not correct: %v", cacheNames),
		)

		return "", errors.ErrIncorrectCache
	}

	cacheName = cacheNames.GetStringSlice()[definitions.SliceWithOneElement]

	return
}

// CreatePositivePasswordCache constructs a PositivePasswordCache containing user authentication details.
func (a *AuthState) CreatePositivePasswordCache() *bktype.PositivePasswordCache {
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

// processCache updates the relevant user cache entries based on authentication results from password databases.
func (a *AuthState) processCache(ctx *gin.Context, authenticated bool, accountName string, useCache bool, backendPos map[definitions.Backend]int) error {
	tr := monittrace.New("nauthilus/auth")
	cctx, cspan := tr.Start(ctx.Request.Context(), "auth.cache.process",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
		attribute.Bool("authenticated", authenticated),
		attribute.Bool("use_cache", useCache),
	)

	_ = cctx

	defer cspan.End()

	if stop := stats.PrometheusTimer(definitions.PromAuth, "auth_process_cache_total"); stop != nil {
		defer stop()
	}

	if useCache && a.isCacheInCorrectPosition(backendPos) {
		if cs := getCacheService(); cs != nil {
			if authenticated {
				if err := cs.OnSuccess(a, accountName); err != nil {
					return err
				}
			} else {
				cs.OnFailure(a, accountName)
			}
		}

		// Load histories and update counters via service (no behavior change)
		bfLoadHistories(ctx, a, accountName)
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
	tr := monittrace.New("nauthilus/auth")
	actx, aspan := tr.Start(ctx.Request.Context(), "auth.authenticate",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
		attribute.Bool("use_cache", useCache),
	)

	ctx.Request = ctx.Request.WithContext(actx)

	defer aspan.End()

	if stop := stats.PrometheusTimer(definitions.PromAuth, "auth_authenticate_user_total"); stop != nil {
		defer stop()
	}

	// Protect against re-entrancy: if a prior pass in this request already authenticated, do not degrade
	if a.Authenticated {
		return definitions.AuthResultOK
	}

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

	if accountName, err = a.processUserFound(passDBResult); err != nil || passDBResult == nil {
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
			localcache.LocalCache.Set(a.generateLocalCacheKey(), passDBResult, getDefaultEnvironment().GetLocalCacheAuthTTL())
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
		aspan.SetAttributes(attribute.String("lua.result", string(authResult)))

		a.PostLuaAction(passDBResult)
	}

	return authResult
}

// FilterLua calls Lua filters which can change the backend result.
func (a *AuthState) FilterLua(passDBResult *PassDBResult, ctx *gin.Context) definitions.AuthResult {
	tr := monittrace.New("nauthilus/auth")
	lctx, lspan := tr.Start(ctx.Request.Context(), "auth.lua.filter",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
	)

	ctx.Request = ctx.Request.WithContext(lctx)

	defer lspan.End()

	if stop := stats.PrometheusTimer(definitions.PromAuth, "auth_filter_lua_total"); stop != nil {
		defer stop()
	}

	if lf := getLuaFilter(); lf != nil {
		res := lf.Filter(ctx, a.View(), passDBResult)
		lspan.SetAttributes(attribute.String("result", string(res)))

		return res
	}

	level.Error(a.logger()).Log(definitions.LogKeyGUID, a.GUID, definitions.LogKeyMsg, "LuaFilter not registered")

	return definitions.AuthResultTempFail
}

// ListUserAccounts returns the list of all known users from the account databases.
func (a *AuthState) ListUserAccounts() (accountList AccountList) {
	var accounts []*AccountListMap

	// Pre-allocate the accounts slice to avoid continuous reallocation
	// This is a conservative estimate, we'll allocate based on the number of backends
	accountList = make(AccountList, 0, 100)

	a.Protocol.Set("account-provider")

	for _, backendType := range a.cfg().GetServer().GetBackends() {
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
				level.Error(a.logger()).Log(
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, detailedError.GetDetails(),
					definitions.LogKeyError, err,
				)
			} else {
				level.Error(a.logger()).Log(
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, "Error calling account database",
					definitions.LogKeyError, err,
				)
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

	// Service-scoped read to avoid inheriting a canceled request context
	dReadCtx, cancelRead := util.GetCtxWithDeadlineRedisRead(nil)
	accountName = backend.GetUserAccountFromCache(dReadCtx, a.Username, a.GUID)
	cancelRead()

	if accountName != "" {
		return
	}

	if a.AccountField != "" {
		if values, assertOk = a.GetAttribute(a.AccountField); !assertOk {
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

		// Service-scoped write for robust cache update
		dWriteCtx, cancelWrite := util.GetCtxWithDeadlineRedisWrite(nil)
		err = backend.SetUserAccountMapping(dWriteCtx, a.Username, accountName)
		cancelWrite()
	}

	return
}

// Ctx returns a standard library context for this AuthState.
// Preference order:
// 1) HTTPClientRequest.Context() if present
// 2) HTTPClientContext.Request.Context() if present
// 3) svcctx.Get() as a safe, non-nil fallback
func (a *AuthState) Ctx() context.Context {
	if a != nil {
		if a.HTTPClientRequest != nil {
			if rc := a.HTTPClientRequest.Context(); rc != nil {
				// Avoid returning a canceled request context
				if rc.Err() == nil {
					return rc
				}
			}
		}

		if a.HTTPClientContext != nil && a.HTTPClientContext.Request != nil {
			if rc := a.HTTPClientContext.Request.Context(); rc != nil {
				// Avoid returning a canceled request context
				if rc.Err() == nil {
					return rc
				}
			}
		}
	}

	return svcctx.Get()
}

// HasJWTRole checks if the user has the specified role in their JWT token.
// It retrieves the JWT claims from the context and checks if the user has the required role.
// If JWT authentication is not enabled or no claims are found, it returns false.
func (a *AuthState) HasJWTRole(ctx *gin.Context, role string) bool {
	// Check if JWT auth is enabled
	if !a.cfg().GetServer().GetJWTAuth().IsEnabled() {
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
	if stop := stats.PrometheusTimer(definitions.PromAuth, "auth_set_operation_mode_total"); stop != nil {
		defer stop()
	}

	guid := ctx.GetString(definitions.CtxGUIDKey)
	cfg := a.cfg()
	logger := a.logger()

	// We reset flags, because they might have been cached in the in-memory cahce.
	a.NoAuth = false
	a.ListAccounts = false
	a.MonitoringFlags = []definitions.Monitoring{}

	switch ctx.Query("mode") {
	case "no-auth":
		util.DebugModule(definitions.DbgAuth, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "mode=no-auth")

		// Check if JWT is enabled and user has the required role
		if cfg.GetServer().GetJWTAuth().IsEnabled() {
			if a.HasJWTRole(ctx, "user_info") {
				a.NoAuth = true
			} else {
				level.Warn(logger).Log(
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
		if cfg.GetServer().GetJWTAuth().IsEnabled() {
			if a.HasJWTRole(ctx, "list_accounts") {
				a.ListAccounts = true
			} else {
				level.Warn(logger).Log(
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
	if stop := stats.PrometheusTimer(definitions.PromRequest, "request_headers_parse_total"); stop != nil {
		defer stop()
	}

	cfg := getDefaultConfigFile()
	if a, ok := auth.(*AuthState); ok {
		cfg = a.cfg()
	}

	// Nginx header, see: https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html#protocol
	username := ctx.GetHeader(cfg.GetUsername())
	password := ctx.GetHeader(cfg.GetPassword())

	encoded := ctx.GetHeader(cfg.GetPasswordEncoded())
	if encoded == "1" {
		// Decode password locally before applying
		padding := len(password) % 4
		if padding > 0 {
			password += string(bytes.Repeat([]byte("="), 4-padding))
		}

		if decodedPassword, err := base64.URLEncoding.DecodeString(password); err != nil {
			password = ""
			ctx.Error(errors.ErrPasswordEncoding)
		} else {
			password = string(decodedPassword)
		}
	}

	if a, ok := auth.(*AuthState); ok {
		// Apply credentials and header-derived context in a consolidated manner
		a.ApplyCredentials(NewCredentials(
			WithUsername(username),
			WithPassword(password),
		))

		a.ApplyContextData(NewAuthContext(
			WithProtocol(ctx.GetHeader(cfg.GetProtocol())),
			WithMethod(ctx.GetHeader(cfg.GetAuthMethod())),
		))
	}

	// Initialize login attempts from header using the centralized manager.
	if a, ok := auth.(*AuthState); ok {
		lam := a.ensureLAM()
		if lam != nil {
			lam.InitFromHeader(ctx.GetHeader(cfg.GetLoginAttempt()))
			// Mirror for backward compatibility: store FailCount (number of failures)
			a.LoginAttempts = lam.FailCount()
		}
	}

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
	if stop := stats.PrometheusTimer(definitions.PromRequest, "request_form_decode_total"); stop != nil {
		defer stop()
	}

	// Build username incorporating optional realm suffix
	username := ctx.PostForm("username")
	realm := ctx.PostForm("realm")

	if len(realm) > 0 {
		username = username + "@" + realm
	}

	// Apply credentials via builder
	if a, ok := auth.(*AuthState); ok {
		a.ApplyCredentials(NewCredentials(
			WithUsername(username),
			WithPassword(ctx.PostForm("password")),
		))
	}

	// Build and apply context metadata
	x := NewAuthContext(
		WithMethod(ctx.PostForm("method")),
		WithUserAgent(ctx.PostForm("user_agent")),
		WithProtocol(ctx.PostForm("protocol")),
		WithLocalIP(definitions.Localhost4),
		WithLocalPort(ctx.PostForm("port")),
		WithXSSL(ctx.PostForm("tls")),
		WithXSSLProtocol(ctx.PostForm("security")),
	)

	if a, ok := auth.(*AuthState); ok {
		a.ApplyContextData(x)
	}
}

// processApplicationJSON takes a gin Context and an AuthState object.
// It attempts to bind the JSON payload from the Context to a JSONRequest object.
// If there is an error in the binding process, it sets the error type to "gin.ErrorTypeBind" and returns.
// Otherwise, it calls the setAuthenticationFields function with the AuthState object and the JSONRequest object,
// and sets additional fields in the AuthState object using the XSSL method.
func processApplicationJSON(ctx *gin.Context, auth State) {
	if stop := stats.PrometheusTimer(definitions.PromRequest, "request_json_decode_total"); stop != nil {
		defer stop()
	}

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
	authState, ok := auth.(*AuthState)
	if !ok {
		return
	}

	creds := NewCredentials(buildCredentialOptions(request)...)
	authState.ApplyCredentials(creds)

	ctxData := NewAuthContext(buildAuthContextOptions(request)...)
	authState.ApplyContextData(ctxData)
}

// buildCredentialOptions creates credential options from the request.
func buildCredentialOptions(request *authdto.Request) []CredentialOption {
	var opts []CredentialOption

	if request.Username != "" {
		opts = append(opts, WithUsername(request.Username))
	}

	if request.Password != "" {
		opts = append(opts, WithPassword(request.Password))
	}

	return opts
}

// buildAuthContextOptions creates authentication context options from the request.
func buildAuthContextOptions(request *authdto.Request) []AuthContextOption {
	// Map of request field values to their corresponding option constructors
	fieldMappings := []struct {
		value  string
		option func(string) AuthContextOption
	}{
		{request.Method, WithMethod},
		{request.UserAgent, WithUserAgent},
		{request.ClientID, WithClientID},
		{request.ClientIP, WithClientIP},
		{request.ClientPort, WithClientPort},
		{request.ClientHostname, WithClientHostname},
		{request.LocalIP, WithLocalIP},
		{request.LocalPort, WithLocalPort},
		{request.Protocol, WithProtocol},
		{request.XSSL, WithXSSL},
		{request.XSSLSessionID, WithXSSLSessionID},
		{request.XSSLClientVerify, WithXSSLClientVerify},
		{request.XSSLClientDN, WithXSSLClientDN},
		{request.XSSLClientCN, WithXSSLClientCN},
		{request.XSSLIssuer, WithXSSLIssuer},
		{request.XSSLClientNotBefore, WithXSSLClientNotBefore},
		{request.XSSLClientNotAfter, WithXSSLClientNotAfter},
		{request.XSSLSubjectDN, WithXSSLSubjectDN},
		{request.XSSLIssuerDN, WithXSSLIssuerDN},
		{request.XSSLClientSubjectDN, WithXSSLClientSubjectDN},
		{request.XSSLClientIssuerDN, WithXSSLClientIssuerDN},
		{request.XSSLProtocol, WithXSSLProtocol},
		{request.XSSLCipher, WithXSSLCipher},
		{request.SSLSerial, WithSSLSerial},
		{request.SSLFingerprint, WithSSLFingerprint},
		{request.OIDCCID, WithOIDCCID},
	}

	var opts []AuthContextOption

	for _, mapping := range fieldMappings {
		if mapping.value != "" {
			opts = append(opts, mapping.option(mapping.value))
		}
	}

	return opts
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
	if a.Method == "" {
		a.Method = ""
	}

	if a.UserAgent == "" {
		a.UserAgent = ""
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
	if stop := stats.PrometheusTimer(definitions.PromRequest, "request_setup_total"); stop != nil {
		defer stop()
	}

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
	// Setup tracing
	tr := monittrace.New("nauthilus/auth")
	tctx, tsp := tr.Start(ctx.Request.Context(), "auth.setup",
		attribute.String("service", ctx.GetString(definitions.CtxServiceKey)),
		attribute.String("method", ctx.Request.Method),
	)

	defer tsp.End()

	// Propagate tracing context downwards for any callee that reads request context
	ctx.Request = ctx.Request.WithContext(tctx)

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

// NewAuthStateWithSetupWithDeps is the dependency-injected variant of NewAuthStateWithSetup.
// Call this from request boundaries that already have explicit deps available.
func NewAuthStateWithSetupWithDeps(ctx *gin.Context, deps AuthDeps) State {
	// Setup tracing
	tr := monittrace.New("nauthilus/auth")
	tctx, tsp := tr.Start(ctx.Request.Context(), "auth.setup",
		attribute.String("service", ctx.GetString(definitions.CtxServiceKey)),
		attribute.String("method", ctx.Request.Method),
	)

	defer tsp.End()

	// Propagate tracing context downwards for any callee that reads request context
	ctx.Request = ctx.Request.WithContext(tctx)

	auth := NewAuthStateFromContextWithDeps(ctx, deps)

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
	return NewAuthStateFromContextWithDeps(ctx, AuthDeps{
		Cfg:    getDefaultConfigFile(),
		Env:    getDefaultEnvironment(),
		Logger: getDefaultLogger(),
		Redis:  getDefaultRedisClient(),
	})
}

// NewAuthStateFromContextWithDeps initializes and returns an AuthState using the provided gin.Context and explicit deps.
func NewAuthStateFromContextWithDeps(ctx *gin.Context, deps AuthDeps) State {
	auth := &AuthState{
		deps:              deps,
		StartTime:         time.Now(),
		HTTPClientContext: ctx,
		HTTPClientRequest: ctx.Request,
	}

	return auth
}

// WithDefaults sets default values for the AuthState structure including the GUID session value.
func (a *AuthState) WithDefaults(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	a.GUID = ctx.GetString(definitions.CtxGUIDKey)
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

	cfg := a.cfg()
	a.XLocalIP = ctx.GetHeader(cfg.GetLocalIP())
	a.XPort = ctx.GetHeader(cfg.GetLocalPort())

	return a
}

// postResolvDNS resolves the client IP to a host name if DNS client IP resolution is enabled in the configuration.
func (a *AuthState) postResolvDNS(ctx *gin.Context) {
	if a.cfg().GetServer().GetDNS().GetResolveClientIP() {
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

	cfg := a.cfg()
	a.OIDCCID = ctx.GetHeader(cfg.GetOIDCCID())
	a.ClientIP = ctx.GetHeader(cfg.GetClientIP())
	a.XClientPort = ctx.GetHeader(cfg.GetClientPort())
	a.XClientID = ctx.GetHeader(cfg.GetClientID())
	a.ClientHost = ctx.GetHeader(cfg.GetClientHost())

	if a.ClientIP == "" {
		// This might be valid if HAproxy v2 support is enabled
		if cfg.GetServer().IsHAproxyProtocolEnabled() {
			a.ClientIP, a.XClientPort, err = net.SplitHostPort(ctx.Request.RemoteAddr)
			if err != nil {
				level.Error(a.logger()).Log(
					definitions.LogKeyGUID, a.GUID,
					definitions.LogKeyMsg, "Failed to split client IP and port",
					definitions.LogKeyError, err,
				)
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

	a.UserAgent = ctx.Request.UserAgent()

	return a
}

// WithXSSL adds HAProxy header processing to the AuthState structure.
func (a *AuthState) WithXSSL(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	h := a.cfg().GetServer().GetDefaultHTTPRequestHeader()
	a.XSSL = ctx.GetHeader(h.GetSSL())
	a.XSSLSessionID = ctx.GetHeader(h.GetSSLSessionID())
	a.XSSLClientVerify = ctx.GetHeader(h.GetSSLVerify())
	a.XSSLClientDN = ctx.GetHeader(h.GetSSLSubject())
	a.XSSLClientCN = ctx.GetHeader(h.GetSSLClientCN())
	a.XSSLIssuer = ctx.GetHeader(h.GetSSLIssuer())
	a.XSSLClientNotBefore = ctx.GetHeader(h.GetSSLClientNotBefore())
	a.XSSLClientNotAfter = ctx.GetHeader(h.GetSSLClientNotAfter())
	a.XSSLSubjectDN = ctx.GetHeader(h.GetSSLSubjectDN())
	a.XSSLIssuerDN = ctx.GetHeader(h.GetSSLIssuerDN())
	a.XSSLClientSubjectDN = ctx.GetHeader(h.GetSSLClientSubjectDN())
	a.XSSLClientIssuerDN = ctx.GetHeader(h.GetSSLClientIssuerDN())
	a.XSSLCipher = ctx.GetHeader(h.GetSSLCipher())
	a.XSSLProtocol = ctx.GetHeader(h.GetSSLProtocol())
	a.SSLSerial = ctx.GetHeader(h.GetSSLSerial())
	a.SSLFingerprint = ctx.GetHeader(h.GetSSLFingerprint())

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
// Fields: service, protocol, username, client_ip, local_ip, local_port, ssl_flag, [oidcCID], pw_short
func (a *AuthState) generateSingleflightKey() string {
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
	base := a.Service + sep + a.Protocol.Get() + sep + a.Username + sep + clientIP + sep + a.XLocalIP + sep + a.XPort + sep + sslFlag

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
	tr := monittrace.New("nauthilus/auth")
	lcCtx, lcSpan := tr.Start(a.Ctx(), "auth.local_cache",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
	)

	_ = lcCtx

	defer lcSpan.End()

	if a.HaveMonitoringFlag(definitions.MonInMemory) {
		lcSpan.SetAttributes(attribute.Bool("skipped", true))

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

		lcSpan.SetAttributes(
			attribute.Bool("hit", true),
			attribute.String("backend", definitions.BackendLocalCache.String()),
		)

		return found
	} else {
		lcSpan.SetAttributes(attribute.Bool("hit", false))

		return false
	}
}

// PreproccessAuthRequest preprocesses the authentication request by checking if the request is already in the local cache.
// If not found in the cache, it checks if the request is a brute force attack and updates the brute force counter.
// It then performs a post Lua action and triggers a failed authentication response.
// If a brute force attack is detected, it returns true, otherwise false.
func (a *AuthState) PreproccessAuthRequest(ctx *gin.Context) (reject bool) {
	tr := monittrace.New("nauthilus/auth")
	pctx, pspan := tr.Start(ctx.Request.Context(), "auth.features",
		attribute.String("service", a.Service),
		attribute.String("username", a.Username),
	)

	// propagate for any nested calls
	ctx.Request = ctx.Request.WithContext(pctx)

	var cacheHit bool
	if found := a.GetFromLocalCache(ctx); !found {
		stats.GetMetrics().GetCacheMisses().Inc()

		if a.CheckBruteForce(ctx) {
			pspan.SetAttributes(attribute.Bool("bruteforce.blocked", true))
			a.UpdateBruteForceBucketsCounter(ctx)
			result := GetPassDBResultFromPool()
			a.PostLuaAction(result)
			PutPassDBResultToPool(result)
			a.AuthFail(ctx)

			pspan.SetAttributes(attribute.Bool("reject", true))
			pspan.End()

			return true
		}
	} else {
		stats.GetMetrics().GetCacheHits().Inc()

		cacheHit = true
	}

	pspan.SetAttributes(attribute.Bool("cache.hit", cacheHit))
	pspan.End()

	return false
}

// ApplyCredentials applies non-empty credential fields to the AuthState.
func (a *AuthState) ApplyCredentials(c Credentials) {
	if a == nil {
		return
	}

	if c.Username != "" {
		a.Username = c.Username
	}

	if c.Password != "" {
		a.Password = c.Password
	}

	// Note: TOTP/TOTPRecovery are intentionally not mapped here to avoid
	// behavior changes. They will be integrated in later phases when MFA
	// input wiring is introduced.
}

// ApplyContextData applies non-empty request/connection metadata to AuthState.
// Only fields provided (non-empty) are applied to preserve existing precedence.
func (a *AuthState) ApplyContextData(x AuthContext) {
	if a == nil {
		return
	}

	// Field mappings for simple string assignments
	fieldMappings := []struct {
		src  string
		dest *string
	}{
		{x.Method, &a.Method},
		{x.UserAgent, &a.UserAgent},
		{x.ClientIP, &a.ClientIP},
		{x.ClientPort, &a.XClientPort},
		{x.ClientHostname, &a.ClientHost},
		{x.ClientID, &a.XClientID},
		{x.LocalIP, &a.XLocalIP},
		{x.LocalPort, &a.XPort},
		{x.XSSL, &a.XSSL},
		{x.XSSLSessionID, &a.XSSLSessionID},
		{x.XSSLClientVerify, &a.XSSLClientVerify},
		{x.XSSLClientDN, &a.XSSLClientDN},
		{x.XSSLClientCN, &a.XSSLClientCN},
		{x.XSSLIssuer, &a.XSSLIssuer},
		{x.XSSLClientNotBefore, &a.XSSLClientNotBefore},
		{x.XSSLClientNotAfter, &a.XSSLClientNotAfter},
		{x.XSSLSubjectDN, &a.XSSLSubjectDN},
		{x.XSSLIssuerDN, &a.XSSLIssuerDN},
		{x.XSSLClientSubjectDN, &a.XSSLClientSubjectDN},
		{x.XSSLClientIssuerDN, &a.XSSLClientIssuerDN},
		{x.XSSLProtocol, &a.XSSLProtocol},
		{x.XSSLCipher, &a.XSSLCipher},
		{x.SSLSerial, &a.SSLSerial},
		{x.SSLFingerprint, &a.SSLFingerprint},
		{x.OIDCCID, &a.OIDCCID},
	}

	// Apply all string field mappings
	for _, mapping := range fieldMappings {
		util.ApplyStringField(mapping.src, mapping.dest)
	}

	// Handle Protocol specially as it requires type conversion
	if x.Protocol != "" {
		a.SetProtocol(config.NewProtocol(x.Protocol))
	}
}
