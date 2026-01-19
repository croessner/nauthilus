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
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
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

	// GetUniqueUserIDOk returns the unique user identifier and a boolean indicating its presence.
	GetUniqueUserIDOk() (string, bool)

	// GetDisplayNameOk returns the user display name and a boolean indicating its presence.
	GetDisplayNameOk() (string, bool)

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

	// GetAttributesCopy returns a deep copy of the attributes map.
	GetAttributesCopy() bktype.AttributeMapping

	// GetAdditionalLogs retrieves a slice of additional log entries, useful for appending context-specific logging details.
	GetAdditionalLogs() []any

	// GetClientIP retrieves the client's IP address associated with the current authentication or request context.
	GetClientIP() string

	// GetLogger returns the injected logger for this state.
	GetLogger() *slog.Logger

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
	PostLuaAction(ctx *gin.Context, passDBResult *PassDBResult)

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

	// AccountCache returns the AccountCache manager.
	AccountCache() *accountcache.Manager

	// Channel returns the backend channel.
	Channel() backend.Channel

	// GetOauth2SubjectAndClaims retrieves the subject and claims for OAuth2/OIDC.
	GetOauth2SubjectAndClaims(client any) (string, map[string]any)
}

// AuthRequest holds data directly extracted from the HTTP request or connection metadata.
type AuthRequest struct {
	// Protocol is the protocol used for the request.
	Protocol *config.Protocol

	// HTTPClientContext is the Gin context associated with the request.
	HTTPClientContext *gin.Context

	// HTTPClientRequest is the HTTP request being processed.
	HTTPClientRequest *http.Request

	// Method is the authentication method.
	Method string

	// Username is the name of the user attempting to authenticate.
	Username string

	// Password is the user's password.
	Password string

	// ClientIP is the IP address of the client making the request.
	ClientIP string

	// XClientPort is the port number of the client.
	XClientPort string

	// ClientHost is the hostname of the client.
	ClientHost string

	// UserAgent is the user agent string of the client.
	UserAgent string

	// Service is the name of the service being accessed.
	Service string

	// OIDCCID is the OIDC client ID.
	OIDCCID string

	// XSSL indicates whether the connection is SSL/TLS.
	XSSL string // %[ssl_fc]

	// XSSLSessionID is the SSL session ID.
	XSSLSessionID string // %[ssl_fc_session_id,hex]

	// XSSLClientVerify indicates the status of client certificate verification.
	XSSLClientVerify string // %[ssl_c_verify]

	// XSSLClientDN is the distinguished name of the client certificate.
	XSSLClientDN string // %{+Q}[ssl_c_s_dn]

	// XSSLClientCN is the common name of the client certificate.
	XSSLClientCN string // %{+Q}[ssl_c_s_dn(cn)]

	// XSSLIssuer is the issuer of the client certificate.
	XSSLIssuer string // %{+Q}[ssl_c_i_dn]

	// XSSLClientNotBefore is the "Not Before" date of the client certificate.
	XSSLClientNotBefore string // %{+Q}[ssl_c_notbefore]

	// XSSLClientNotAfter is the "Not After" date of the client certificate.
	XSSLClientNotAfter string // %{+Q}[ssl_c_notafter]

	// XSSLSubjectDN is the subject DN of the server certificate.
	XSSLSubjectDN string // %{+Q}[ssl_c_s_dn]

	// XSSLIssuerDN is the issuer DN of the server certificate.
	XSSLIssuerDN string // %{+Q}[ssl_c_i_dn]

	// XSSLClientSubjectDN is the subject DN of the client certificate.
	XSSLClientSubjectDN string // %{+Q}[ssl_c_s_dn]

	// XSSLClientIssuerDN is the issuer DN of the client certificate.
	XSSLClientIssuerDN string // %{+Q}[ssl_c_i_dn]

	// XSSLProtocol is the SSL/TLS protocol version.
	XSSLProtocol string // %[ssl_fc_protocol]

	// XSSLCipher is the SSL/TLS cipher suite used.
	XSSLCipher string // %[ssl_fc_cipher]

	// SSLSerial is the serial number of the SSL certificate.
	SSLSerial string

	// SSLFingerprint is the fingerprint of the SSL certificate.
	SSLFingerprint string

	// XClientID is a custom client identifier.
	XClientID string

	// XLocalIP is the local IP address on which the request was received.
	XLocalIP string

	// XPort is the local port number on which the request was received.
	XPort string

	// NoAuth indicates whether authentication should be skipped.
	NoAuth bool

	// ListAccounts indicates whether to list available accounts.
	ListAccounts bool
}

// AuthRuntime holds process-related data generated or tracked during the authentication request.
type AuthRuntime struct {
	// StartTime is the time when the authentication request started.
	StartTime time.Time

	// AdditionalLogs contains additional log entries for the request.
	AdditionalLogs []any

	// MonitoringFlags holds flags related to request monitoring.
	MonitoringFlags []definitions.Monitoring

	// GUID is a unique identifier for the authentication request.
	GUID string

	// StatusMessage is a message describing the status of the request.
	StatusMessage string

	// AccountField is the name of the field containing the account information.
	AccountField string

	// AccountName is the name of the account being authenticated.
	AccountName string

	// FeatureName is the name of the feature being accessed.
	FeatureName string

	// BackendName is the name of the backend used for authentication.
	BackendName string

	// UsedBackendIP is the IP address of the backend server used.
	UsedBackendIP string

	// TOTPSecret is the secret used for TOTP authentication.
	TOTPSecret string

	// TOTPSecretField is the field name containing the TOTP secret.
	TOTPSecretField string

	// TOTPRecoveryField is the field name containing the TOTP recovery codes.
	TOTPRecoveryField string

	// UniqueUserIDField is the field name containing the unique user ID.
	UniqueUserIDField string

	// DisplayNameField is the field name containing the user's display name.
	DisplayNameField string

	// BFClientNet is the network address used for brute-force detection.
	BFClientNet string

	// AdditionalFeatures contains additional feature-specific data.
	AdditionalFeatures map[string]any

	// Context is the Lua context associated with the request.
	Context *lualib.Context

	// UsedBackendPort is the port number of the backend server used.
	UsedBackendPort int

	// StatusCodeOK is the HTTP status code for a successful request.
	StatusCodeOK int

	// StatusCodeInternalError is the HTTP status code for an internal server error.
	StatusCodeInternalError int

	// StatusCodeFail is the HTTP status code for a failed authentication.
	StatusCodeFail int

	// SourcePassDBBackend is the source password database backend.
	SourcePassDBBackend definitions.Backend

	// UsedPassDBBackend is the password database backend actually used.
	UsedPassDBBackend definitions.Backend

	// UserFound indicates whether the user was found in the backend.
	UserFound bool

	// Authenticated indicates whether the user was successfully authenticated.
	Authenticated bool

	// Authorized indicates whether the user is authorized for the request.
	Authorized bool

	// BFRepeating indicates whether brute-force detection is repeating.
	BFRepeating bool

	// MasterUserMode indicates whether the request is in master user mode.
	MasterUserMode bool
}

// AuthSecurity manages counters, managers and history related to brute-force and security.
type AuthSecurity struct {
	// Tolerate is the brute-force tolerance configuration.
	Tolerate tolerate.Tolerate

	// BruteForceName is the name of the brute-force protection profile.
	BruteForceName string

	// BruteForceCounter keeps track of brute-force attempts.
	BruteForceCounter map[string]uint

	// PasswordHistory maintains the history of password attempts.
	PasswordHistory *bruteforce.PasswordHistory

	// attempts manages the login attempts.
	attempts *defaultLoginAttemptManager

	// Logs contains custom log entries.
	Logs *lualib.CustomLogKeyValue

	// PasswordsAccountSeen is the number of passwords seen for the account.
	PasswordsAccountSeen uint

	// PasswordsTotalSeen is the total number of passwords seen.
	PasswordsTotalSeen uint

	// LoginAttempts is the number of login attempts made.
	LoginAttempts uint
}

// AuthAttributes handles user attributes and their synchronization.
type AuthAttributes struct {
	// Attributes is a map of user attributes retrieved from the backend.
	Attributes bktype.AttributeMapping

	// attributesMu is a mutex for thread-safe access to Attributes.
	attributesMu sync.RWMutex
}

// AuthState represents a struct that holds information related to an authentication process.
type AuthState struct {
	// deps holds the injected runtime dependencies for this auth request.
	// It must be initialized by the request-boundary constructor.
	deps AuthDeps

	// Request holds data directly extracted from the HTTP request or connection metadata.
	Request AuthRequest

	// Runtime holds process-related data generated or tracked during the authentication request.
	Runtime AuthRuntime

	// Security manages counters, managers and history related to brute-force and security.
	Security AuthSecurity

	// Attributes handles user attributes and their synchronization.
	Attributes AuthAttributes
}

func (a *AuthState) Cfg() config.File {
	return a.deps.Cfg
}

func (a *AuthState) Env() config.Environment {
	return a.deps.Env
}

func (a *AuthState) Logger() *slog.Logger {
	return a.deps.Logger
}

func (a *AuthState) Redis() rediscli.Client {
	return a.deps.Redis
}

func (a *AuthState) cfg() config.File {
	return a.Cfg()
}

func (a *AuthState) env() config.Environment {
	return a.Env()
}

func (a *AuthState) logger() *slog.Logger {
	return a.Logger()
}

func (a *AuthState) redis() rediscli.Client {
	return a.Redis()
}

func (a *AuthState) AccountCache() *accountcache.Manager {
	return a.deps.AccountCache
}

func (a *AuthState) Channel() backend.Channel {
	return a.deps.Channel
}

func (a *AuthState) GetLogger() *slog.Logger {
	return a.deps.Logger
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

	// Account is the actual account name of the user.
	Account string

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
	p.Account = ""
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

// Clone creates a deep copy of the PassDBResult.
// It retrieves a new object from the pool and populates it.
func (p *PassDBResult) Clone() *PassDBResult {
	if p == nil {
		return nil
	}

	res := GetPassDBResultFromPool()
	res.Authenticated = p.Authenticated
	res.UserFound = p.UserFound
	res.BackendName = p.BackendName
	res.AccountField = p.AccountField
	res.Account = p.Account
	res.TOTPSecretField = p.TOTPSecretField
	res.TOTPRecoveryField = p.TOTPRecoveryField
	res.UniqueUserIDField = p.UniqueUserIDField
	res.DisplayNameField = p.DisplayNameField
	res.Backend = p.Backend
	res.Attributes = p.Attributes.Clone()

	if p.AdditionalFeatures != nil {
		res.AdditionalFeatures = make(map[string]any, len(p.AdditionalFeatures))
		for k, v := range p.AdditionalFeatures {
			res.AdditionalFeatures[k] = v
		}
	}

	return res
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
	var result strings.Builder

	value := reflect.ValueOf(*a)
	typeOfValue := value.Type()

	for index := range value.NumField() {
		switch typeOfValue.Field(index).Name {
		case "GUID":
			continue
		case "Password":
			if getDefaultEnvironment().GetDevMode() {
				fmt.Fprintf(&result, " %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
			} else {
				fmt.Fprintf(&result, " %s='<hidden>'", typeOfValue.Field(index).Name)
			}
		default:
			fmt.Fprintf(&result, " %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	if result.Len() == 0 {
		return ""
	}

	return result.String()[1:]
}

// SetUsername sets the username for the AuthState instance to the given value.
func (a *AuthState) SetUsername(username string) {
	a.Request.Username = username
}

// SetPassword sets the password for the AuthState instance.
func (a *AuthState) SetPassword(password string) {
	a.Request.Password = password
}

// SetClientIP sets the client's IP address in the AuthState structure.
func (a *AuthState) SetClientIP(clientIP string) {
	a.Request.ClientIP = clientIP
}

// SetClientPort sets the client's port information to the provided clientPort value.
func (a *AuthState) SetClientPort(clientPort string) {
	a.Request.XClientPort = clientPort
}

// SetClientHost sets the client host value in the AuthState instance.
func (a *AuthState) SetClientHost(clientHost string) {
	a.Request.ClientHost = clientHost
}

// SetClientID sets the client ID for the authentication state using the provided clientID string.
func (a *AuthState) SetClientID(clientID string) {
	a.Request.XClientID = clientID
}

// SetSSLSessionID sets the SSL session ID for the AuthState instance.
func (a *AuthState) SetSSLSessionID(sslSessionID string) {
	a.Request.XSSLSessionID = sslSessionID
}

// SetSSLClientVerify sets the SSL client verification value for the AuthState.
func (a *AuthState) SetSSLClientVerify(sslClientVerify string) {
	a.Request.XSSLClientVerify = sslClientVerify
}

// SetSSLClientDN sets the distinguished name (DN) of the SSL client in the AuthState struct.
func (a *AuthState) SetSSLClientDN(sslClientDN string) {
	a.Request.XSSLClientDN = sslClientDN
}

// SetSSLClientCN sets the value of the SSL client common name (CN) for the AuthState instance.
func (a *AuthState) SetSSLClientCN(sslClientCN string) {
	a.Request.XSSLClientCN = sslClientCN
}

// SetSSLIssuer sets the issuer for the XSSL certificate in the AuthState.
func (a *AuthState) SetSSLIssuer(xSSLIssuer string) {
	a.Request.XSSLIssuer = xSSLIssuer
}

// SetSSLClientNotBefore sets the SSL client certificate's "Not Before" value in the AuthState.
func (a *AuthState) SetSSLClientNotBefore(sslClientNotBefore string) {
	a.Request.XSSLClientNotBefore = sslClientNotBefore
}

// SetSSLClientNotAfter sets the XSSLClientNotAfter field with the provided SSL client expiration date.
func (a *AuthState) SetSSLClientNotAfter(sslClientNotAfter string) {
	a.Request.XSSLClientNotAfter = sslClientNotAfter
}

// SetSSLSubjectDN sets the SSL subject distinguished name to the provided string value.
func (a *AuthState) SetSSLSubjectDN(sslSubjectDN string) {
	a.Request.XSSLSubjectDN = sslSubjectDN
}

// SetSSLIssuerDN sets the X.509 SSL issuer distinguished name for the AuthState.
func (a *AuthState) SetSSLIssuerDN(xSSLIssuerDN string) {
	a.Request.XSSLIssuerDN = xSSLIssuerDN
}

// SetSSLClientSubjectDN sets the subject distinguished name (DN) for the SSL client in the AuthState object.
func (a *AuthState) SetSSLClientSubjectDN(sslClientSubjectDN string) {
	a.Request.XSSLClientSubjectDN = sslClientSubjectDN
}

// SetSSLClientIssuerDN sets the SSL client issuer distinguished name for the authentication state.
func (a *AuthState) SetSSLClientIssuerDN(sslClientIssuerDN string) {
	a.Request.XSSLClientIssuerDN = sslClientIssuerDN
}

// SetSSLCipher sets the SSL cipher suite for the current authentication state.
func (a *AuthState) SetSSLCipher(sslCipher string) {
	a.Request.XSSLCipher = sslCipher
}

// SetSSLSerial sets the SSL serial number for the AuthState instance.
func (a *AuthState) SetSSLSerial(sslSerial string) {
	a.Request.SSLSerial = sslSerial
}

// SetSSLFingerprint sets the SSL fingerprint for the AuthState instance. It updates the SSLFingerprint field with the provided value.
func (a *AuthState) SetSSLFingerprint(sslFingerprint string) {
	a.Request.SSLFingerprint = sslFingerprint
}

// SetOIDCCID sets the OIDC Client ID for the AuthState instance. It updates the OIDCCID field with the provided value.
func (a *AuthState) SetOIDCCID(oidcCID string) {
	a.Request.OIDCCID = oidcCID
}

// SetNoAuth configures the authentication state to enable or disable "NoAuth" mode based on the provided boolean value.
func (a *AuthState) SetNoAuth(noAuth bool) {
	a.Request.NoAuth = noAuth
}

// SetProtocol sets the protocol for the AuthState using the given Protocol configuration.
func (a *AuthState) SetProtocol(protocol *config.Protocol) {
	a.Request.Protocol = protocol
}

// SetLoginAttempts sets the number of login attempts for the AuthState instance.
func (a *AuthState) SetLoginAttempts(loginAttempts uint) {
	a.Security.LoginAttempts = loginAttempts
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

	return a.Security.LoginAttempts
}

// SetMethod sets the authentication method for the AuthState instance by assigning it to the Method field.
func (a *AuthState) SetMethod(method string) {
	a.Request.Method = method
}

// SetUserAgent sets the UserAgent field for the AuthState with the provided userAgent value.
func (a *AuthState) SetUserAgent(userAgent string) {
	a.Request.UserAgent = userAgent
}

// SetLocalIP sets the local IP address for the AuthState instance.
func (a *AuthState) SetLocalIP(localIP string) {
	a.Request.XLocalIP = localIP
}

// SetLocalPort sets the local port for the AuthState instance to the given port string.
func (a *AuthState) SetLocalPort(port string) {
	a.Request.XPort = port
}

// SetSSL sets the XSSL property of the AuthState to the provided SSL value.
func (a *AuthState) SetSSL(ssl string) {
	a.Request.XSSL = ssl
}

// SetSSLProtocol sets the SSL protocol version to be used for the connection by updating the XSSLProtocol field.
func (a *AuthState) SetSSLProtocol(sslProtocol string) {
	a.Request.XSSLProtocol = sslProtocol
}

// GetGUID retrieves the GUID from the AuthState. Returns an empty string if the GUID is nil.
func (a *AuthState) GetGUID() string {
	return a.Runtime.GUID
}

// GetUsername retrieves the username from the AuthState structure.
func (a *AuthState) GetUsername() string {
	return a.Request.Username
}

// GetPassword retrieves the password stored in the AuthState instance. It returns the password as a string.
func (a *AuthState) GetPassword() string {
	return a.Request.Password
}

// GetProtocol retrieves the configured Protocol for the AuthState. If no Protocol is set, it returns a default Protocol instance.
func (a *AuthState) GetProtocol() *config.Protocol {
	if a.Request.Protocol == nil {
		a.Request.Protocol = &config.Protocol{}
	}

	return a.Request.Protocol
}

// GetTOTPSecretField retrieves the TOTP secret field from the AuthState. Returns an empty string if the field is nil.
func (a *AuthState) GetTOTPSecretField() string {
	return a.Runtime.TOTPSecretField
}

// GetTOTPRecoveryField retrieves the TOTP recovery field value from AuthState. Returns an empty string if not set.
func (a *AuthState) GetTOTPRecoveryField() string {
	return a.Runtime.TOTPRecoveryField
}

// GetUniqueUserIDField retrieves the value of the UniqueUserIDField if set; returns an empty string otherwise.
func (a *AuthState) GetUniqueUserIDField() string {
	return a.Runtime.UniqueUserIDField
}

// GetDisplayNameField retrieves the display name field from the AuthState. Returns an empty string if it's nil.
func (a *AuthState) GetDisplayNameField() string {
	return a.Runtime.DisplayNameField
}

// GetUsedPassDBBackend returns the currently used backend for password database operations.
func (a *AuthState) GetUsedPassDBBackend() definitions.Backend {
	return a.Runtime.UsedPassDBBackend
}

// GetAttributes retrieves the stored database attributes from the AuthState and returns them as a AttributeMapping.
func (a *AuthState) GetAttributes() bktype.AttributeMapping {
	return a.Attributes.Attributes
}

// GetAttributesCopy returns a deep copy of the Attributes map to avoid aliasing across components.
// The copy is made under a read lock; callers may safely mutate the returned map.
func (a *AuthState) GetAttributesCopy() bktype.AttributeMapping {
	a.Attributes.attributesMu.RLock()
	defer a.Attributes.attributesMu.RUnlock()

	if a.Attributes.Attributes == nil {
		return nil
	}

	cp := make(bktype.AttributeMapping, len(a.Attributes.Attributes))
	for k, v := range a.Attributes.Attributes {
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

	a.Attributes.attributesMu.Lock()
	if a.Attributes.Attributes != nil {
		delete(a.Attributes.Attributes, name)
	}

	a.Attributes.attributesMu.Unlock()
}

// SetAttributeIfAbsent sets the attribute to a single-value slice if it does not exist yet.
// This mirrors typical usage where scripts want to add an attribute only when missing.
// It allocates the Attributes map lazily and is concurrency-safe.
func (a *AuthState) SetAttributeIfAbsent(name string, value any) {
	if a == nil || name == "" {
		return
	}

	a.Attributes.attributesMu.Lock()
	if a.Attributes.Attributes == nil {
		a.Attributes.Attributes = make(bktype.AttributeMapping)
	}

	if _, ok := a.Attributes.Attributes[name]; !ok {
		a.Attributes.Attributes[name] = []any{value}
	}

	a.Attributes.attributesMu.Unlock()
}

// ReplaceAllAttributes replaces the entire Attributes map with a deep copy of the provided map, under write lock.
// Passing nil will set Attributes to nil.
func (a *AuthState) ReplaceAllAttributes(m bktype.AttributeMapping) {
	a.Attributes.attributesMu.Lock()
	defer a.Attributes.attributesMu.Unlock()

	if m == nil {
		a.Attributes.Attributes = nil

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

	a.Attributes.Attributes = cp
}

// GetAttribute returns the attribute slice and a boolean indicating presence, under a read lock.
func (a *AuthState) GetAttribute(name string) ([]any, bool) {
	a.Attributes.attributesMu.RLock()
	defer a.Attributes.attributesMu.RUnlock()

	if a.Attributes.Attributes == nil {
		return nil, false
	}

	v, ok := a.Attributes.Attributes[name]

	return v, ok
}

// RangeAttributes iterates over all attributes under a read lock and calls fn for each key/value.
// If fn returns false, iteration stops early.
func (a *AuthState) RangeAttributes(fn func(string, []any) bool) {
	a.Attributes.attributesMu.RLock()
	defer a.Attributes.attributesMu.RUnlock()
	for k, v := range a.Attributes.Attributes {
		if !fn(k, v) {
			return
		}
	}
}

// GetAdditionalLogs returns a slice of additional logs associated with the AuthState instance.
func (a *AuthState) GetAdditionalLogs() []any {
	return a.Runtime.AdditionalLogs
}

// GetClientIP returns the client's IP address stored in the AuthState instance.
func (a *AuthState) GetClientIP() string {
	return a.Request.ClientIP
}

// GetAccount returns the account value from the AuthState object. If the account field is not set or the account
// value is not found in the attributes, an empty string is returned
func (a *AuthState) GetAccount() string {
	if a == nil {
		return ""
	}

	if a.Runtime.AccountName != "" {
		return a.Runtime.AccountName
	}

	// Prefer value stored in the Gin context for the current request
	// to avoid redundant cache/Redis lookups within the same request.
	if a.Request.HTTPClientContext != nil {
		if v := a.Request.HTTPClientContext.GetString(definitions.CtxAccountKey); v != "" {
			return v
		}
	}

	if account, okay := a.GetAttribute(a.Runtime.AccountField); okay {
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
	a.Security.LoginAttempts = lam.FailCount()
}

// SyncLoginAttemptsFromBucket updates the internal login attempt manager from a
// brute-force bucket value and mirrors the FailCount to the legacy field.
// The bucket is considered authoritative over header hints.
func (a *AuthState) SyncLoginAttemptsFromBucket(counter uint) {
	lam := a.ensureLAM()
	if lam == nil {
		a.Security.LoginAttempts = counter

		return
	}

	lam.InitFromBucket(counter)
	a.Security.LoginAttempts = lam.FailCount()
}

// ResetLoginAttemptsOnSuccess resets the internal fail counter after a
// successful authentication. This affects only the in-process view; any
// persistent brute-force storage remains managed by the brute-force subsystem.
func (a *AuthState) ResetLoginAttemptsOnSuccess() {
	lam := a.ensureLAM()
	if lam == nil {
		a.Security.LoginAttempts = 0
		return
	}

	lam.OnAuthSuccess()
	a.Security.LoginAttempts = lam.FailCount()
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
	if a.Runtime.StatusMessage == "" {
		a.Runtime.StatusMessage = definitions.PasswordFail
	}

	ctx.Header("Auth-Status", a.Runtime.StatusMessage)
	ctx.Header("X-Nauthilus-Session", a.Runtime.GUID)

	switch a.Request.Service {
	case definitions.ServHeader, definitions.ServNginx, definitions.ServJSON:
		maxWaitDelay := viper.GetUint("nginx_wait_delay")

		if maxWaitDelay > 0 {
			waitDelay := bfWaitDelay(maxWaitDelay, a.Security.LoginAttempts)
			ctx.Header("Auth-Wait", fmt.Sprintf("%v", waitDelay))
		}

		// Do not include password history in responses; always return JSON null on failure
		ctx.JSON(a.Runtime.StatusCodeFail, nil)
	default:
		ctx.String(a.Runtime.StatusCodeFail, a.Runtime.StatusMessage)
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
	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	keyvals = a.fillLogLineTemplate(keyvals, "fail", ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Authentication request has failed")

	level.Notice(a.logger()).Log(keyvals...)

	stats.GetMetrics().GetRejectedProtocols().WithLabelValues(a.Request.Protocol.Get()).Inc()
	stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelFailure).Inc()
}

// setSMPTHeaders sets SMTP headers in the specified `gin.Context` if the `Service` is `ServNginx` and the `Protocol` is `ProtoSMTP`.
// It adds the `Auth-Error-Code` header with the value `TempFailCode` from the declaration package.
//
// Example usage:
//
//	a.setSMPTHeaders(ctx)
func (a *AuthState) setSMPTHeaders(ctx *gin.Context) {
	if a.Request.Service == definitions.ServNginx && a.Request.Protocol.Get() == definitions.ProtoSMTP {
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
		if strings.Count(a.Request.Username, delim) == 1 {
			parts := strings.Split(a.Request.Username, delim)
			if len(parts[0]) > 0 && len(parts[1]) > 0 {
				return true
			}
		}
	}

	return false
}

// IsInNetwork checks an IP address against a network and returns true if it matches.
func (a *AuthState) IsInNetwork(networkList []string) (matchIP bool) {
	return util.IsInNetworkWithCfg(a.Ctx(), a.Cfg(), a.Logger(), networkList, a.Runtime.GUID, a.Request.ClientIP)
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
			definitions.LogKeyGUID, auth.Runtime.GUID,
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
			definitions.LogKeyGUID, auth.Runtime.GUID,
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

	util.DebugModuleWithCfg(
		auth.Ctx(),
		auth.deps.Cfg,
		auth.deps.Logger,
		definitions.DbgAuth,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		"passdb", passDB.backend.String(),
		definitions.LogKeyUsername, auth.Request.Username,
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
		auth.Runtime.UserFound = true

		auth.Runtime.SourcePassDBBackend = passDBResult.Backend
		auth.Runtime.BackendName = passDBResult.BackendName
		if passDB != nil {
			auth.Runtime.UsedPassDBBackend = passDB.backend
		} else {
			auth.Runtime.UsedPassDBBackend = passDBResult.Backend
		}
	}

	if passDBResult.AccountField != "" {
		auth.Runtime.AccountField = passDBResult.AccountField
	}

	if passDBResult.Account != "" {
		auth.Runtime.AccountName = passDBResult.Account
	}

	if passDBResult.TOTPSecretField != "" {
		auth.Runtime.TOTPSecretField = passDBResult.TOTPSecretField
	}

	if passDBResult.UniqueUserIDField != "" {
		auth.Runtime.UniqueUserIDField = passDBResult.UniqueUserIDField
	}

	if passDBResult.DisplayNameField != "" {
		auth.Runtime.DisplayNameField = passDBResult.DisplayNameField
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
	if vals, ok := auth.GetAttribute(auth.Runtime.AccountField); ok {
		// We expect a single value string at LDAPSingleValue
		if acc, ok2 := vals[definitions.LDAPSingleValue].(string); ok2 && acc != "" {
			// Update the request-scoped context value and log source
			prev := ctx.GetString(definitions.CtxAccountKey)
			ctx.Set(definitions.CtxAccountKey, acc)

			util.DebugModuleWithCfg(
				auth.Ctx(),
				auth.deps.Cfg,
				auth.deps.Logger,
				definitions.DbgAccount,
				definitions.LogKeyGUID, auth.Runtime.GUID,
				definitions.LogKeyUsername, auth.Request.Username,
				definitions.LogKeyMsg, "Set account from attributes",
				"prev", prev,
				"new", acc,
				"source", "attribute",
				"changed", prev != acc,
			)

			// Keep Redis nt:USER mapping in sync when attribute-derived account differs.
			// Read the current mapping with a bounded read deadline.
			dReadCtx, cancelRead := util.GetCtxWithDeadlineRedisRead(auth.Ctx(), auth.Cfg())
			current, err := backend.LookupUserAccountFromRedis(dReadCtx, auth.Cfg(), auth.deps.Redis, auth.Request.Username)
			cancelRead()

			if err != nil {
				level.Error(auth.Logger()).Log(
					definitions.LogKeyGUID, auth.Runtime.GUID,
					definitions.LogKeyMsg, "Failed to lookup user->account mapping in Redis",
					definitions.LogKeyError, err,
				)
			} else if current == "" || current != acc {
				// Update Redis mapping with a bounded write deadline.
				defer stats.GetMetrics().GetRedisWriteCounter().Inc()

				dWriteCtx, cancelWrite := util.GetCtxWithDeadlineRedisWrite(nil, auth.Cfg())
				werr := backend.SetUserAccountMapping(dWriteCtx, auth.Cfg(), auth.deps.Redis, auth.Request.Username, acc)
				cancelWrite()

				if werr != nil {
					level.Error(auth.Logger()).Log(
						definitions.LogKeyGUID, auth.Runtime.GUID,
						definitions.LogKeyMsg, "Failed to update user->account mapping in Redis",
						definitions.LogKeyError, werr,
					)
				} else {
					util.DebugModuleWithCfg(
						auth.Ctx(),
						auth.deps.Cfg, auth.deps.Logger, definitions.DbgAccount,
						definitions.LogKeyGUID, auth.Runtime.GUID,
						definitions.LogKeyUsername, auth.Request.Username,
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
		a.Runtime.StatusCodeOK = http.StatusOK
		a.Runtime.StatusCodeInternalError = http.StatusOK
		a.Runtime.StatusCodeFail = http.StatusOK
	default:
		a.Runtime.StatusCodeOK = http.StatusOK
		a.Runtime.StatusCodeInternalError = http.StatusInternalServerError
		a.Runtime.StatusCodeFail = http.StatusForbidden
	}
}

// userExists checks if a user exists by looking up their account in Redis using the provided username.
// It returns true if the account name is found, otherwise false.
// An error is returned if there are issues during the Redis lookup.
func (a *AuthState) userExists() (bool, error) {
	accountName, err := backend.LookupUserAccountFromRedis(a.Ctx(), a.Cfg(), a.deps.Redis, a.Request.Username)
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
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(a.Ctx(), a.Cfg())
	accountName = backend.GetUserAccountFromCache(dCtx, a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Runtime.GUID)
	cancel()

	if accountName == "" {
		return
	}

	a.Runtime.AccountName = accountName

	return accountName
}

// FillCommonRequest populates a CommonRequest object from the current AuthState.
func (a *AuthState) FillCommonRequest(cr *lualib.CommonRequest) {
	if cr == nil {
		return
	}

	cr.Session = a.Runtime.GUID
	cr.Username = a.Request.Username
	cr.Password = a.Request.Password
	cr.ClientIP = a.Request.ClientIP
	cr.Account = a.GetAccount()
	cr.AccountField = a.Runtime.AccountField
	cr.UniqueUserID = a.GetUniqueUserID()
	cr.DisplayName = a.GetDisplayName()
	cr.Service = a.Request.Service
	cr.OIDCCID = a.Request.OIDCCID
	cr.Protocol = a.Request.Protocol.Get()
	cr.Method = a.Request.Method
	cr.ClientPort = a.Request.XClientPort
	cr.ClientNet = a.Runtime.BFClientNet
	cr.ClientHost = a.Request.ClientHost
	cr.ClientID = a.Request.XClientID
	cr.LocalIP = a.Request.XLocalIP
	cr.LocalPort = a.Request.XPort
	cr.UserAgent = a.Request.UserAgent
	cr.XSSL = a.Request.XSSL
	cr.XSSLSessionID = a.Request.XSSLSessionID
	cr.XSSLClientVerify = a.Request.XSSLClientVerify
	cr.XSSLClientDN = a.Request.XSSLClientDN
	cr.XSSLClientCN = a.Request.XSSLClientCN
	cr.XSSLIssuer = a.Request.XSSLIssuer
	cr.XSSLClientNotBefore = a.Request.XSSLClientNotBefore
	cr.XSSLClientNotAfter = a.Request.XSSLClientNotAfter
	cr.XSSLSubjectDN = a.Request.XSSLSubjectDN
	cr.XSSLIssuerDN = a.Request.XSSLIssuerDN
	cr.XSSLClientSubjectDN = a.Request.XSSLClientSubjectDN
	cr.XSSLClientIssuerDN = a.Request.XSSLClientIssuerDN
	cr.XSSLProtocol = a.Request.XSSLProtocol
	cr.XSSLCipher = a.Request.XSSLCipher
	cr.SSLSerial = a.Request.SSLSerial
	cr.SSLFingerprint = a.Request.SSLFingerprint
	cr.BackendServers = ListBackendServers()
	cr.UsedBackendAddr = &a.Runtime.UsedBackendIP
	cr.UsedBackendPort = &a.Runtime.UsedBackendPort
	cr.Latency = float64(time.Since(a.Runtime.StartTime).Milliseconds())
	cr.Debug = false
	cr.Repeating = a.Runtime.BFRepeating
	cr.NoAuth = a.Request.NoAuth
	cr.UserFound = a.Runtime.UserFound
	cr.Authenticated = a.Runtime.Authenticated
	cr.BruteForceName = a.Security.BruteForceName
	cr.FeatureName = a.Runtime.FeatureName
	cr.StatusMessage = &a.Runtime.StatusMessage

	if a.deps.Cfg != nil {
		cr.Debug = a.deps.Cfg.GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	}
}

// GetLoginAttempts returns the number of login attempts from the AuthState.
func (a *AuthState) GetLoginAttempts() uint {
	return a.Security.LoginAttempts
}

// GetPasswordsAccountSeen returns the count of passwords seen for the account.
func (a *AuthState) GetPasswordsAccountSeen() uint {
	return a.Security.PasswordsAccountSeen
}

// GetPasswordsTotalSeen returns the total count of passwords seen across all accounts.
func (a *AuthState) GetPasswordsTotalSeen() uint {
	return a.Security.PasswordsTotalSeen
}

// GetBruteForceCounter returns the brute force counter from the AuthState.
func (a *AuthState) GetBruteForceCounter() map[string]uint {
	return a.Security.BruteForceCounter
}

// GetBruteForceBucketRedisKey returns the Redis key for the specified brute force rule.
func (a *AuthState) GetBruteForceBucketRedisKey(rule *config.BruteForceRule) (key string) {
	if a == nil || a.deps.Cfg == nil {
		return ""
	}

	key = a.deps.Cfg.GetServer().GetRedis().GetPrefix() + definitions.RedisBruteForceHashKey + "{" + a.Request.ClientIP + "}:" + rule.Name

	return
}

// GetPasswordHistory returns the password history from the AuthState.
func (a *AuthState) GetPasswordHistory() *bruteforce.PasswordHistory {
	return a.Security.PasswordHistory
}

// GetFeatureName returns the feature name from the AuthState.
func (a *AuthState) GetFeatureName() string {
	return a.Runtime.FeatureName
}

// WithUsername sets the username in the AuthState.
func (a *AuthState) WithUsername(username string) bruteforce.BucketManager {
	a.Request.Username = username

	return a
}

// WithPassword sets the password in the AuthState.
func (a *AuthState) WithPassword(password string) bruteforce.BucketManager {
	a.Request.Password = password

	return a
}

// WithAccountName sets the account name in the AuthState.
func (a *AuthState) WithAccountName(accountName string) bruteforce.BucketManager {
	a.Runtime.AccountName = accountName

	return a
}

// WithProtocol sets the protocol in the AuthState.
func (a *AuthState) WithProtocol(protocol string) bruteforce.BucketManager {
	a.Request.Protocol.Set(protocol)

	return a
}

// WithOIDCCID sets the OIDC Client ID in the AuthState.
func (a *AuthState) WithOIDCCID(oidcCID string) bruteforce.BucketManager {
	a.Request.OIDCCID = oidcCID

	return a
}

// GetBruteForceName returns the brute force name from the AuthState.
func (a *AuthState) GetBruteForceName() string {
	return a.Security.BruteForceName
}

// LoadAllPasswordHistories loads all password histories for the current AuthState.
func (a *AuthState) LoadAllPasswordHistories() {
	if !a.deps.Cfg.HasFeature(definitions.FeatureBruteForce) {
		return
	}

	bm := a.createBucketManager(a.Ctx())
	bm.LoadAllPasswordHistories()
	a.Security.PasswordHistory = bm.GetPasswordHistory()
}

// CheckRepeatingBruteForcer checks for repeating brute force attacks based on the given rules.
func (a *AuthState) CheckRepeatingBruteForcer(rules []config.BruteForceRule, network **net.IPNet, message *string) (withError bool, alreadyTriggered bool, ruleNumber int) {
	bm := a.createBucketManager(a.Ctx())

	return bm.CheckRepeatingBruteForcer(rules, network, message)
}

// CheckBucketOverLimit checks if any brute force bucket limit has been exceeded.
func (a *AuthState) CheckBucketOverLimit(rules []config.BruteForceRule, message *string) (withError bool, ruleTriggered bool, ruleNumber int) {
	bm := a.createBucketManager(a.Ctx())

	return bm.CheckBucketOverLimit(rules, message)
}

// ProcessBruteForce evaluates and handles a brute force trigger based on the given rule and network.
func (a *AuthState) ProcessBruteForce(ruleTriggered, alreadyTriggered bool, rule *config.BruteForceRule, network *net.IPNet, message string, setter func()) bool {
	bm := a.createBucketManager(a.Ctx())

	return bm.ProcessBruteForce(ruleTriggered, alreadyTriggered, rule, network, message, setter)
}

// ProcessPWHist processes the password history and updates the account name if necessary.
func (a *AuthState) ProcessPWHist() (accountName string) {
	bm := a.createBucketManager(a.Ctx())
	accountName = bm.ProcessPWHist()
	a.Runtime.AccountName = accountName

	return
}

// SaveBruteForceBucketCounterToRedis persists the brute force bucket counter to Redis.
func (a *AuthState) SaveBruteForceBucketCounterToRedis(rule *config.BruteForceRule) {
	bm := a.createBucketManager(a.Ctx())
	bm.SaveBruteForceBucketCounterToRedis(rule)
}

// SaveFailedPasswordCounterInRedis updates the failed password counter in Redis.
func (a *AuthState) SaveFailedPasswordCounterInRedis() {
	bm := a.createBucketManager(a.Ctx())
	bm.SaveFailedPasswordCounterInRedis()
}

// DeleteIPBruteForceRedis removes brute force tracking for an IP from Redis.
func (a *AuthState) DeleteIPBruteForceRedis(rule *config.BruteForceRule, ruleName string) (removedKey string, err error) {
	bm := a.createBucketManager(a.Ctx())

	return bm.DeleteIPBruteForceRedis(rule, ruleName)
}

// IsIPAddressBlocked checks if the current client IP address is blocked by any brute force rules.
func (a *AuthState) IsIPAddressBlocked() (buckets []string, found bool) {
	bm := a.createBucketManager(a.Ctx())

	return bm.IsIPAddressBlocked()
}

// PrepareNetcalc pre-calculates network CIDRs for brute force rules.
func (a *AuthState) PrepareNetcalc(rules []config.BruteForceRule) {
	bm := a.createBucketManager(a.Ctx())
	bm.PrepareNetcalc(rules)
}

func (a *AuthState) createBucketManager(ctx context.Context) bruteforce.BucketManager {
	return bruteforce.NewBucketManagerWithDeps(ctx, a.Runtime.GUID, a.Request.ClientIP, bruteforce.BucketManagerDeps{
		Cfg:      a.deps.Cfg,
		Logger:   a.deps.Logger,
		Redis:    a.deps.Redis,
		Tolerate: a.deps.Tolerate,
	}).WithProtocol(a.Request.Protocol.Get()).WithOIDCCID(a.Request.OIDCCID).WithUsername(a.Request.Username).WithPassword(a.Request.Password).WithAccountName(a.Runtime.AccountField)
}

// GetAccountField returns the value of the AccountField field in the AuthState struct.
// If the AccountField field is nil, it returns an empty string.
func (a *AuthState) GetAccountField() string {
	return a.Runtime.AccountField
}

func (a *AuthState) PostLuaAction(ctx *gin.Context, passDBResult *PassDBResult) {
	tr := monittrace.New("nauthilus/auth")
	lctx, lspan := tr.Start(ctx.Request.Context(), "auth.lua.post_action",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
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

	cr := lualib.GetCommonRequest()
	a.FillCommonRequest(cr)

	if passDBResult != nil {
		cr.UserFound = passDBResult.UserFound
		cr.Authenticated = passDBResult.Authenticated
	}

	cr.HTTPStatus = ctx.Writer.Status()

	a.RunLuaPostAction(PostActionArgs{
		Context:       a.Runtime.Context,
		HTTPRequest:   a.Request.HTTPClientRequest,
		ParentSpan:    lspan.SpanContext(),
		StatusMessage: a.Runtime.StatusMessage,
		Request:       *cr,
	})

	lualib.PutCommonRequest(cr)
}

// HaveMonitoringFlag checks if the provided flag exists in the MonitoringFlags slice of the AuthState object.
// It iterates over the MonitoringFlags slice and returns true if the flag is found, otherwise it returns false.
func (a *AuthState) HaveMonitoringFlag(flag definitions.Monitoring) bool {
	for _, setFlag := range a.Runtime.MonitoringFlags {
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
	if a.Request.Username == "" {
		util.DebugModuleWithCfg(a.Ctx(), a.Cfg(), a.Logger(), definitions.DbgAuth, definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMsg, "Empty username")

		return definitions.AuthResultEmptyUsername
	}

	if !a.Request.NoAuth && a.Request.Password == "" {
		util.DebugModuleWithCfg(a.Ctx(), a.Cfg(), a.Logger(), definitions.DbgAuth, definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMsg, "Empty password")

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
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_local_cache_path_total"); stop != nil {
		defer stop()
	}

	a.SetOperationMode(ctx)

	passDBResult := a.initializePassDBResult()

	// Since this path is a confirmed positive hit from the in-memory cache,
	// the PassDB stage has already decided previously. Reflect that in AuthState
	// so final logs include authn=true for cache hits.
	a.Runtime.Authenticated = true

	authResult := definitions.AuthResultOK

	if !(a.Request.Protocol.Get() == definitions.ProtoOryHydra) {
		if lf := getLuaFilter(); lf != nil {
			authResult = lf.Filter(ctx, a.View(), passDBResult)
		}

		a.PostLuaAction(ctx, passDBResult)
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
	result.AccountField = a.Runtime.AccountField
	result.Account = a.GetAccount()
	result.TOTPSecretField = a.Runtime.TOTPSecretField
	result.TOTPRecoveryField = a.Runtime.TOTPRecoveryField
	result.UniqueUserIDField = a.Runtime.UniqueUserIDField
	result.DisplayNameField = a.Runtime.DisplayNameField
	result.Backend = a.Runtime.UsedPassDBBackend
	// Hand out a copy to avoid aliasing with the live AuthState map
	result.Attributes = a.GetAttributesCopy()

	return result
}

// handleBackendTypes initializes and populates variables related to backend types.
// The `backendPos` map stores the position of each backend type in the configuration list.
// The `useCache` boolean indicates whether the Cache backend type is used. It is set to true if at least one Cache backend is found in the configuration.
// The `passDBs` slice holds the PassDBMap objects associated with each backend type in the configuration.
func (a *AuthState) handleBackendTypes() (useCache bool, backendPos map[definitions.Backend]int, passDBs []*PassDBMap) {
	backendPos = make(map[definitions.Backend]int)

	cfg := a.Cfg()

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
				mgr := NewLDAPManager(backendType.GetName(), a.deps)
				passDBs = a.appendBackend(passDBs, definitions.BackendLDAP, mgr.PassDB)
			}
		case definitions.BackendLua:
			mgr := NewLuaManager(backendType.GetName(), a.deps)
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
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	// ensure downstream uses the same context
	ctx.Request = ctx.Request.WithContext(vctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(vctx)
	}
	defer vspan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_verify_password_total"); stop != nil {
		defer stop()
	}

	sfKey := a.Runtime.GUID
	if idem := ctx.GetHeader(idempotencyHeaderName); idem != "" {
		sfKey = "idem:" + idem
	}

	val, err, shared := backchanSF.Do(sfKey, func() (any, error) {
		return a.verifyPassword(ctx, passDBs)
	})

	var passDBResult *PassDBResult
	if val != nil {
		res := val.(*PassDBResult)
		if shared {
			passDBResult = res.Clone()
			updateAuthentication(ctx, a, passDBResult, nil)
		} else {
			passDBResult = res
		}
	}

	if passDBResult != nil {
		vspan.SetAttributes(
			attribute.Bool("authenticated", passDBResult.Authenticated),
			attribute.Bool("user_found", passDBResult.UserFound),
			attribute.Bool("shared", shared),
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
				definitions.LogKeyGUID, a.Runtime.GUID,
				definitions.LogKeyMsg, detailedError.GetDetails(),
				definitions.LogKeyError, detailedError.Error(),
			}

			if len(a.Runtime.AdditionalLogs) > 0 && len(a.Runtime.AdditionalLogs)%2 == 0 {
				logs = append(logs, a.Runtime.AdditionalLogs...)
			}

			level.Error(getDefaultLogger()).Log(
				logs...,
			)
		} else {
			level.Error(getDefaultLogger()).Log(
				definitions.LogKeyGUID, a.Runtime.GUID,
				definitions.LogKeyMsg, "Error verifying password",
				definitions.LogKeyError, err)
		}
	}

	return passDBResult, err
}

// processUserFound handles the processing when a user is found in the database, updates user account in Redis, and processes password history.
// It returns the account name and any error encountered during the process.
func (a *AuthState) processUserFound(passDBResult *PassDBResult) (accountName string, err error) {
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_user_found_total"); stop != nil {
		defer stop()
	}

	var bm bruteforce.BucketManager

	if a.Runtime.UserFound {
		accountName, err = a.updateUserAccountInRedis()
		if err != nil {
			level.Error(getDefaultLogger()).Log(
				definitions.LogKeyGUID, a.Runtime.GUID,
				definitions.LogKeyMsg, "Error updating user account in Redis",
				definitions.LogKeyError, err)
		}

		if !passDBResult.Authenticated {
			bm = bruteforce.NewBucketManagerWithDeps(a.Ctx(), a.Runtime.GUID, a.Request.ClientIP, bruteforce.BucketManagerDeps{
				Cfg:      a.Cfg(),
				Logger:   a.Logger(),
				Redis:    a.Redis(),
				Tolerate: a.deps.Tolerate,
			}).
				WithUsername(a.Request.Username).
				WithPassword(a.Request.Password).
				WithAccountName(accountName)

			// Set the protocol if available
			if a.Request.Protocol != nil && a.Request.Protocol.Get() != "" {
				bm = bm.WithProtocol(a.Request.Protocol.Get())
			}

			// Set the OIDC Client ID if available
			if a.Request.OIDCCID != "" {
				bm = bm.WithOIDCCID(a.Request.OIDCCID)
			}

			bm.ProcessPWHist()
		}
	}

	return
}

// isCacheInCorrectPosition checks if the cache backend is positioned before the used password database backend.
func (a *AuthState) isCacheInCorrectPosition(backendPos map[definitions.Backend]int) bool {
	return backendPos[definitions.BackendCache] < backendPos[a.Runtime.UsedPassDBBackend]
}

// GetUsedCacheBackend returns the cache name backend based on the used password database backend.
func (a *AuthState) GetUsedCacheBackend() (definitions.CacheNameBackend, error) {
	var usedBackend definitions.CacheNameBackend

	switch a.Runtime.UsedPassDBBackend {
	case definitions.BackendLDAP:
		usedBackend = definitions.CacheLDAP
	case definitions.BackendLua:
		usedBackend = definitions.CacheLua
	case definitions.BackendUnknown:
	case definitions.BackendCache:
	case definitions.BackendLocalCache:
	default:
		level.Error(getDefaultLogger()).Log(
			definitions.LogKeyGUID, a.Runtime.GUID,
			definitions.LogKeyMsg, "Unable to get the cache name backend",
			definitions.LogKeyError, fmt.Errorf("unknown backend type: %s", a.Runtime.UsedPassDBBackend),
		)

		return usedBackend, errors.ErrIncorrectCache
	}

	return usedBackend, nil
}

// GetCacheNameFor retrieves the cache name associated with the given backend, based on the protocol configured for the AuthState.
func (a *AuthState) GetCacheNameFor(usedBackend definitions.CacheNameBackend) (cacheName string, err error) {
	cacheNames := backend.GetCacheNames(a.Cfg(), a.Channel(), a.Request.Protocol.Get(), usedBackend)
	if len(cacheNames) != 1 {
		level.Error(a.Logger()).Log(
			definitions.LogKeyGUID, a.Runtime.GUID,
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
		AccountField:      a.Runtime.AccountField,
		TOTPSecretField:   a.Runtime.TOTPSecretField,
		UniqueUserIDField: a.Runtime.UniqueUserIDField,
		DisplayNameField:  a.Runtime.DisplayNameField,
		Password: func() string {
			if a.Request.Password != "" {
				passwordShort := util.GetHash(util.PreparePassword(a.Request.Password))

				return passwordShort
			}

			return ""
		}(),
		Backend:    a.Runtime.SourcePassDBBackend,
		Attributes: a.Attributes.Attributes,
	}
}

// processCache updates the relevant user cache entries based on authentication results from password databases.
func (a *AuthState) processCache(ctx *gin.Context, authenticated bool, accountName string, useCache bool, backendPos map[definitions.Backend]int) error {
	tr := monittrace.New("nauthilus/auth")
	cctx, cspan := tr.Start(ctx.Request.Context(), "auth.cache.process",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.Bool("authenticated", authenticated),
		attribute.Bool("use_cache", useCache),
	)

	_ = cctx

	defer cspan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_process_cache_total"); stop != nil {
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
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.Bool("use_cache", useCache),
	)

	ctx.Request = ctx.Request.WithContext(actx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(actx)
	}

	defer aspan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_authenticate_user_total"); stop != nil {
		defer stop()
	}

	// Protect against re-entrancy: if a prior pass in this request already authenticated, do not degrade
	if a.Runtime.Authenticated {
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
		a.Runtime.Authenticated = false

		return definitions.AuthResultTempFail
	}

	if accountName, err = a.processUserFound(passDBResult); err != nil || passDBResult == nil {
		// treat as tempfail
		a.Runtime.Authenticated = false

		return definitions.AuthResultTempFail
	}

	if err = a.processCache(ctx, passDBResult.Authenticated, accountName, useCache, backendPos); err != nil {
		// tempfail during cache processing
		a.Runtime.Authenticated = false

		return definitions.AuthResultTempFail
	}

	if passDBResult.Authenticated {
		if !(a.HaveMonitoringFlag(definitions.MonInMemory) || a.IsMasterUser()) {
			localcache.LocalCache.Set(a.generateLocalCacheKey(), passDBResult, getDefaultEnvironment().GetLocalCacheAuthTTL())
		}

		a.Runtime.Authenticated = true
		authResult = definitions.AuthResultOK
	} else {
		a.UpdateBruteForceBucketsCounter(ctx)

		a.Runtime.Authenticated = false
		authResult = definitions.AuthResultFail
	}

	if !(a.Request.Protocol.Get() == definitions.ProtoOryHydra) {
		authResult = a.FilterLua(passDBResult, ctx)
		aspan.SetAttributes(attribute.String("lua.result", string(authResult)))

		a.PostLuaAction(ctx, passDBResult)
	}

	return authResult
}

// FilterLua calls Lua filters which can change the backend result.
func (a *AuthState) FilterLua(passDBResult *PassDBResult, ctx *gin.Context) definitions.AuthResult {
	tr := monittrace.New("nauthilus/auth")
	lctx, lspan := tr.Start(ctx.Request.Context(), "auth.lua.filter",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	ctx.Request = ctx.Request.WithContext(lctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(lctx)
	}

	defer lspan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_filter_lua_total"); stop != nil {
		defer stop()
	}

	if lf := getLuaFilter(); lf != nil {
		res := lf.Filter(ctx, a.View(), passDBResult)
		lspan.SetAttributes(attribute.String("result", string(res)))

		return res
	}

	level.Error(a.logger()).Log(definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMsg, "LuaFilter not registered")

	return definitions.AuthResultTempFail
}

// ListUserAccounts returns the list of all known users from the account databases.
func (a *AuthState) ListUserAccounts() (accountList AccountList) {
	var accounts []*AccountListMap

	// Pre-allocate the accounts slice to avoid continuous reallocation
	// This is a conservative estimate, we'll allocate based on the number of backends
	accountList = make(AccountList, 0, 100)

	a.Request.Protocol.Set("account-provider")

	for _, backendType := range a.cfg().GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			mgr := NewLDAPManager(backendType.GetName(), a.deps)
			accounts = append(accounts, &AccountListMap{
				definitions.BackendLDAP,
				mgr.AccountDB,
			})
		case definitions.BackendLua:
			mgr := NewLuaManager(backendType.GetName(), a.deps)
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

		util.DebugModuleWithCfg(a.Ctx(), a.Cfg(), a.Logger(), definitions.DbgAuth, definitions.LogKeyGUID, a.Runtime.GUID, "backendType", accountDB.backend.String(), "result", fmt.Sprintf("%v", result))

		if err == nil {
			accountList = append(accountList, result...)
		} else {
			var detailedError *errors.DetailedError
			if stderrors.As(err, &detailedError) {
				level.Error(a.logger()).Log(
					definitions.LogKeyGUID, a.Runtime.GUID,
					definitions.LogKeyMsg, detailedError.GetDetails(),
					definitions.LogKeyError, err,
				)
			} else {
				level.Error(a.logger()).Log(
					definitions.LogKeyGUID, a.Runtime.GUID,
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
	dReadCtx, cancelRead := util.GetCtxWithDeadlineRedisRead(nil, a.Cfg())
	accountName = backend.GetUserAccountFromCache(dReadCtx, a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Runtime.GUID)
	cancelRead()

	if accountName != "" {
		return
	}

	if a.Runtime.AccountField != "" {
		if values, assertOk = a.GetAttribute(a.Runtime.AccountField); !assertOk {
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
		dWriteCtx, cancelWrite := util.GetCtxWithDeadlineRedisWrite(nil, a.Cfg())
		err = backend.SetUserAccountMapping(dWriteCtx, a.Cfg(), a.deps.Redis, a.Request.Username, accountName)
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
		if a.Request.HTTPClientRequest != nil {
			if rc := a.Request.HTTPClientRequest.Context(); rc != nil {
				// Avoid returning a canceled request context
				if rc.Err() == nil {
					return rc
				}
			}
		}

		if a.Request.HTTPClientContext != nil && a.Request.HTTPClientContext.Request != nil {
			if rc := a.Request.HTTPClientContext.Request.Context(); rc != nil {
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
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_set_operation_mode_total"); stop != nil {
		defer stop()
	}

	guid := ctx.GetString(definitions.CtxGUIDKey)
	cfg := a.cfg()
	logger := a.logger()

	// We reset flags, because they might have been cached in the in-memory cahce.
	a.Request.NoAuth = false
	a.Request.ListAccounts = false
	a.Runtime.MonitoringFlags = []definitions.Monitoring{}

	switch ctx.Query("mode") {
	case "no-auth":
		util.DebugModuleWithCfg(ctx.Request.Context(), cfg, logger, definitions.DbgAuth, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "mode=no-auth")

		// Check if JWT is enabled and user has the required role
		if cfg.GetServer().GetJWTAuth().IsEnabled() {
			if a.HasJWTRole(ctx, "user_info") {
				a.Request.NoAuth = true
			} else {
				level.Warn(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "JWT user does not have the 'user_info' role required for no-auth mode",
				)
			}
		} else {
			a.Request.NoAuth = true
		}
	case "list-accounts":
		util.DebugModuleWithCfg(ctx.Request.Context(), cfg, logger, definitions.DbgAuth, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "mode=list-accounts")

		// Check if JWT is enabled and user has the required role
		if cfg.GetServer().GetJWTAuth().IsEnabled() {
			if a.HasJWTRole(ctx, "list_accounts") {
				a.Request.ListAccounts = true
			} else {
				level.Warn(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "JWT user does not have the 'list_accounts' role required for list-accounts mode",
				)
			}
		} else {
			a.Request.ListAccounts = true
		}
	}

	if ctx.Query("in-memory") == "0" {
		a.Runtime.MonitoringFlags = append(a.Runtime.MonitoringFlags, definitions.MonInMemory)
	}

	if ctx.Query("cache") == "0" {
		a.Runtime.MonitoringFlags = append(a.Runtime.MonitoringFlags, definitions.MonCache)
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
	cfg := getDefaultConfigFile()
	if a, ok := auth.(*AuthState); ok {
		cfg = a.cfg()

		if stop := stats.PrometheusTimer(cfg, definitions.PromRequest, "request_headers_parse_total"); stop != nil {
			defer stop()
		}
	}

	// Nginx header, see: https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html#protocol
	username := ctx.GetHeader(cfg.GetUsername())
	password := ctx.GetHeader(cfg.GetPassword())

	if strings.Contains(password, "%") {
		if decodedPassword, err := url.PathUnescape(password); err == nil {
			password = decodedPassword
		}
	}

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
			a.Security.LoginAttempts = lam.FailCount()
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
	if a, ok := auth.(*AuthState); ok {
		if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromRequest, "request_form_decode_total"); stop != nil {
			defer stop()
		}
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
	if a, ok := auth.(*AuthState); ok {
		if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromRequest, "request_json_decode_total"); stop != nil {
			defer stop()
		}
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
		} else if strings.HasPrefix(contentType, "application/json") {
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
	if a.Request.Method == "" {
		a.Request.Method = ""
	}

	if a.Request.UserAgent == "" {
		a.Request.UserAgent = ""
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
	if a, ok := auth.(*AuthState); ok {
		if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromRequest, "request_setup_total"); stop != nil {
			defer stop()
		}
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

	if ctx.IsAborted() {
		return
	}

	if ctx.Query("mode") != "list-accounts" && ctx.Query("mode") != "no-auth" && svc != definitions.ServBasic {
		username := auth.GetUsername()

		if username == "" {
			ctx.Error(errors.ErrEmptyUsername)

			return
		} else if !util.ValidateUsername(username) {
			auth.SetUsername("")
			ctx.Error(errors.ErrInvalidUsername)

			return
		}

		if auth.GetPassword() == "" {
			ctx.Error(errors.ErrEmptyPassword)

			return
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

	if ctx.Errors.Last() != nil || ctx.IsAborted() {
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

	if ctx.Errors.Last() != nil || ctx.IsAborted() {
		return nil
	}

	return auth
}

// NewAuthStateFromContext initializes and returns an AuthState using the provided gin.Context.
func NewAuthStateFromContext(ctx *gin.Context) State {
	return NewAuthStateFromContextWithDeps(ctx, AuthDeps{
		Cfg:          getDefaultConfigFile(),
		Env:          getDefaultEnvironment(),
		Logger:       getDefaultLogger(),
		Redis:        getDefaultRedisClient(),
		AccountCache: getDefaultAccountCache(),
		Channel:      getDefaultChannel(),
	})
}

// NewAuthStateFromContextWithDeps initializes and returns an AuthState using the provided gin.Context and explicit deps.
func NewAuthStateFromContextWithDeps(ctx *gin.Context, deps AuthDeps) State {
	var (
		httpCtx     *gin.Context
		httpRequest *http.Request
	)

	if ctx != nil {
		httpCtx = ctx
		httpRequest = ctx.Request
	} else {
		// Fallback for tests or contexts where gin.Context is not available
		httpCtx = &gin.Context{}
		httpRequest = &http.Request{Proto: "HTTP/1.1"}
	}

	auth := &AuthState{
		deps: deps,
		Request: AuthRequest{
			HTTPClientContext: httpCtx,
			HTTPClientRequest: httpRequest,
		},
		Runtime: AuthRuntime{
			StartTime: time.Now(),
		},
	}

	return auth
}

// WithDefaults sets default values for the AuthState structure including the GUID session value.
func (a *AuthState) WithDefaults(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	a.Runtime.GUID = ctx.GetString(definitions.CtxGUIDKey)
	a.Runtime.UsedPassDBBackend = definitions.BackendUnknown
	a.Security.PasswordsAccountSeen = 0
	a.Request.Service = ctx.GetString(definitions.CtxServiceKey)
	a.Runtime.Context = ctx.MustGet(definitions.CtxDataExchangeKey).(*lualib.Context)

	// Default flags
	a.Runtime.Authenticated = false // not decided yet
	a.Runtime.Authorized = true     // default allow unless a filter rejects

	if a.Request.Service == definitions.ServBasic {
		a.Request.Protocol.Set(definitions.ProtoHTTP)
	}

	if a.Request.Protocol.Get() == "" {
		a.Request.Protocol.Set(definitions.ProtoDefault)
	}

	return a
}

// WithLocalInfo adds the local IP and -port headers to the AuthState structure.
func (a *AuthState) WithLocalInfo(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	cfg := a.cfg()
	a.Request.XLocalIP = ctx.GetHeader(cfg.GetLocalIP())
	a.Request.XPort = ctx.GetHeader(cfg.GetLocalPort())

	return a
}

// postResolvDNS resolves the client IP to a host name if DNS client IP resolution is enabled in the configuration.
func (a *AuthState) postResolvDNS(ctx context.Context) {
	if a.cfg().GetServer().GetDNS().GetResolveClientIP() {
		stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromDNS, definitions.DNSResolvePTR)

		a.Request.ClientHost = util.ResolveIPAddress(ctx, a.Cfg(), a.Request.ClientIP)

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
	a.Request.OIDCCID = ctx.GetHeader(cfg.GetOIDCCID())
	a.Request.ClientIP = ctx.GetHeader(cfg.GetClientIP())
	a.Request.XClientPort = ctx.GetHeader(cfg.GetClientPort())
	a.Request.XClientID = ctx.GetHeader(cfg.GetClientID())
	a.Request.ClientHost = ctx.GetHeader(cfg.GetClientHost())

	if a.Request.ClientIP == "" {
		// This might be valid if HAproxy v2 support is enabled
		if cfg.GetServer().IsHAproxyProtocolEnabled() {
			a.Request.ClientIP, a.Request.XClientPort, err = net.SplitHostPort(ctx.Request.RemoteAddr)
			if err != nil {
				level.Error(a.logger()).Log(
					definitions.LogKeyGUID, a.Runtime.GUID,
					definitions.LogKeyMsg, "Failed to split client IP and port",
					definitions.LogKeyError, err,
				)
			}

			util.ProcessXForwardedFor(ctx, a.Cfg(), a.Logger(), &a.Request.ClientIP, &a.Request.XClientPort, &a.Request.XSSL)
		}
	}

	a.postResolvDNS(ctx.Request.Context())

	return a
}

// WithUserAgent adds the User-Agent header to the AuthState structure.
func (a *AuthState) WithUserAgent(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	a.Request.UserAgent = ctx.Request.UserAgent()

	return a
}

// WithXSSL adds HAProxy header processing to the AuthState structure.
func (a *AuthState) WithXSSL(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	h := a.cfg().GetServer().GetDefaultHTTPRequestHeader()
	a.Request.XSSL = ctx.GetHeader(h.GetSSL())
	a.Request.XSSLSessionID = ctx.GetHeader(h.GetSSLSessionID())
	a.Request.XSSLClientVerify = ctx.GetHeader(h.GetSSLVerify())
	a.Request.XSSLClientDN = ctx.GetHeader(h.GetSSLSubject())
	a.Request.XSSLClientCN = ctx.GetHeader(h.GetSSLClientCN())
	a.Request.XSSLIssuer = ctx.GetHeader(h.GetSSLIssuer())
	a.Request.XSSLClientNotBefore = ctx.GetHeader(h.GetSSLClientNotBefore())
	a.Request.XSSLClientNotAfter = ctx.GetHeader(h.GetSSLClientNotAfter())
	a.Request.XSSLSubjectDN = ctx.GetHeader(h.GetSSLSubjectDN())
	a.Request.XSSLIssuerDN = ctx.GetHeader(h.GetSSLIssuerDN())
	a.Request.XSSLClientSubjectDN = ctx.GetHeader(h.GetSSLClientSubjectDN())
	a.Request.XSSLClientIssuerDN = ctx.GetHeader(h.GetSSLClientIssuerDN())
	a.Request.XSSLCipher = ctx.GetHeader(h.GetSSLCipher())
	a.Request.XSSLProtocol = ctx.GetHeader(h.GetSSLProtocol())
	a.Request.SSLSerial = ctx.GetHeader(h.GetSSLSerial())
	a.Request.SSLFingerprint = ctx.GetHeader(h.GetSSLFingerprint())

	return a
}

// generateLocalCacheKey generates a string key used for caching the AuthState object in the local cache.
// The key is constructed by concatenating the Username, Password and  Service values using a null character ('\0')
// as a separator.
func (a *AuthState) generateLocalCacheKey() string {
	return fmt.Sprintf("%s\000%s\000%s\000%s\000%s",
		a.Request.Username,
		a.Request.Password,
		a.Request.Service,
		a.Request.Protocol.Get(),
		func() string {
			if a.Request.ClientIP == "" {
				return "0.0.0.0"
			}

			return a.Request.ClientIP
		}(),
	)
}

// generateSingleflightKey builds a strict deduplication key for backchannel singleflight.
// Fields: service, protocol, username, client_ip, local_ip, local_port, ssl_flag, [oidcCID], pw_short
func (a *AuthState) generateSingleflightKey() string {
	clientIP := a.Request.ClientIP
	if clientIP == "" {
		clientIP = "0.0.0.0"
	}

	sslFlag := "0"
	if a.Request.XSSL != "" || a.Request.XSSLProtocol != "" {
		sslFlag = "1"
	}

	// Short password hash (same function as for positive password cache)
	pwShort := util.GetHash(util.PreparePassword(a.Request.Password))

	const sep = "\x00"

	var sb strings.Builder

	sb.WriteString(a.Request.Service)
	sb.WriteString(sep)
	sb.WriteString(a.Request.Protocol.Get())
	sb.WriteString(sep)
	sb.WriteString(a.Request.Username)
	sb.WriteString(sep)
	sb.WriteString(clientIP)
	sb.WriteString(sep)
	sb.WriteString(a.Request.XLocalIP)
	sb.WriteString(sep)
	sb.WriteString(a.Request.XPort)
	sb.WriteString(sep)
	sb.WriteString(sslFlag)

	if a.Request.OIDCCID != "" {
		sb.WriteString(sep)
		sb.WriteString(a.Request.OIDCCID)
	}

	sb.WriteString(sep)
	sb.WriteString(pwShort)

	return sb.String()
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
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	// ensure downstream uses the same context
	ctx.Request = ctx.Request.WithContext(lcCtx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(lcCtx)
	}

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
	}

	lcSpan.SetAttributes(attribute.Bool("hit", false))

	return false

}

// PreproccessAuthRequest preprocesses the authentication request by checking if the request is already in the local cache.
// If not found in the cache, it checks if the request is a brute force attack and updates the brute force counter.
// It then performs a post Lua action and triggers a failed authentication response.
// If a brute force attack is detected, it returns true, otherwise false.
func (a *AuthState) PreproccessAuthRequest(ctx *gin.Context) (reject bool) {
	tr := monittrace.New("nauthilus/auth")
	pctx, pspan := tr.Start(ctx.Request.Context(), "auth.features",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	// propagate for any nested calls
	ctx.Request = ctx.Request.WithContext(pctx)
	if a.Request.HTTPClientRequest != nil {
		a.Request.HTTPClientRequest = a.Request.HTTPClientRequest.WithContext(pctx)
	}

	var cacheHit bool
	if found := a.GetFromLocalCache(ctx); !found {
		stats.GetMetrics().GetCacheMisses().Inc()

		if a.CheckBruteForce(ctx) {
			pspan.SetAttributes(attribute.Bool("bruteforce.blocked", true))
			a.UpdateBruteForceBucketsCounter(ctx)
			result := GetPassDBResultFromPool()
			a.PostLuaAction(ctx, result)
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
		a.Request.Username = c.Username
	}

	if c.Password != "" {
		a.Request.Password = c.Password
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
		{x.Method, &a.Request.Method},
		{x.UserAgent, &a.Request.UserAgent},
		{x.ClientIP, &a.Request.ClientIP},
		{x.ClientPort, &a.Request.XClientPort},
		{x.ClientHostname, &a.Request.ClientHost},
		{x.ClientID, &a.Request.XClientID},
		{x.LocalIP, &a.Request.XLocalIP},
		{x.LocalPort, &a.Request.XPort},
		{x.XSSL, &a.Request.XSSL},
		{x.XSSLSessionID, &a.Request.XSSLSessionID},
		{x.XSSLClientVerify, &a.Request.XSSLClientVerify},
		{x.XSSLClientDN, &a.Request.XSSLClientDN},
		{x.XSSLClientCN, &a.Request.XSSLClientCN},
		{x.XSSLIssuer, &a.Request.XSSLIssuer},
		{x.XSSLClientNotBefore, &a.Request.XSSLClientNotBefore},
		{x.XSSLClientNotAfter, &a.Request.XSSLClientNotAfter},
		{x.XSSLSubjectDN, &a.Request.XSSLSubjectDN},
		{x.XSSLIssuerDN, &a.Request.XSSLIssuerDN},
		{x.XSSLClientSubjectDN, &a.Request.XSSLClientSubjectDN},
		{x.XSSLClientIssuerDN, &a.Request.XSSLClientIssuerDN},
		{x.XSSLProtocol, &a.Request.XSSLProtocol},
		{x.XSSLCipher, &a.Request.XSSLCipher},
		{x.SSLSerial, &a.Request.SSLSerial},
		{x.SSLFingerprint, &a.Request.SSLFingerprint},
		{x.OIDCCID, &a.Request.OIDCCID},
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
