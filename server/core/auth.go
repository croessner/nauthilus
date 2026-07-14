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
	stdjson "encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/bruteforce"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/localcache"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/evaluation"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/svcctx"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"
)

var backchanSF singleflight.Group

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

// GetTotalServers provides the exported GetTotalServers method.
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
	// DeleteWebAuthnCredential removes a WebAuthn credential for the user in the backend.
	DeleteWebAuthnCredential(credential *mfa.PersistentCredential) (err error)

	// SaveWebAuthnCredential saves a WebAuthn credential for the user in the backend.
	SaveWebAuthnCredential(credential *mfa.PersistentCredential) (err error)

	// UpdateWebAuthnCredential updates an existing WebAuthn credential in the backend.
	UpdateWebAuthnCredential(oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) (err error)

	// GetWebAuthnCredentials retrieves WebAuthn credentials for the user in the backend.
	GetWebAuthnCredentials() (credentials []mfa.PersistentCredential, err error)

	// FinishSetup completes the initialization of the state and logs the incoming request.
	FinishSetup(ctx *gin.Context)

	// SetUsername sets the username for the current authentication state.
	SetUsername(username string)

	// SetPassword sets the password for the current authentication state.
	SetPassword(password secret.Value)

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

	// GetPassword retrieves the current password stored in the authentication state.
	GetPassword() secret.Value

	// GetProtocol retrieves the protocol configuration associated with the current state.
	GetProtocol() *config.Protocol

	// FinishLogging logs the authentication result and updates metrics.
	FinishLogging(ctx *gin.Context, result definitions.AuthResult)

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

	// SetSAMLEntityID sets the SAML Entity ID for the authentication state.
	SetSAMLEntityID(samlEntityID string)

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

	// GetUsedPassDBBackendName returns the name of the backend used for the password database during the authentication process.
	GetUsedPassDBBackendName() string

	// GetSourcePassDBBackend returns the source backend used for the password database during the authentication process.
	GetSourcePassDBBackend() definitions.Backend

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

	// SubjectLua applies Lua-based subject analysis logic to the provided execution context and PassDBResult.
	// It returns an AuthResult indicating the outcome of the subject analysis process.
	SubjectLua(ctx *gin.Context, passDBResult *PassDBResult) definitions.AuthResult

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

	// PurgeCache invalidates the user authentication cache.
	PurgeCache()

	// PurgeCacheFor invalidates the user authentication cache for a specific username.
	PurgeCacheFor(username string)
}

// AuthRequest holds data directly extracted from the HTTP request or connection metadata.
type AuthRequest struct {
	// Protocol is the protocol used for the request.
	Protocol *config.Protocol

	// HTTPClientContext is the Gin context associated with the request.
	HTTPClientContext *gin.Context

	// HTTPClientRequest is the HTTP request being processed.
	HTTPClientRequest *http.Request

	// RequestMetadata contains incoming transport metadata such as gRPC metadata.
	RequestMetadata map[string][]string

	// Method is the authentication method.
	Method string

	// Username is the name of the user attempting to authenticate.
	Username string

	// Password is the user's password.
	Password secret.Value

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

	// SAMLEntityID is the SAML Entity ID.
	SAMLEntityID string

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

	// AuthLoginAttempt is the incoming authentication attempt ordinal.
	AuthLoginAttempt uint

	// XClientID is a custom client identifier.
	XClientID string

	// ExternalSessionID is an upstream session identifier supplied by the caller.
	ExternalSessionID string

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

	// BruteForceBuckets contains read-only bucket facts collected for policy evaluation.
	BruteForceBuckets []bruteforce.BucketPolicyFact

	// AccountProviderPluginFacts contains native plugin account-list facts for policy evaluation.
	AccountProviderPluginFacts []pluginapi.PolicyFact

	// BruteForceToleration contains the request-local toleration fact collected for policy evaluation.
	BruteForceToleration tolerate.PolicyFact

	// RelayDomainPolicy contains the request-local relay-domain facts collected for policy evaluation.
	RelayDomainPolicy RelayDomainPolicyFact

	// RBLPolicy contains the request-local RBL facts collected for policy evaluation.
	RBLPolicy RBLPolicyFact

	// GUID is a unique identifier for the authentication request.
	GUID string

	// StatusMessage is a message describing the status of the request.
	StatusMessage string

	// StatusMessageI18NKey is the policy-selected localization key for StatusMessage.
	StatusMessageI18NKey string

	// ResponseLanguage is the policy-selected response-rendering language.
	ResponseLanguage string

	// AuthFSMTerminalState contains the current auth FSM terminal state when known.
	AuthFSMTerminalState string

	// AccountField is the name of the field containing the account information.
	AccountField string

	// AccountName is the name of the account being authenticated.
	AccountName string

	// EnvironmentName is the name of the environment control or source being accessed.
	EnvironmentName string

	// RemoteBackendRef binds follow-up identity operations to an authority-side backend.
	RemoteBackendRef RemoteBackendRef

	// IdentityAttributeRequest carries edge-side requested backend attributes for claim materialization.
	IdentityAttributeRequest *IdentityAttributeRequest

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

	// AdditionalAttributes contains additional attribute-specific data.
	AdditionalAttributes map[string]any

	// AuthFSMEventPath contains current auth FSM events seen by this request.
	AuthFSMEventPath []string

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

	// BFRWP stores the request-level Repeating Wrong Password (RWP) allowance decision.
	// A pre-auth candidate is cleared after successful authentication, so final logs retain true only for failures
	// whose brute-force bucket counters were not increased.
	BFRWP bool

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

// AuthGroups handles resolved group memberships and their synchronization.
type AuthGroups struct {
	// Groups stores resolved group names.
	Groups []string

	// GroupDistinguishedNames stores resolved group distinguished names.
	GroupDistinguishedNames []string

	// groupsMu is a mutex for thread-safe access to group fields.
	groupsMu sync.RWMutex
}

// AuthState represents a struct that holds information related to an authentication process.
type AuthState struct {
	// operationContext is an isolated worker-owned context when no shared request carrier may be mutated.
	operationContext context.Context

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

	// Groups handles resolved groups and their synchronization.
	Groups AuthGroups
}

// Cfg provides the exported Cfg method.
func (a *AuthState) Cfg() config.File {
	return a.deps.Cfg
}

// Env provides the exported Env method.
func (a *AuthState) Env() config.Environment {
	return a.deps.Env
}

// Logger provides the exported Logger method.
func (a *AuthState) Logger() *slog.Logger {
	return a.deps.Logger
}

// Redis provides the exported Redis method.
func (a *AuthState) Redis() rediscli.Client {
	return a.deps.Redis
}

func (a *AuthState) cfg() config.File {
	return a.Cfg()
}

func (a *AuthState) logger() *slog.Logger {
	return a.Logger()
}

// AccountCache provides the exported AccountCache method.
func (a *AuthState) AccountCache() *accountcache.Manager {
	return a.deps.AccountCache
}

// Channel provides the exported Channel method.
func (a *AuthState) Channel() backend.Channel {
	return a.deps.Channel
}

// GetLogger provides the exported GetLogger method.
func (a *AuthState) GetLogger() *slog.Logger {
	return a.deps.Logger
}

// GetWebAuthnCredentials retrieves WebAuthn credentials for the user in the backend.
func (a *AuthState) GetWebAuthnCredentials() (credentials []mfa.PersistentCredential, err error) {
	var (
		passDB      definitions.Backend
		backendName string
	)

	mgr := cookie.GetManager(a.Request.HTTPClientContext)
	a.restoreRemoteBackendRefFromSession(mgr)

	// We expect the same Database for credentials that was used for authenticating a user!
	if mgr != nil {
		cookieValue := mgr.GetUint8(definitions.SessionKeyUserBackend, 0)

		if cookieValue != 0 {
			passDB = definitions.Backend(cookieValue)
			backendName = mgr.GetString(definitions.SessionKeyUserBackendName, "")

			if backendMgr := a.GetBackendManager(passDB, backendName); backendMgr != nil {
				return backendMgr.GetWebAuthnCredentials(a)
			}
		}
	}

	// No cookie (default login page), search all configured databases.
	for _, backendType := range a.Cfg().GetServer().GetBackends() {
		if mgr := a.GetBackendManager(backendType.Get(), backendType.GetName()); mgr != nil {
			credentials, err = mgr.GetWebAuthnCredentials(a)
			if err != nil {
				// Skip backends that do not support this protocol.
				if stderrors.Is(err, errors.ErrLDAPConfig) {
					continue
				}

				return nil, err
			}

			if len(credentials) > 0 {
				return credentials, nil
			}
		}
	}

	return []mfa.PersistentCredential{}, nil
}

// SaveWebAuthnCredential saves a WebAuthn credential for the user in the backend.
func (a *AuthState) SaveWebAuthnCredential(credential *mfa.PersistentCredential) (err error) {
	var (
		passDB      definitions.Backend
		backendName string
	)

	mgr := cookie.GetManager(a.Request.HTTPClientContext)
	a.restoreRemoteBackendRefFromSession(mgr)

	// We expect the same Database for credentials that was used for authenticating a user!
	if mgr != nil {
		cookieValue := mgr.GetUint8(definitions.SessionKeyUserBackend, 0)

		if cookieValue != 0 {
			passDB = definitions.Backend(cookieValue)
			backendName = mgr.GetString(definitions.SessionKeyUserBackendName, "")

			if backendMgr := a.GetBackendManager(passDB, backendName); backendMgr != nil {
				return backendMgr.SaveWebAuthnCredential(a, credential)
			}
		}
	}

	// Default to first LDAP backend if none specified (safest bet for registration).
	// Skip backends that do not support this protocol.
	for _, backendType := range a.Cfg().GetServer().GetBackends() {
		if mgr := a.GetBackendManager(backendType.Get(), backendType.GetName()); mgr != nil {
			if err := mgr.SaveWebAuthnCredential(a, credential); err != nil {
				if stderrors.Is(err, errors.ErrLDAPConfig) {
					continue
				}

				return err
			}

			return nil
		}
	}

	return errors.ErrUnknownDatabaseBackend
}

// DeleteWebAuthnCredential removes a WebAuthn credential for the user in the backend.
func (a *AuthState) DeleteWebAuthnCredential(credential *mfa.PersistentCredential) (err error) {
	var (
		passDB      definitions.Backend
		backendName string
	)

	mgr := cookie.GetManager(a.Request.HTTPClientContext)
	a.restoreRemoteBackendRefFromSession(mgr)

	// We expect the same Database for credentials that was used for authenticating a user!
	if mgr != nil {
		cookieValue := mgr.GetUint8(definitions.SessionKeyUserBackend, 0)

		if cookieValue != 0 {
			passDB = definitions.Backend(cookieValue)
			backendName = mgr.GetString(definitions.SessionKeyUserBackendName, "")

			if backendMgr := a.GetBackendManager(passDB, backendName); backendMgr != nil {
				return backendMgr.DeleteWebAuthnCredential(a, credential)
			}
		}
	}

	// No cookie, search all backends to find where it is stored and delete it.
	// GetWebAuthnCredentials already skips pools without protocol support (returns empty).
	for _, backendType := range a.Cfg().GetServer().GetBackends() {
		if mgr := a.GetBackendManager(backendType.Get(), backendType.GetName()); mgr != nil {
			credentials, _ := mgr.GetWebAuthnCredentials(a)
			for _, cred := range credentials {
				if bytes.Equal(cred.ID, credential.ID) {
					return mgr.DeleteWebAuthnCredential(a, credential)
				}
			}
		}
	}

	return errors.ErrUnknownDatabaseBackend
}

// UpdateWebAuthnCredential updates an existing WebAuthn credential in the backend.
func (a *AuthState) UpdateWebAuthnCredential(oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) (err error) {
	var (
		passDB      definitions.Backend
		backendName string
	)

	mgr := cookie.GetManager(a.Request.HTTPClientContext)
	a.restoreRemoteBackendRefFromSession(mgr)

	// We expect the same Database for credentials that was used for authenticating a user!
	if mgr != nil {
		cookieValue := mgr.GetUint8(definitions.SessionKeyUserBackend, 0)

		if cookieValue != 0 {
			passDB = definitions.Backend(cookieValue)
			backendName = mgr.GetString(definitions.SessionKeyUserBackendName, "")

			if backendMgr := a.GetBackendManager(passDB, backendName); backendMgr != nil {
				return backendMgr.UpdateWebAuthnCredential(a, oldCredential, newCredential)
			}
		}
	}

	// No cookie, search all backends to find where it is stored and update it.
	// GetWebAuthnCredentials already skips pools without protocol support (returns empty).
	for _, backendType := range a.Cfg().GetServer().GetBackends() {
		if mgr := a.GetBackendManager(backendType.Get(), backendType.GetName()); mgr != nil {
			credentials, _ := mgr.GetWebAuthnCredentials(a)
			for _, cred := range credentials {
				if bytes.Equal(cred.ID, oldCredential.ID) {
					return mgr.UpdateWebAuthnCredential(a, oldCredential, newCredential)
				}
			}
		}
	}

	return errors.ErrUnknownDatabaseBackend
}

// GetBackendManager returns a BackendManager based on the provided backend type and name.
func (a *AuthState) GetBackendManager(backendType definitions.Backend, backendName string) BackendManager {
	switch backendType {
	case definitions.BackendLDAP:
		if backendName == "" {
			poolName, ok := config.ResolveLDAPSearchPoolName(a.Cfg(), a.Request.Protocol.Get())
			if ok {
				backendName = poolName
			} else {
				level.Warn(a.Logger()).Log(
					definitions.LogKeyGUID, a.Runtime.GUID,
					definitions.LogKeyMsg, "LDAP pool name unresolved; using default",
					definitions.LogKeyProtocol, a.Request.Protocol.Get(),
				)

				backendName = definitions.DefaultBackendName
			}
		}

		return NewLDAPManager(backendName, a.deps)
	case definitions.BackendLua:
		return NewLuaManager(backendName, a.deps)
	case definitions.BackendTest:
		return NewTestBackendManager(backendName, a.deps)
	default:
		return backendManagerFromFactory(backendType, backendName, a.deps)
	}
}

var _ State = (*AuthState)(nil)

// PassDBResult is used in all password databases to store final results of an authentication process.
type PassDBResult struct {
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

	// BackendRef binds this result to an authority-side backend without exposing credentials.
	BackendRef RemoteBackendRef

	// Attributes is the result catalog returned by the underlying password Database.
	Attributes bktype.AttributeMapping

	// Groups contains resolved group names.
	Groups []string

	// GroupDistinguishedNames contains resolved group distinguished names.
	GroupDistinguishedNames []string

	// AdditionalAttributes contains additional backend attributes
	AdditionalAttributes map[string]any

	// Authenticated is a flag that is set if a user was not only found, but also succeeded authentication.
	Authenticated bool

	// UserFound is a flag that is set if the user was found in a password Database.
	UserFound bool

	// Backend is set by the Database backend, which has found the user.
	Backend definitions.Backend
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
	p.BackendRef = RemoteBackendRef{}

	// Reset map fields to nil
	p.Attributes = nil
	p.AdditionalAttributes = nil
	p.Groups = nil
	p.GroupDistinguishedNames = nil
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
	res.BackendRef = p.BackendRef
	res.Attributes = p.Attributes.Clone()
	res.Groups = slices.Clone(p.Groups)
	res.GroupDistinguishedNames = slices.Clone(p.GroupDistinguishedNames)

	if p.AdditionalAttributes != nil {
		res.AdditionalAttributes = make(map[string]any, len(p.AdditionalAttributes))
		maps.Copy(res.AdditionalAttributes, p.AdditionalAttributes)
	}

	return res
}

type (
	// PassDBOption describes the exported PassDBOption type.
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
type WebAuthnCredentialDBFunc func(uniqueUserID string) ([]mfa.PersistentCredential, error)

// AddTOTPSecretFunc is a function signature that takes a *AuthState and *TOTPSecret as arguments and returns an error.
type AddTOTPSecretFunc func(auth *AuthState, totp *mfa.TOTPSecret) (err error)

// BackendServers is an exported package value.
var BackendServers = NewBackendServer()

// authStateField describes a single key-value pair for string representation.
type authStateField struct {
	Name  string
	Value any
}

// hiddenAuthStateFields lists field names whose values must be redacted in non-dev mode.
var hiddenAuthStateFields = map[string]struct{}{
	authStateFieldPassword:   {},
	authStateFieldTOTPSecret: {},
}

const (
	authStateFieldAccountField      = "AccountField"
	authStateFieldAuthenticated     = "Authenticated"
	authStateFieldBackendName       = "BackendName"
	authStateFieldDisplayNameField  = "DisplayNameField"
	authStateFieldPassword          = "Password"
	authStateFieldTOTPRecoveryField = "TOTPRecoveryField"
	authStateFieldTOTPSecret        = "TOTPSecret"
	authStateFieldTOTPSecretField   = "TOTPSecretField"
	authStateFieldUniqueUserIDField = "UniqueUserIDField"
	authStateFieldUserFound         = "UserFound"
	logRedactedValue                = "<redacted>"
)

// String returns a human-readable representation of the AuthState.
// The GUID is omitted and the password is hidden unless dev mode is active.
func (a *AuthState) String() string {
	fields := a.collectFields()

	var result strings.Builder

	for _, f := range fields {
		if _, hidden := hiddenAuthStateFields[f.Name]; hidden {
			if getDefaultEnvironment().GetDevMode() {
				fmt.Fprintf(&result, " %s='%v'", f.Name, f.Value)
			} else {
				fmt.Fprintf(&result, " %s='<hidden>'", f.Name)
			}

			continue
		}

		fmt.Fprintf(&result, " %s='%v'", f.Name, f.Value)
	}

	if result.Len() == 0 {
		return ""
	}

	return result.String()[1:]
}

// collectFields returns the ordered list of fields for string representation.
// Fields that should never appear (e.g. GUID) are excluded here.
func (a *AuthState) collectFields() []authStateField {
	fields := a.requestFields()

	return append(fields, a.runtimeFields()...)
}

// requestFields returns request fields for AuthState string rendering.
func (a *AuthState) requestFields() []authStateField {
	return []authStateField{
		{"Protocol", a.Request.Protocol},
		{"Method", a.Request.Method},
		{"Username", a.Request.Username},
		{authStateFieldPassword, a.Request.Password},
		{"ClientIP", a.Request.ClientIP},
		{"XClientPort", a.Request.XClientPort},
		{"ClientHost", a.Request.ClientHost},
		{"UserAgent", a.Request.UserAgent},
		{"Service", a.Request.Service},
		{"OIDCCID", a.Request.OIDCCID},
		{"SAMLEntityID", a.Request.SAMLEntityID},
		{"XSSL", a.Request.XSSL},
		{"XSSLSessionID", a.Request.XSSLSessionID},
		{"XSSLClientVerify", a.Request.XSSLClientVerify},
		{"XSSLClientDN", a.Request.XSSLClientDN},
		{"XSSLClientCN", a.Request.XSSLClientCN},
		{"XSSLIssuer", a.Request.XSSLIssuer},
		{"XSSLClientNotBefore", a.Request.XSSLClientNotBefore},
		{"XSSLClientNotAfter", a.Request.XSSLClientNotAfter},
		{"XSSLSubjectDN", a.Request.XSSLSubjectDN},
		{"XSSLIssuerDN", a.Request.XSSLIssuerDN},
		{"XSSLClientSubjectDN", a.Request.XSSLClientSubjectDN},
		{"XSSLClientIssuerDN", a.Request.XSSLClientIssuerDN},
		{"XSSLProtocol", a.Request.XSSLProtocol},
		{"XSSLCipher", a.Request.XSSLCipher},
		{"SSLSerial", a.Request.SSLSerial},
		{"SSLFingerprint", a.Request.SSLFingerprint},
		{"XClientID", a.Request.XClientID},
		{"XLocalIP", a.Request.XLocalIP},
		{"XPort", a.Request.XPort},
		{"NoAuth", a.Request.NoAuth},
		{"ListAccounts", a.Request.ListAccounts},
	}
}

// runtimeFields returns runtime and security fields for AuthState string rendering.
func (a *AuthState) runtimeFields() []authStateField {
	return []authStateField{
		{"StatusMessage", a.Runtime.StatusMessage},
		{authStateFieldAccountField, a.Runtime.AccountField},
		{"AccountName", a.Runtime.AccountName},
		{"EnvironmentName", a.Runtime.EnvironmentName},
		{authStateFieldBackendName, a.Runtime.BackendName},
		{"UsedBackendIP", a.Runtime.UsedBackendIP},
		{authStateFieldTOTPSecret, a.Runtime.TOTPSecret},
		{authStateFieldTOTPSecretField, a.Runtime.TOTPSecretField},
		{authStateFieldTOTPRecoveryField, a.Runtime.TOTPRecoveryField},
		{authStateFieldUniqueUserIDField, a.Runtime.UniqueUserIDField},
		{authStateFieldDisplayNameField, a.Runtime.DisplayNameField},
		{"BFClientNet", a.Runtime.BFClientNet},
		{"UsedBackendPort", a.Runtime.UsedBackendPort},
		{"StatusCodeOK", a.Runtime.StatusCodeOK},
		{"StatusCodeInternalError", a.Runtime.StatusCodeInternalError},
		{"StatusCodeFail", a.Runtime.StatusCodeFail},
		{"SourcePassDBBackend", a.Runtime.SourcePassDBBackend},
		{"UsedPassDBBackend", a.Runtime.UsedPassDBBackend},
		{authStateFieldUserFound, a.Runtime.UserFound},
		{authStateFieldAuthenticated, a.Runtime.Authenticated},
		{"Authorized", a.Runtime.Authorized},
		{"BFRepeating", a.Runtime.BFRepeating},
		{"BFRWP", a.Runtime.BFRWP},
		{"MasterUserMode", a.Runtime.MasterUserMode},
		// --- Security ---
		{"BruteForceName", a.Security.BruteForceName},
		{"PasswordsAccountSeen", a.Security.PasswordsAccountSeen},
		{"PasswordsTotalSeen", a.Security.PasswordsTotalSeen},
		{"LoginAttempts", a.Security.LoginAttempts},
	}
}

// SetUsername sets the username for the AuthState instance to the given value.
func (a *AuthState) SetUsername(username string) {
	a.Request.Username = username
}

// SetAccount sets the account for the AuthState instance.
func (a *AuthState) SetAccount(account string) {
	a.Runtime.AccountName = account
}

// SetTOTPSecret sets the TOTP secret for the AuthState instance.
func (a *AuthState) SetTOTPSecret(totpSecret string) {
	a.Runtime.TOTPSecret = totpSecret
}

// SetTOTPSecretField sets the TOTP secret field for the AuthState object.
func (a *AuthState) SetTOTPSecretField(totpSecretField string) {
	a.Runtime.TOTPSecretField = totpSecretField
}

// SetTOTPRecoveryField sets the TOTP recovery field for the AuthState object.
func (a *AuthState) SetTOTPRecoveryField(totpRecoveryField string) {
	a.Runtime.TOTPRecoveryField = totpRecoveryField
}

// SetPassword sets the password for the AuthState instance.
func (a *AuthState) SetPassword(password secret.Value) {
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

// SetSAMLEntityID sets the SAML Entity ID for the AuthState instance. It updates the SAMLEntityID field with the provided value.
func (a *AuthState) SetSAMLEntityID(samlEntityID string) {
	a.Request.SAMLEntityID = samlEntityID
}

// SetNoAuth configures the authentication state to enable or disable "NoAuth" mode based on the provided boolean value.
func (a *AuthState) SetNoAuth(noAuth bool) {
	a.Request.NoAuth = noAuth
}

// SetProtocol sets the protocol for the AuthState using the given Protocol configuration.
func (a *AuthState) SetProtocol(protocol *config.Protocol) {
	a.Request.Protocol = protocol
}

// FinishSetup completes the initialization of the state and logs the incoming request.
func (a *AuthState) FinishSetup(ctx *gin.Context) {
	if a == nil || ctx == nil {
		return
	}

	svc := ctx.GetString(definitions.CtxServiceKey)
	if svc == "" {
		// Fallback for native-idp if not set
		svc = definitions.CatAuth
	}

	a.SetStatusCodes(svc)
	setupAuth(ctx, a)

	logProcessingRequest(ctx, a)
}

// FinishLogging logs the authentication result and updates metrics.
func (a *AuthState) FinishLogging(ctx *gin.Context, result definitions.AuthResult) {
	if a == nil || ctx == nil {
		return
	}

	if result == definitions.AuthResultOK {
		handleLogging(ctx, a)
	} else {
		a.loginAttemptProcessing(ctx)
	}
}

// SetLoginAttempts sets the number of login attempts for the AuthState instance.
func (a *AuthState) SetLoginAttempts(loginAttempts uint) {
	a.Security.LoginAttempts = loginAttempts
}

// SyncLoginAttemptsFromAttemptOrdinal updates the internal login attempt manager
// from a 1-based attempt ordinal and mirrors the normalized fail count.
func (a *AuthState) SyncLoginAttemptsFromAttemptOrdinal(ordinal uint) {
	if ordinal == 0 {
		return
	}

	lam := a.ensureLAM()
	if lam == nil {
		a.Security.LoginAttempts = ordinal - 1

		return
	}

	lam.InitFromAttemptOrdinal(ordinal)
	a.Security.LoginAttempts = lam.FailCount()
}

// SyncLoginAttemptsFromHeader updates the internal login attempt manager from
// a header value containing a 1-based attempt ordinal.
func (a *AuthState) SyncLoginAttemptsFromHeader(headerValue string) {
	lam := a.ensureLAM()
	if lam == nil {
		return
	}

	lam.InitFromHeader(headerValue)
	a.Security.LoginAttempts = lam.FailCount()
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

// GetPassword retrieves the password stored in the AuthState instance.
func (a *AuthState) GetPassword() secret.Value {
	return a.Request.Password
}

func (a *AuthState) passwordString() string {
	var password string

	a.Request.Password.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		password = string(value)
	})

	return password
}

func (a *AuthState) passwordBytes() []byte {
	var password []byte

	a.Request.Password.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		password = bytes.Clone(value)
	})

	return password
}

// PasswordString materializes the password as a short-lived string.
func (a *AuthState) PasswordString() string {
	return a.passwordString()
}

// PasswordBytes materializes the password as a short-lived byte slice.
func (a *AuthState) PasswordBytes() []byte {
	return a.passwordBytes()
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

// GetUsedPassDBBackendName returns the name of the currently used backend for password database operations.
func (a *AuthState) GetUsedPassDBBackendName() string {
	return a.Runtime.BackendName
}

// GetSourcePassDBBackend returns the source backend used for the password database during the authentication process.
func (a *AuthState) GetSourcePassDBBackend() definitions.Backend {
	return a.Runtime.SourcePassDBBackend
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

// SetAttributeValues replaces one attribute with a defensive copy of values.
func (a *AuthState) SetAttributeValues(name string, values []any) {
	if a == nil || name == "" {
		return
	}

	a.Attributes.attributesMu.Lock()
	defer a.Attributes.attributesMu.Unlock()

	if a.Attributes.Attributes == nil {
		a.Attributes.Attributes = make(bktype.AttributeMapping)
	}

	a.Attributes.Attributes[name] = append([]any(nil), values...)
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

// SetResolvedGroups replaces the resolved group names and group DNs.
func (a *AuthState) SetResolvedGroups(groups []string, groupDistinguishedNames []string) {
	if a == nil {
		return
	}

	a.Groups.groupsMu.Lock()
	a.Groups.Groups = normalizeStringSet(groups)
	a.Groups.GroupDistinguishedNames = normalizeStringSet(groupDistinguishedNames)
	a.Groups.groupsMu.Unlock()
}

// GetGroups returns a copy of resolved group names.
func (a *AuthState) GetGroups() []string {
	if a == nil {
		return nil
	}

	return a.copyResolvedGroupValues(func(groups *AuthGroups) []string {
		return groups.Groups
	})
}

// GetGroupDistinguishedNames returns a copy of resolved group distinguished names.
func (a *AuthState) GetGroupDistinguishedNames() []string {
	if a == nil {
		return nil
	}

	return a.copyResolvedGroupValues(func(groups *AuthGroups) []string {
		return groups.GroupDistinguishedNames
	})
}

// copyResolvedGroupValues returns a stable copy of one resolved group slice under the group lock.
func (a *AuthState) copyResolvedGroupValues(selectValues func(*AuthGroups) []string) []string {
	a.Groups.groupsMu.RLock()
	defer a.Groups.groupsMu.RUnlock()

	values := selectValues(&a.Groups)
	if len(values) == 0 {
		return nil
	}

	out := make([]string, len(values))
	copy(out, values)

	return out
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
	if a.Runtime.TOTPSecret != "" {
		return a.Runtime.TOTPSecret
	}

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

// GetTOTPRecoveryCodes returns the TOTP recovery codes for a user.
func (a *AuthState) GetTOTPRecoveryCodes() []string {
	if recoveryCodes, okay := a.GetAttribute(a.GetTOTPRecoveryField()); okay {
		codes := make([]string, 0, len(recoveryCodes))
		for _, v := range recoveryCodes {
			if s, ok := v.(string); ok {
				codes = append(codes, s)
			}
		}

		return codes
	}

	return nil
}

// PurgeCache invalidates the user authentication cache.
func (a *AuthState) PurgeCache() {
	a.PurgeCacheFor(a.GetUsername())
}

// PurgeCacheFor invalidates the user authentication cache for a specific username.
func (a *AuthState) PurgeCacheFor(username string) {
	if username == "" {
		return
	}

	a.AccountCache().Purge(username)

	if cs := getCacheService(); cs != nil {
		cs.Purge(a, username)
	}
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
// It sets Auth-Status to the selected response-boundary status message.
// It sets X-Nauthilus-Session to the authentication GUID.
// It falls back to the default password-failure message when no status message was selected.
//
// If the Service field of the authentication is equal to global.ServUserInfo, it also sets the following headers:
//   - "X-User-Found" header to the string representation of the UserFound field of the authentication
//   - If the PasswordHistory field is not nil, it responds with a JSON representation of the PasswordHistory.
//     If the PasswordHistory field is nil, it responds with an empty JSON object.
//
// If the Service field is not equal to global.ServUserInfo, it responds with the selected status message as plain text.
func (a *AuthState) setFailureHeaders(ctx *gin.Context, render responseMessageRenderer) {
	a.prepareAuthFailure()

	statusMessage := a.Runtime.StatusMessage
	if render != nil {
		statusMessage = render(ctx, a)
	}

	ctx.Header("Auth-Status", statusMessage)
	ctx.Header("X-Nauthilus-Session", a.Runtime.GUID)

	switch a.Request.Service {
	case definitions.ServHeader, definitions.ServNginx, definitions.ServJSON:
		a.setAuthWaitHeader(ctx)

		// Do not include password history in responses; always return JSON null on failure
		ctx.JSON(a.Runtime.StatusCodeFail, nil)
	case definitions.ServCBOR:
		a.setAuthWaitHeader(ctx)

		sendCBOR(ctx, a.Runtime.StatusCodeFail, nil)
	default:
		ctx.String(a.Runtime.StatusCodeFail, statusMessage)
	}
}

func (a *AuthState) setAuthWaitHeader(ctx *gin.Context) {
	maxWaitDelay := uint(a.Cfg().GetServer().GetNginxWaitDelay())
	if maxWaitDelay == 0 {
		return
	}

	waitDelay := bfWaitDelay(maxWaitDelay, a.Security.LoginAttempts)
	ctx.Header("Auth-Wait", fmt.Sprintf("%v", waitDelay))
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

// IsMasterUser checks whether the current user matches the configured master-user login format.
// It returns true only when master-user mode is enabled and the configured format can be parsed unambiguously.
func (a *AuthState) IsMasterUser() bool {
	return a.masterUserIdentity().active
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
			err = checkAllBackends(configErrors, passDBs, auth)
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
// A backend is considered "real" (non-cache) if it is not BackendCache. Only if every real backend
// has a configuration error do we report ErrAllBackendConfigError.
func checkAllBackends(configErrors map[definitions.Backend]error, passDBs []*PassDBMap, auth *AuthState) (err error) {
	realBackends := 0
	failedBackends := 0

	for _, pdb := range passDBs {
		if pdb.backend == definitions.BackendCache {
			continue
		}

		realBackends++

		if cfgErr, exists := configErrors[pdb.backend]; exists && cfgErr != nil {
			failedBackends++
		}
	}

	// If all real Database backends failed, we must return with a temporary failure
	if realBackends > 0 && failedBackends == realBackends {
		details := collectConfigErrorDetails(configErrors)
		err = errors.ErrAllBackendConfigError.WithDetail(details)

		level.Error(auth.logger()).Log(
			definitions.LogKeyGUID, auth.Runtime.GUID,
			"passdb", "all",
			definitions.LogKeyMsg, "All backends failed",
			definitions.LogKeyError, err,
			"details", details,
		)
	}

	return err
}

// collectConfigErrorDetails builds a summary string from all backend configuration errors.
func collectConfigErrorDetails(configErrors map[definitions.Backend]error) string {
	var parts []string

	for configIndex, cfgErr := range configErrors {
		if cfgErr == nil {
			continue
		}

		detail := cfgErr.Error()

		if detailedErr, ok := stderrors.AsType[*errors.DetailedError](cfgErr); ok {
			if d := detailedErr.GetDetails(); d != "" {
				detail = d
			}
		}

		parts = append(parts, fmt.Sprintf("%s: %s", configIndex, detail))
	}

	sort.Strings(parts)

	return strings.Join(parts, "; ")
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
		"passdb_result", passDBResult.String(),
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
		auth.applyFoundPassDBRuntime(passDBResult, passDB)
	}

	auth.applyPassDBRuntimeFields(passDBResult)
	auth.applyPassDBAttributes(ctx, passDBResult)
	auth.syncAccountFromPassDBAttributes(ctx)
}

// applyFoundPassDBRuntime records backend identity for a found user.
func (a *AuthState) applyFoundPassDBRuntime(passDBResult *PassDBResult, passDB *PassDBMap) {
	a.Runtime.UserFound = true
	a.Runtime.SourcePassDBBackend = passDBResult.Backend
	a.Runtime.BackendName = passDBResult.BackendName

	if !passDBResult.BackendRef.IsZero() {
		a.Runtime.RemoteBackendRef = passDBResult.BackendRef
	}

	if passDB != nil {
		a.Runtime.UsedPassDBBackend = passDB.backend

		return
	}

	a.Runtime.UsedPassDBBackend = passDBResult.Backend
}

// applyPassDBRuntimeFields copies non-empty runtime fields from the backend result.
func (a *AuthState) applyPassDBRuntimeFields(passDBResult *PassDBResult) {
	if passDBResult.AccountField != "" {
		a.Runtime.AccountField = passDBResult.AccountField
	}

	if passDBResult.Account != "" {
		a.Runtime.AccountName = passDBResult.Account
	}

	if passDBResult.TOTPSecretField != "" {
		a.Runtime.TOTPSecretField = passDBResult.TOTPSecretField
	}

	if passDBResult.TOTPRecoveryField != "" {
		a.Runtime.TOTPRecoveryField = passDBResult.TOTPRecoveryField
	}

	if passDBResult.UniqueUserIDField != "" {
		a.Runtime.UniqueUserIDField = passDBResult.UniqueUserIDField
	}

	if passDBResult.DisplayNameField != "" {
		a.Runtime.DisplayNameField = passDBResult.DisplayNameField
	}
}

// applyPassDBAttributes installs backend attributes and request-scoped additional attributes.
func (a *AuthState) applyPassDBAttributes(ctx *gin.Context, passDBResult *PassDBResult) {
	if len(passDBResult.Attributes) > 0 {
		a.ReplaceAllAttributes(passDBResult.Attributes)
	}

	if passDBResult.UserFound {
		a.SetResolvedGroups(passDBResult.Groups, passDBResult.GroupDistinguishedNames)
	}

	// Handle AdditionalAttributes if they exist in the PassDBResult
	if len(passDBResult.AdditionalAttributes) > 0 {
		// Set AdditionalAttributes in the gin.Context
		ctx.Set(definitions.CtxAdditionalAttributesKey, passDBResult.AdditionalAttributes)
	}
}

// syncAccountFromPassDBAttributes mirrors the authoritative account attribute into context and Redis.
func (a *AuthState) syncAccountFromPassDBAttributes(ctx *gin.Context) {
	account, ok := a.accountFromPassDBAttributes()
	if !ok {
		return
	}

	prev := ctx.GetString(definitions.CtxAccountKey)
	ctx.Set(definitions.CtxAccountKey, account)
	a.logAccountAttributeSource(prev, account)
	a.syncUserAccountMapping(account)
}

// accountFromPassDBAttributes returns the single-valued account attribute when present.
func (a *AuthState) accountFromPassDBAttributes() (string, bool) {
	vals, ok := a.GetAttribute(a.Runtime.AccountField)
	if !ok {
		return "", false
	}

	account, ok := vals[definitions.LDAPSingleValue].(string)
	if !ok || account == "" {
		return "", false
	}

	return account, true
}

// logAccountAttributeSource records the attribute-derived account source decision.
func (a *AuthState) logAccountAttributeSource(previous string, account string) {
	util.DebugModuleWithCfg(
		a.Ctx(),
		a.deps.Cfg,
		a.deps.Logger,
		definitions.DbgAccount,
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyUsername, a.Request.Username,
		definitions.LogKeyMsg, "Set account from attributes",
		"prev", previous,
		"new", account,
		"source", "attribute",
		"changed", previous != account,
	)
}

// syncUserAccountMapping updates Redis when the attribute-derived account differs.
func (a *AuthState) syncUserAccountMapping(account string) {
	current, ok := a.currentUserAccountMapping()
	if !ok {
		return
	}

	if current != "" && current == account {
		return
	}

	a.setUserAccountMapping(account)
}

// currentUserAccountMapping reads the current user-to-account mapping with a bounded deadline.
func (a *AuthState) currentUserAccountMapping() (string, bool) {
	dReadCtx, cancelRead := util.GetCtxWithDeadlineRedisRead(a.Ctx(), a.Cfg())
	current, err := backend.LookupUserAccountFromRedis(dReadCtx, a.Cfg(), a.deps.Redis, a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID)

	cancelRead()

	if err != nil {
		level.Error(a.Logger()).Log(
			definitions.LogKeyGUID, a.Runtime.GUID,
			definitions.LogKeyMsg, "Failed to lookup user->account mapping in Redis",
			definitions.LogKeyError, err,
		)

		return "", false
	}

	return current, true
}

// setUserAccountMapping writes the user-to-account mapping with a bounded deadline.
func (a *AuthState) setUserAccountMapping(account string) {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dWriteCtx, cancelWrite := util.GetCtxWithDeadlineRedisWrite(context.TODO(), a.Cfg())
	werr := backend.SetUserAccountMapping(dWriteCtx, a.Cfg(), a.deps.Redis, a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID, account)

	cancelWrite()

	if werr != nil {
		level.Error(a.Logger()).Log(
			definitions.LogKeyGUID, a.Runtime.GUID,
			definitions.LogKeyMsg, "Failed to update user->account mapping in Redis",
			definitions.LogKeyError, werr,
		)

		return
	}

	util.DebugModuleWithCfg(
		a.Ctx(),
		a.deps.Cfg, a.deps.Logger, definitions.DbgAccount,
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyUsername, a.Request.Username,
		definitions.LogKeyMsg, "Synchronized nt:USER mapping",
		"account", account,
		"source", "redis-update",
	)
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
	accountName, err := backend.LookupUserAccountFromRedis(a.Ctx(), a.Cfg(), a.deps.Redis, a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID)
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
	accountName = backend.GetUserAccountFromCache(dCtx, a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID, a.Runtime.GUID)

	cancel()

	if accountName == "" {
		return
	}

	a.Runtime.AccountName = accountName

	return accountName
}

// traceSetupDetails adds details from the authentication state to the provided span.
// It includes key request metadata while ensuring sensitive information like passwords
// and local network details are excluded. SSL information is limited to common fields.
func (a *AuthState) traceSetupDetails(tsp trace.Span) {
	if tsp == nil {
		return
	}

	mode := string(AuthModeAuthenticate)
	if a.Request.NoAuth {
		mode = authModeNoAuth
	}

	tsp.SetAttributes(
		attribute.String(definitions.LogKeyGUID, a.Runtime.GUID),
		attribute.String(definitions.LogKeyMode, mode),
		attribute.String(definitions.LogKeyProtocol, a.Request.Protocol.String()),
		attribute.String(definitions.LogKeyOIDCCID, a.Request.OIDCCID),
		attribute.String(definitions.LogKeySAMLEntityID, a.Request.SAMLEntityID),
		attribute.String(definitions.LogKeyClientIP, a.Request.ClientIP),
		attribute.String(definitions.LogKeyClientPort, a.Request.XClientPort),
		attribute.String(definitions.LogKeyClientHost, a.Request.ClientHost),
		attribute.String(definitions.LogKeyTLSSecure, a.Request.XSSLProtocol),
		attribute.String(definitions.LogKeyTLSCipher, a.Request.XSSLCipher),
		attribute.String(definitions.LogKeyAuthMethod, a.Request.Method),
		attribute.String(definitions.LogKeyUsername, a.Request.Username),
		attribute.String(definitions.LogKeyUserAgent, a.Request.UserAgent),
		attribute.String(definitions.LogKeyClientID, a.Request.XClientID),
	)
}

// FillCommonRequest populates a CommonRequest object from the current AuthState.
func (a *AuthState) FillCommonRequest(cr *lualib.CommonRequest) {
	if cr == nil {
		return
	}

	a.fillCommonIdentityFields(cr)
	a.fillCommonConnectionFields(cr)
	a.fillCommonRuntimeFields(cr)
	a.fillCommonBruteForceCounter(cr)
	a.fillIDPFields(cr)
}

// fillCommonIdentityFields copies account and protocol fields.
func (a *AuthState) fillCommonIdentityFields(cr *lualib.CommonRequest) {
	cr.Session = a.Runtime.GUID
	cr.ExternalSessionID = a.Request.ExternalSessionID
	cr.HealthCheck = a.IsBackendHealthCheckRequest()
	cr.Username = a.Request.Username
	cr.Password = a.passwordBytes()
	cr.ClientIP = a.Request.ClientIP
	cr.Account = a.GetAccount()
	cr.AccountField = a.Runtime.AccountField
	cr.UniqueUserID = a.GetUniqueUserID()
	cr.DisplayName = a.GetDisplayName()
	cr.Service = a.Request.Service
	cr.OIDCCID = a.Request.OIDCCID
	cr.SAMLEntityID = a.Request.SAMLEntityID
	cr.Protocol = a.Request.Protocol.Get()
	cr.Method = a.Request.Method
}

// fillCommonConnectionFields copies network, user-agent, and TLS fields.
func (a *AuthState) fillCommonConnectionFields(cr *lualib.CommonRequest) {
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
	cr.AuthLoginAttempt = a.Request.AuthLoginAttempt
}

// fillCommonRuntimeFields copies backend, status, and debug fields.
func (a *AuthState) fillCommonRuntimeFields(cr *lualib.CommonRequest) {
	cr.BackendServers = ListBackendServers()
	cr.UsedBackendAddr = &a.Runtime.UsedBackendIP
	cr.UsedBackendPort = &a.Runtime.UsedBackendPort
	cr.Latency = float64(time.Since(a.Runtime.StartTime).Milliseconds())
	cr.Debug = false
	cr.Repeating = a.Runtime.BFRepeating
	cr.RWP = a.Runtime.BFRWP
	cr.NoAuth = a.Request.NoAuth
	cr.UserFound = a.Runtime.UserFound
	cr.Authenticated = a.Runtime.Authenticated
	cr.BruteForceName = a.Security.BruteForceName
	cr.EnvironmentName = a.Runtime.EnvironmentName
	cr.StatusMessage = &a.Runtime.StatusMessage
	cr.RedisPrefix = a.Cfg().GetServer().GetRedis().GetPrefix()

	if cr.Authenticated {
		cr.HTTPStatus = a.Runtime.StatusCodeOK
	} else {
		cr.HTTPStatus = a.Runtime.StatusCodeFail
	}

	if a.deps.Cfg != nil {
		cr.Debug = a.deps.Cfg.GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	}
}

// fillCommonBruteForceCounter copies the selected brute-force counter value.
func (a *AuthState) fillCommonBruteForceCounter(cr *lualib.CommonRequest) {
	if a.Security.BruteForceName == "" {
		return
	}

	if val, ok := a.Security.BruteForceCounter[a.Security.BruteForceName]; ok {
		cr.BruteForceCounter = val

		return
	}

	parts := strings.Split(a.Security.BruteForceName, ",")
	if val, ok := a.Security.BruteForceCounter[parts[0]]; ok {
		cr.BruteForceCounter = val
	}
}

// IsBackendHealthCheckRequest reports whether the current authentication request matches a configured health-check identity.
func (a *AuthState) IsBackendHealthCheckRequest() bool {
	if a == nil || a.Cfg() == nil {
		return false
	}

	username := strings.TrimSpace(a.Request.Username)
	if username == "" {
		return false
	}

	service := strings.ToLower(strings.TrimSpace(a.Request.Service))
	protocol := strings.ToLower(strings.TrimSpace(a.Request.Protocol.Get()))

	for _, server := range a.Cfg().GetBackendServers() {
		if server == nil || server.TestUsername == "" {
			continue
		}

		if username != strings.TrimSpace(server.TestUsername) {
			continue
		}

		serverProtocol := strings.ToLower(strings.TrimSpace(server.Protocol))

		if service == "" && protocol == "" {
			return true
		}

		if serverProtocol == service || serverProtocol == protocol {
			return true
		}
	}

	return false
}

// findOIDCClient looks up an OIDC client by its ID from the loaded configuration.
func (a *AuthState) findOIDCClient(clientID string) *config.OIDCClient {
	cfg := a.Cfg()
	if cfg == nil || cfg.GetIDP() == nil {
		return nil
	}

	clients := cfg.GetIDP().OIDC.Clients

	for i := range clients {
		if clients[i].ClientID == clientID {
			return &clients[i]
		}
	}

	return nil
}

// fillIDPFields enriches the CommonRequest with IDP-specific data read from the
// session cookie (grant type, scopes, redirect URI, MFA status) and the OIDC client
// configuration (client name, allowed scopes, allowed grant types).
func (a *AuthState) fillIDPFields(cr *lualib.CommonRequest) {
	if a.Request.HTTPClientContext == nil {
		return
	}

	mgr := cookie.GetManager(a.Request.HTTPClientContext)
	if mgr != nil {
		cr.GrantType = mgr.GetString(definitions.SessionKeyOIDCGrantType, "")
		cr.RedirectURI = mgr.GetString(definitions.SessionKeyIDPRedirectURI, "")
		cr.MFACompleted = mgr.GetBool(definitions.SessionKeyMFACompleted, false)
		cr.MFAMethod = mgr.GetString(definitions.SessionKeyMFAMethod, "")

		if scopeStr := mgr.GetString(definitions.SessionKeyIDPScope, ""); scopeStr != "" {
			cr.RequestedScopes = strings.Split(scopeStr, " ")
		}
	}

	if a.Request.OIDCCID != "" {
		if client := a.findOIDCClient(a.Request.OIDCCID); client != nil {
			cr.OIDCClientName = client.Name
			cr.AllowedClientScopes = client.GetAllowedScopes()
			cr.AllowedClientGrantTypes = client.GetGrantTypes()
		}
	}

	cr.UserGroups = a.GetGroups()

	if cr.GrantType == "" {
		if grantType, exists := a.Request.HTTPClientContext.Get(definitions.CtxOIDCGrantTypeKey); exists {
			if value, ok := grantType.(string); ok {
				cr.GrantType = value
			}
		}
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
	if a == nil {
		return ""
	}

	bm := a.createBucketManager(a.Ctx())

	return bm.GetBruteForceBucketRedisKey(rule)
}

// GetBruteForceBanRedisKey returns the Redis ban key and normalized network for the specified brute force rule.
func (a *AuthState) GetBruteForceBanRedisKey(rule *config.BruteForceRule) (key string, network string, err error) {
	if a == nil {
		return "", "", nil
	}

	bm := a.createBucketManager(a.Ctx())

	return bm.GetBruteForceBanRedisKey(rule)
}

// GetBucketKeys returns all Redis keys associated with a brute force rule.
func (a *AuthState) GetBucketKeys(rule *config.BruteForceRule) []string {
	if a == nil {
		return nil
	}

	bm := a.createBucketManager(a.Ctx())

	return bm.GetBucketKeys(rule)
}

// GetSlidingWindowKeys returns the current and previous window keys for a rule.
func (a *AuthState) GetSlidingWindowKeys(rule *config.BruteForceRule, network *net.IPNet) (currentKey, prevKey string, weight float64) {
	if a == nil {
		return "", "", 0
	}

	bm := a.createBucketManager(a.Ctx())

	return bm.GetSlidingWindowKeys(rule, network)
}

// GetEnvironmentName returns the environment name from the AuthState.
func (a *AuthState) GetEnvironmentName() string {
	return a.Runtime.EnvironmentName
}

// WithUsername sets the username in the AuthState.
func (a *AuthState) WithUsername(username string) bruteforce.BucketManager {
	a.Request.Username = username

	return a
}

// WithPassword sets the password in the AuthState.
func (a *AuthState) WithPassword(password secret.Value) bruteforce.BucketManager {
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

// WithRWPDecision sets the cached RWP enforcement decision (true=enforce, false=RWP active).
func (a *AuthState) WithRWPDecision(enforce bool) bruteforce.BucketManager {
	a.Runtime.BFRWP = !enforce

	return a
}

// GetTolerationPolicyFact returns the last collected toleration policy fact.
func (a *AuthState) GetTolerationPolicyFact() tolerate.PolicyFact {
	if a == nil {
		return tolerate.PolicyFact{}
	}

	return a.Runtime.BruteForceToleration
}

// GetBruteForceName returns the brute force name from the AuthState.
func (a *AuthState) GetBruteForceName() string {
	return a.Security.BruteForceName
}

// LoadAllPasswordHistories loads all password histories for the current AuthState.
func (a *AuthState) LoadAllPasswordHistories() {
	if !a.deps.Cfg.HasRuntimeModule(definitions.ControlBruteForce) {
		return
	}

	bm := a.createBucketManager(a.Ctx())
	bm.LoadAllPasswordHistories()
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

// GetBucketPolicyFacts returns the last collected brute-force bucket policy facts.
func (a *AuthState) GetBucketPolicyFacts() []bruteforce.BucketPolicyFact {
	if a == nil || len(a.Runtime.BruteForceBuckets) == 0 {
		return nil
	}

	return append([]bruteforce.BucketPolicyFact(nil), a.Runtime.BruteForceBuckets...)
}

// CollectBucketPolicyFacts reads current brute-force bucket policy facts.
func (a *AuthState) CollectBucketPolicyFacts(rules []config.BruteForceRule) ([]bruteforce.BucketPolicyFact, error) {
	bm := a.createBucketManager(a.Ctx())
	facts, err := bm.CollectBucketPolicyFacts(rules)
	a.Runtime.BruteForceBuckets = facts

	return facts, err
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

// CommitRWPSlidingWindow delegates to the underlying BucketManager to write the RWP hash.
func (a *AuthState) CommitRWPSlidingWindow() {
	bm := a.createBucketManager(a.Ctx())
	bm.CommitRWPSlidingWindow()
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

// ShouldEnforceBucketUpdate determines whether brute force bucket counters should be increased.
func (a *AuthState) ShouldEnforceBucketUpdate() (bool, error) {
	bm := a.createBucketManager(a.Ctx())

	return bm.ShouldEnforceBucketUpdate()
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

// PostLuaAction executes a Lua-based post-processing action using the given authentication result and context.
func (a *AuthState) PostLuaAction(ctx *gin.Context, passDBResult *PassDBResult) {
	if disp := getPostAction(); disp != nil {
		disp.Run(a.newPostActionInput(ctx, passDBResult))
	}
}

// newPostActionInput captures the request flags used by Lua post-actions.
func (a *AuthState) newPostActionInput(ctx *gin.Context, passDBResult *PassDBResult) PostActionInput {
	environmentRejected := false
	environmentStageExpected := true
	subjectStageExpected := true

	if ctx != nil {
		environmentRejected = ctx.GetBool(definitions.CtxEnvironmentRejectedKey)
	}

	if environmentRejected {
		subjectStageExpected = false

		if a.Runtime.EnvironmentName == definitions.ControlBruteForce {
			environmentStageExpected = false
		}
	}

	return PostActionInput{
		View:                     a.View(),
		Result:                   passDBResult,
		EnvironmentRejected:      environmentRejected,
		EnvironmentStageExpected: environmentStageExpected,
		SubjectStageExpected:     subjectStageExpected,
	}
}

func (a *AuthState) markEnvironmentRejected(ctx *gin.Context) {
	if ctx == nil {
		return
	}

	ctx.Set(definitions.CtxEnvironmentRejectedKey, true)
}

// HaveMonitoringFlag checks if the provided flag exists in the MonitoringFlags slice of the AuthState object.
// It iterates over the MonitoringFlags slice and returns true if the flag is found, otherwise it returns false.
func (a *AuthState) HaveMonitoringFlag(flag definitions.Monitoring) bool {
	return slices.Contains(a.Runtime.MonitoringFlags, flag)
}

// SFKeyHash returns a short hash for the strict singleflight key to use in Redis keys.
func (a *AuthState) SFKeyHash() string {
	sum := sha1.Sum([]byte(a.generateSingleflightKey()))

	return hex.EncodeToString(sum[:])
}

// HandlePassword handles the authentication process for the password flow.
// Delegate orchestration to the Authenticator to keep responsibilities separated.
func (a *AuthState) HandlePassword(ctx *gin.Context) (authResult definitions.AuthResult) {
	defer a.completePolicyStage(ctx, policy.StageAuthBackend)

	authResult = defaultAuthenticator.Authenticate(ctx, a)
	if authResult == definitions.AuthResultEmptyUsername || authResult == definitions.AuthResultEmptyPassword {
		a.recordPolicyBackendResult(ctx, authResult, nil, nil)
	}

	if configuredResult, ok := a.configuredPolicyAuthResult(ctx, authResult); ok {
		return configuredResult
	}

	return a.defaultPolicyAuthResult(ctx, authResult)
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

	if !a.Request.NoAuth && a.Request.Password.IsZero() {
		util.DebugModuleWithCfg(a.Ctx(), a.Cfg(), a.Logger(), definitions.DbgAuth, definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMsg, "Empty password")

		return definitions.AuthResultEmptyPassword
	}

	return definitions.AuthResultUnset
}

// handleLocalCache handles the local cache authentication logic for the AuthState object.
// It sets the operation mode and initializes the passDBResult.
// Then, it applies Lua subject analysis to the authentication result.
// After that, the PostLuaAction is executed on the passDBResult.
// Finally, it returns the authResult of type definitions.AuthResult.
func (a *AuthState) handleLocalCache(ctx *gin.Context) definitions.AuthResult {
	resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_local_cache_path_total", resource); stop != nil {
		defer stop()
	}

	a.SetOperationMode(ctx)

	passDBResult := a.initializePassDBResult()

	defer PutPassDBResultToPool(passDBResult)

	// Since this path is a confirmed positive hit from the in-memory cache,
	// the PassDB stage has already decided previously. Reflect that in AuthState
	// so final logs include authn=true for cache hits.
	a.Runtime.Authenticated = true
	a.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

	return a.runPostBackendActions(ctx, passDBResult)
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

// buildBackendExecutionPlan converts the configured backend order into executable backends and side-effect metadata.
func (a *AuthState) buildBackendExecutionPlan() backendExecutionPlan {
	plan := backendExecutionPlan{
		positions: make(map[definitions.Backend]int),
	}

	cfg := a.Cfg()

	for index, backendType := range cfg.GetServer().GetBackends() {
		db := backendType.Get()
		a.appendConfiguredBackend(&plan, backendType)
		plan.positions[db] = index
	}

	return plan
}

func (a *AuthState) appendConfiguredBackend(plan *backendExecutionPlan, backendType *config.Backend) {
	switch backendType.Get() {
	case definitions.BackendCache:
		a.appendCacheBackend(plan)
	case definitions.BackendLDAP:
		a.appendLDAPBackend(plan, backendType.GetName())
	case definitions.BackendLua:
		a.appendLuaBackend(plan, backendType.GetName())
	case definitions.BackendTest:
		a.appendTestBackend(plan, backendType.GetName())
	case definitions.BackendRemote:
		a.appendRemoteBackend(plan, backendType.GetName())
	case definitions.BackendPlugin:
		a.appendPluginBackend(plan, backendType.GetName())
	case definitions.BackendUnknown:
	case definitions.BackendLocalCache:
	}
}

func (a *AuthState) appendCacheBackend(plan *backendExecutionPlan) {
	if a.HaveMonitoringFlag(definitions.MonCache) || a.IsMasterUser() {
		return
	}

	plan.passDBs = a.appendBackend(plan.passDBs, definitions.BackendCache, CachePassDB)
	plan.hasPositivePasswordCache = true
}

func (a *AuthState) appendLDAPBackend(plan *backendExecutionPlan, name string) {
	if a.Cfg().LDAPHavePoolOnly(name) {
		return
	}

	mgr := NewLDAPManager(name, a.deps)
	plan.passDBs = a.appendBackend(plan.passDBs, definitions.BackendLDAP, mgr.PassDB)
}

func (a *AuthState) appendLuaBackend(plan *backendExecutionPlan, name string) {
	mgr := NewLuaManager(name, a.deps)
	plan.passDBs = a.appendBackend(plan.passDBs, definitions.BackendLua, mgr.PassDB)
}

func (a *AuthState) appendTestBackend(plan *backendExecutionPlan, name string) {
	mgr := NewTestBackendManager(name, a.deps)
	plan.passDBs = a.appendBackend(plan.passDBs, definitions.BackendTest, mgr.PassDB)
}

func (a *AuthState) appendRemoteBackend(plan *backendExecutionPlan, name string) {
	mgr := a.GetBackendManager(definitions.BackendRemote, name)
	if mgr == nil {
		return
	}

	plan.passDBs = a.appendBackend(plan.passDBs, definitions.BackendRemote, mgr.PassDB)
}

// appendPluginBackend appends a registered native plugin backend manager.
func (a *AuthState) appendPluginBackend(plan *backendExecutionPlan, name string) {
	mgr := a.GetBackendManager(definitions.BackendPlugin, name)
	if mgr == nil {
		return
	}

	plan.passDBs = a.appendBackend(plan.passDBs, definitions.BackendPlugin, mgr.PassDB)
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

type verifyPasswordResult struct {
	value  any
	err    error
	shared bool
}

// processVerifyPassword verifies the user's password against multiple databases.
// It logs detailed information in case of errors and returns the result of the password verification process.
func (a *AuthState) processVerifyPassword(ctx *gin.Context, passDBs []*PassDBMap) (*PassDBResult, error) {
	tr := monittrace.New("nauthilus/auth")

	_, waitSpan := tr.Start(ctx.Request.Context(), "auth.verify.wait",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)
	defer waitSpan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_verify_password_total", ctx.FullPath()); stop != nil {
		defer stop()
	}

	workerAuth, workerCtx := a.newVerificationWorkerState(ctx)
	service := a.Request.Service
	username := a.Request.Username

	resCh := backchanSF.DoChan(verifyPasswordSingleflightKey(ctx, a), func() (any, error) {
		vctx, vspan := tr.Start(workerCtx.Request.Context(), "auth.verify",
			attribute.String("service", service),
			attribute.String("username", username),
		)
		defer vspan.End()

		workerCtx.Request = workerCtx.Request.WithContext(vctx)
		workerAuth.Request.HTTPClientContext = workerCtx
		workerAuth.Request.HTTPClientRequest = workerCtx.Request
		workerAuth.operationContext = vctx
		result, err := workerAuth.verifyPassword(workerCtx, passDBs)
		recordVerifyPasswordSpan(vspan, result, err)

		return verificationWorkResult{owner: a, auth: workerAuth, result: result}, err
	})

	verifyResult, waitErr := a.waitVerifyPasswordResult(ctx, resCh)
	if waitErr != nil {
		waitSpan.RecordError(waitErr)

		return nil, waitErr
	}

	waitSpan.SetAttributes(attribute.Bool("shared", verifyResult.shared))

	passDBResult := a.passDBResultFromVerifyValue(ctx, verifyResult)
	a.logVerifyPasswordError(verifyResult.err)

	return passDBResult, verifyResult.err
}

// verifyPasswordSingleflightKey returns the deduplication key for password verification.
func verifyPasswordSingleflightKey(ctx *gin.Context, auth *AuthState) string {
	if idem := ctx.GetHeader(idempotencyHeaderName); idem != "" {
		return "idem:" + idem
	}

	return auth.Runtime.GUID
}

// waitVerifyPasswordResult waits for singleflight or request cancellation.
func (a *AuthState) waitVerifyPasswordResult(ctx *gin.Context, resCh <-chan singleflight.Result) (verifyPasswordResult, error) {
	select {
	case <-util.HTTPRequestDone(ctx.Request):
		if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "verify.singleflight_wait") {
			return verifyPasswordResult{}, util.HTTPRequestContextError(ctx.Request)
		}
	case result := <-resCh:
		return verifyPasswordResult{
			value:  result.Val,
			err:    result.Err,
			shared: result.Shared,
		}, nil
	}

	return verifyPasswordResult{}, nil
}

// passDBResultFromVerifyValue clones shared results before applying them to the auth state.
func (a *AuthState) passDBResultFromVerifyValue(ctx *gin.Context, result verifyPasswordResult) *PassDBResult {
	if result.value == nil {
		return nil
	}

	workResult := result.value.(verificationWorkResult)

	passDBResult := workResult.result
	if passDBResult == nil {
		return nil
	}

	if workResult.owner == a {
		a.applyVerificationWorkerState(ctx, workResult.auth, passDBResult)

		return passDBResult
	}

	clonedResult := passDBResult.Clone()
	updateAuthentication(ctx, a, clonedResult, nil)

	return clonedResult
}

// recordVerifyPasswordSpan records verification outcome attributes on the active span.
func recordVerifyPasswordSpan(vspan trace.Span, passDBResult *PassDBResult, err error) {
	if passDBResult != nil {
		vspan.SetAttributes(
			attribute.Bool("authenticated", passDBResult.Authenticated),
			attribute.Bool("user_found", passDBResult.UserFound),
			attribute.String("backend", verifyPasswordBackendName(passDBResult)),
		)
	}

	if err != nil {
		vspan.RecordError(err)
	}
}

// verifyPasswordBackendName returns the configured backend name or backend type fallback.
func verifyPasswordBackendName(passDBResult *PassDBResult) string {
	if passDBResult.BackendName != "" {
		return passDBResult.BackendName
	}

	return passDBResult.Backend.String()
}

// logVerifyPasswordError writes detailed verification errors with any collected extra fields.
func (a *AuthState) logVerifyPasswordError(err error) {
	if err == nil {
		return
	}

	if detailedError, ok := stderrors.AsType[*errors.DetailedError](err); ok {
		a.logDetailedVerifyPasswordError(detailedError)

		return
	}

	level.Error(getDefaultLogger()).Log(
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyMsg, "Error verifying password",
		definitions.LogKeyError, err)
}

// logDetailedVerifyPasswordError writes backend-provided verification details.
func (a *AuthState) logDetailedVerifyPasswordError(detailedError *errors.DetailedError) {
	logs := []any{
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyMsg, detailedError.GetDetails(),
		definitions.LogKeyError, detailedError.Error(),
	}

	if len(a.Runtime.AdditionalLogs) > 0 && len(a.Runtime.AdditionalLogs)%2 == 0 {
		logs = append(logs, a.Runtime.AdditionalLogs...)
	}

	level.Error(getDefaultLogger()).Log(logs...)
}

// processUserFound handles the processing when a user is found in the database, updates user account in Redis, and processes password history.
// It returns the account name and any error encountered during the process.
func (a *AuthState) processUserFound(passDBResult *PassDBResult) (accountName string, err error) {
	resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_user_found_total", resource); stop != nil {
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

type backendExecutionPlan struct {
	positions map[definitions.Backend]int
	passDBs   []*PassDBMap

	hasPositivePasswordCache bool
}

func (p backendExecutionPlan) positivePasswordCacheEnabled(usedBackend definitions.Backend) bool {
	if !p.hasPositivePasswordCache || usedBackend == definitions.BackendRemote || usedBackend == definitions.BackendPlugin {
		return false
	}

	return p.cachePrecedes(usedBackend)
}

func (p backendExecutionPlan) cachePrecedes(usedBackend definitions.Backend) bool {
	cachePosition, hasCache := p.positions[definitions.BackendCache]
	if !hasCache {
		return false
	}

	usedPosition, hasUsedBackend := p.positions[usedBackend]
	if !hasUsedBackend {
		return false
	}

	return cachePosition < usedPosition
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
		TOTPRecoveryField: a.Runtime.TOTPRecoveryField,
		UniqueUserIDField: a.Runtime.UniqueUserIDField,
		DisplayNameField:  a.Runtime.DisplayNameField,
		Password: func() string {
			var passwordShort string

			a.Request.Password.WithBytes(func(value []byte) {
				if len(value) == 0 {
					return
				}

				prepared := util.PreparePasswordBytes(value)
				defer clear(prepared)

				passwordShort = util.GetHashBytes(prepared)
			})

			return passwordShort
		}(),
		Backend:                 a.Runtime.SourcePassDBBackend,
		BackendName:             a.Runtime.BackendName,
		Attributes:              a.Attributes.Attributes,
		Groups:                  a.GetGroups(),
		GroupDistinguishedNames: a.GetGroupDistinguishedNames(),
	}
}

// processPositivePasswordCache updates Redis positive-cache entries when the configured backend order enables them.
func (a *AuthState) processPositivePasswordCache(ctx *gin.Context, authenticated bool, accountName string, plan backendExecutionPlan) error {
	positiveCacheEnabled := plan.positivePasswordCacheEnabled(a.Runtime.UsedPassDBBackend)
	tr := monittrace.New("nauthilus/auth")
	cctx, cspan := tr.Start(ctx.Request.Context(), "auth.cache.process",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.Bool("authenticated", authenticated),
		attribute.Bool("positive_cache", positiveCacheEnabled),
	)

	requestScope := a.scopeRequestContext(cctx, ctx)

	defer requestScope.Restore()

	defer cspan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_process_cache_total", ctx.FullPath()); stop != nil {
		defer stop()
	}

	if !positiveCacheEnabled {
		return nil
	}

	if cs := getCacheService(); cs != nil {
		if authenticated {
			if err := cs.OnSuccess(a, accountName); err != nil {
				return err
			}
		} else {
			cs.OnFailure(a, accountName)
		}
	}

	return nil
}

func (a *AuthState) loadBruteForceHistories(ctx *gin.Context, accountName string) {
	if accountName == "" {
		return
	}

	bfLoadHistories(ctx, a, accountName)
}

func (a *AuthState) applyBackendResult(ctx *gin.Context, passDBResult *PassDBResult) {
	if passDBResult.Authenticated {
		a.Runtime.Authenticated = true
		a.Runtime.BFRWP = false
		a.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

		return
	}

	a.UpdateBruteForceBucketsCounter(ctx)
	a.Runtime.Authenticated = false
	a.recordPolicyBackendResult(ctx, definitions.AuthResultFail, passDBResult, nil)
}

func (a *AuthState) storeAuthenticatedLocalCache(passDBResult *PassDBResult) {
	if a.HaveMonitoringFlag(definitions.MonInMemory) || a.IsMasterUser() {
		return
	}

	localcache.LocalCache.Set(a.generateLocalCacheKey(), passDBResult.Clone(), a.Cfg().GetServer().GetLocalCacheAuthTTL())
}

func (a *AuthState) runPostBackendActions(ctx *gin.Context, passDBResult *PassDBResult) definitions.AuthResult {
	authResult := a.SubjectLua(ctx, passDBResult)

	if a.HasConfiguredAuthPolicyAuthority(ctx) {
		a.storePolicyPostActionResult(ctx, passDBResult)
	} else {
		a.PostLuaAction(ctx, passDBResult)
	}

	return authResult
}

func (a *AuthState) processFinalAuthCache(ctx *gin.Context, passDBResult *PassDBResult, authResult definitions.AuthResult, accountName string, plan backendExecutionPlan) error {
	cacheAuthenticated := passDBResult.Authenticated && authResult == definitions.AuthResultOK
	if err := a.processPositivePasswordCache(ctx, cacheAuthenticated, accountName, plan); err != nil {
		return err
	}

	if cacheAuthenticated {
		a.storeAuthenticatedLocalCache(passDBResult)
	}

	return nil
}

// authenticateUser runs backend verification and then applies post-backend side effects.
// Positive password-cache writes are controlled by the backend order, while brute-force
// history loading follows the resolved account independently from the cache backend.
func (a *AuthState) authenticateUser(ctx *gin.Context, plan backendExecutionPlan) definitions.AuthResult {
	tr := monittrace.New("nauthilus/auth")
	actx, aspan := tr.Start(ctx.Request.Context(), "auth.authenticate",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
		attribute.Bool("positive_cache_configured", plan.hasPositivePasswordCache),
	)

	requestScope := a.scopeRequestContext(actx, ctx)

	defer requestScope.Restore()
	defer aspan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_authenticate_user_total", ctx.FullPath()); stop != nil {
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

	if passDBResult, err = a.processVerifyPassword(ctx, plan.passDBs); err != nil {
		// tempfail: no backend decision could be made
		a.Runtime.Authenticated = false
		a.recordPolicyBackendResult(ctx, definitions.AuthResultTempFail, passDBResult, err)

		return definitions.AuthResultTempFail
	}

	defer PutPassDBResultToPool(passDBResult)

	if accountName, err = a.processUserFound(passDBResult); err != nil || passDBResult == nil {
		// treat as tempfail
		a.Runtime.Authenticated = false
		a.recordPolicyBackendResult(ctx, definitions.AuthResultTempFail, passDBResult, err)

		return definitions.AuthResultTempFail
	}

	a.loadBruteForceHistories(ctx, accountName)
	a.applyBackendResult(ctx, passDBResult)
	authResult = a.runPostBackendActions(ctx, passDBResult)
	aspan.SetAttributes(attribute.String("lua.result", string(authResult)))

	if err = a.processFinalAuthCache(ctx, passDBResult, authResult, accountName, plan); err != nil {
		// tempfail during cache processing
		a.Runtime.Authenticated = false
		a.recordPolicyBackendResult(ctx, definitions.AuthResultTempFail, passDBResult, err)

		return definitions.AuthResultTempFail
	}

	return authResult
}

// SubjectLua calls Lua subject sources which can change the backend result.
func (a *AuthState) SubjectLua(ctx *gin.Context, passDBResult *PassDBResult) definitions.AuthResult {
	if util.IsHTTPRequestCanceled(a.Logger(), ctx.Request, a.Runtime.GUID, "subject.lua") {
		return definitions.AuthResultTempFail
	}

	defer a.completePolicyStage(ctx, policy.StageSubjectAnalysis)

	tr := monittrace.New("nauthilus/auth")
	lctx, lspan := tr.Start(ctx.Request.Context(), "auth.lua.subject",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	requestScope := a.scopeRequestContext(lctx, ctx)

	defer requestScope.Restore()

	defer lspan.End()

	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_subject_lua_total", ctx.FullPath()); stop != nil {
		defer stop()
	}

	if lf := getLuaSubject(); lf != nil {
		bridge := getPluginSubjectSourceBridge()
		if scheduledLua, ok := lf.(ScheduledLuaSubject); ok {
			if mixedBridge, mixed := bridge.(MixedPluginSubjectSourceBridge); mixed {
				if result, handled := mixedBridge.AnalyzeMixed(ctx, a.View(), passDBResult, scheduledLua); handled {
					lspan.SetAttributes(attribute.String("result", string(result)))

					return result
				}
			}
		}

		res := lf.Analyze(ctx, a.View(), passDBResult)
		if bridge != nil {
			if next, handled := bridge.Analyze(ctx, a.View(), passDBResult, res); handled {
				res = next
			}
		}

		lspan.SetAttributes(attribute.String("result", string(res)))

		return res
	}

	_ = level.Error(a.logger()).Log(definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMsg, "LuaSubject not registered")

	return definitions.AuthResultTempFail
}

// ListUserAccounts returns the list of all known users from the account databases.
func (a *AuthState) ListUserAccounts() (accountList AccountList) {
	ginCtx := a.Request.HTTPClientContext
	errSeen := false

	defer func() {
		if a.finishListAccountsPolicy(ginCtx, len(accountList), errSeen) {
			return
		}

		a.observeConfiguredPolicyDecision(ginCtx)
	}()

	// Pre-allocate the accounts slice to avoid continuous reallocation
	// This is a conservative estimate, we'll allocate based on the number of backends
	accountList = make(AccountList, 0, 100)

	a.Request.Protocol.Set(definitions.ProtoAccountProvider)

	accounts := a.accountListBackends()
	errSeen = a.appendAccountDBResults(accounts, &accountList)

	return accountList
}

// accountListBackends builds account-database handlers from configured backends.
func (a *AuthState) accountListBackends() []*AccountListMap {
	accounts := make([]*AccountListMap, 0)

	for _, backendType := range a.cfg().GetServer().GetBackends() {
		if accountDB := a.accountListBackend(backendType); accountDB != nil {
			accounts = append(accounts, accountDB)
		}
	}

	return accounts
}

// accountListBackend resolves one configured backend into an account-database handler.
func (a *AuthState) accountListBackend(backendType *config.Backend) *AccountListMap {
	switch backendType.Get() {
	case definitions.BackendLDAP:
		return a.ldapAccountListBackend(backendType)
	case definitions.BackendLua:
		mgr := NewLuaManager(backendType.GetName(), a.deps)

		return &AccountListMap{definitions.BackendLua, mgr.AccountDB}
	case definitions.BackendTest:
		mgr := NewTestBackendManager(backendType.GetName(), a.deps)

		return &AccountListMap{definitions.BackendTest, mgr.AccountDB}
	case definitions.BackendRemote:
		return a.managedAccountListBackend(definitions.BackendRemote, backendType.GetName())
	case definitions.BackendPlugin:
		return a.managedAccountListBackend(definitions.BackendPlugin, backendType.GetName())
	default:
		return nil
	}
}

// ldapAccountListBackend resolves the LDAP pool used for account-provider listing.
func (a *AuthState) ldapAccountListBackend(backendType *config.Backend) *AccountListMap {
	poolName := backendType.GetName()
	if poolName == "" || poolName == definitions.DefaultBackendName {
		if resolvedPoolName, ok := config.ResolveLDAPSearchPoolName(a.Cfg(), definitions.ProtoAccountProvider); ok {
			poolName = resolvedPoolName
		}
	}

	mgr := NewLDAPManager(poolName, a.deps)

	return &AccountListMap{definitions.BackendLDAP, mgr.AccountDB}
}

// managedAccountListBackend returns an account handler for runtime-managed backends.
func (a *AuthState) managedAccountListBackend(backend definitions.Backend, backendName string) *AccountListMap {
	mgr := a.GetBackendManager(backend, backendName)
	if mgr == nil {
		return nil
	}

	return &AccountListMap{backend, mgr.AccountDB}
}

// appendAccountDBResults executes account handlers and appends successful results.
func (a *AuthState) appendAccountDBResults(accounts []*AccountListMap, accountList *AccountList) bool {
	errSeen := false

	for _, accountDB := range accounts {
		result, err := accountDB.fn(a)

		util.DebugModuleWithCfg(a.Ctx(), a.Cfg(), a.Logger(), definitions.DbgAuth, definitions.LogKeyGUID, a.Runtime.GUID, "backendType", accountDB.backend.String(), "result", fmt.Sprintf("%v", result))

		if err == nil {
			*accountList = append(*accountList, result...)
		} else {
			errSeen = true

			a.logAccountDBError(err)
		}
	}

	return errSeen
}

// logAccountDBError records backend errors raised during account listing.
func (a *AuthState) logAccountDBError(err error) {
	if detailedError, ok := stderrors.AsType[*errors.DetailedError](err); ok {
		level.Error(a.logger()).Log(
			definitions.LogKeyGUID, a.Runtime.GUID,
			definitions.LogKeyMsg, detailedError.GetDetails(),
			definitions.LogKeyError, err,
		)

		return
	}

	level.Error(a.logger()).Log(
		definitions.LogKeyGUID, a.Runtime.GUID,
		definitions.LogKeyMsg, "Error calling account database",
		definitions.LogKeyError, err,
	)
}

func (a *AuthState) finishListAccountsPolicy(ctx *gin.Context, count int, errSeen bool) bool {
	a.recordPolicyAccountProvider(ctx, count, errSeen)
	a.completePolicyStage(ctx, policy.StageAccountProvider)

	final, configured := a.listAccountsPolicyDecision(ctx)
	if final == nil {
		return false
	}

	if configured {
		if listAccountsPolicyTerminates(final) {
			a.applyPolicyDecision(ctx, final)

			return true
		}
	}

	if err := a.applyAuthFSMMarkers(evaluation.TargetFSMEventMarkers(a.policyReport(ctx), final)); err != nil {
		_ = level.Error(a.logger()).Log(definitions.LogKeyGUID, a.Runtime.GUID, definitions.LogKeyMsg, err.Error())
	}

	return false
}

func (a *AuthState) listAccountsPolicyDecision(ctx *gin.Context) (*report.FinalDecision, bool) {
	if final, ok := a.configuredPolicyAuthDecision(ctx); ok {
		return final, true
	}

	final, _ := a.defaultPolicyAuthDecision(ctx)

	return final, false
}

func listAccountsPolicyTerminates(final *report.FinalDecision) bool {
	if final == nil {
		return false
	}

	return final.Effect == policy.DecisionDeny || final.Effect == policy.DecisionTempFail
}

// String returns a human-readable representation of the PassDBResult.
func (p *PassDBResult) String() string {
	attributes := redactPassDBResultAttributes(p.Attributes, p.TOTPSecretField, p.TOTPRecoveryField)

	fields := []authStateField{
		{"BackendName", p.BackendName},
		{"AccountField", p.AccountField},
		{"Account", p.Account},
		{"TOTPSecretField", p.TOTPSecretField},
		{"TOTPRecoveryField", p.TOTPRecoveryField},
		{"UniqueUserIDField", p.UniqueUserIDField},
		{"DisplayNameField", p.DisplayNameField},
		{"Attributes", attributes},
		{"AdditionalAttributes", p.AdditionalAttributes},
		{"Authenticated", p.Authenticated},
		{"UserFound", p.UserFound},
		{"Backend", p.Backend},
	}

	var result strings.Builder

	for _, f := range fields {
		fmt.Fprintf(&result, " %s='%v'", f.Name, f.Value)
	}

	if result.Len() == 0 {
		return ""
	}

	return result.String()[1:]
}

func redactPassDBResultAttributes(attributes bktype.AttributeMapping, fieldNames ...string) bktype.AttributeMapping {
	if len(attributes) == 0 {
		return attributes
	}

	redactedAttributes := attributes.Clone()

	for _, fieldName := range fieldNames {
		if fieldName == "" {
			continue
		}

		values, okay := redactedAttributes[fieldName]
		if !okay {
			continue
		}

		redactedValues := make([]any, len(values))
		for index := range values {
			redactedValues[index] = logRedactedValue
		}

		redactedAttributes[fieldName] = redactedValues
	}

	return redactedAttributes
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
	dReadCtx, cancelRead := util.GetCtxWithDeadlineRedisRead(context.TODO(), a.Cfg())
	accountName = backend.GetUserAccountFromCache(dReadCtx, a.Cfg(), a.Logger(), a.deps.Redis, a.AccountCache(), a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID, a.Runtime.GUID)

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

		sort.Strings(accounts)

		accountName = strings.Join(accounts, ":")

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		// Service-scoped write for robust cache update
		dWriteCtx, cancelWrite := util.GetCtxWithDeadlineRedisWrite(context.TODO(), a.Cfg())
		err = backend.SetUserAccountMapping(dWriteCtx, a.Cfg(), a.deps.Redis, a.Request.Username, a.Request.Protocol.Get(), a.Request.OIDCCID, accountName)

		cancelWrite()
	}

	return
}

// Ctx returns a standard library context for this AuthState.
// Preference order:
// 1) isolated operationContext for worker-owned state
// 2) HTTPClientRequest.Context() if present
// 3) HTTPClientContext.Request.Context() if present
// 4) svcctx.Get() as a safe, non-nil fallback
func (a *AuthState) Ctx() context.Context {
	if a != nil {
		if a.operationContext != nil {
			return a.operationContext
		}

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

// HasOIDCScope checks if the current request's OIDC Bearer token contains the specified scope.
// Returns false if no OIDC claims are present in the context.
func (a *AuthState) HasOIDCScope(ctx *gin.Context, scope string) bool {
	return oidcbearer.HasScopeFromContext(ctx, scope)
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
	if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromAuth, "auth_set_operation_mode_total", ctx.FullPath()); stop != nil {
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
	case authModeNoAuth:
		util.DebugModuleWithCfg(ctx.Request.Context(), cfg, logger, definitions.DbgAuth, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "mode=no-auth")

		a.Request.NoAuth = true
	case string(AuthModeListAccounts):
		util.DebugModuleWithCfg(ctx.Request.Context(), cfg, logger, definitions.DbgAuth, definitions.LogKeyGUID, guid, definitions.LogKeyMsg, "mode=list-accounts")

		a.Request.Protocol.Set(definitions.ProtoAccountProvider)

		// Check if OIDC Bearer token has the required scope
		claims := oidcbearer.GetClaimsFromContext(ctx)

		if claims != nil {
			if a.HasOIDCScope(ctx, definitions.ScopeListAccounts) {
				a.Request.ListAccounts = true
			} else {
				level.Warn(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "OIDC token missing scope '"+definitions.ScopeListAccounts+"' required for list-accounts mode",
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

		if stop := stats.PrometheusTimer(cfg, definitions.PromRequest, "request_headers_parse_total", ctx.FullPath()); stop != nil {
			defer stop()
		}
	}

	// Nginx header, see: https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html#protocol
	usernameValue := getDecodedHeader(ctx, cfg.GetUsername())

	passwordValue := getDecodedHeader(ctx, cfg.GetPassword())
	if passwordValue != "" {
		ctx.Request.Header.Del(cfg.GetPassword())
	}

	encoded := getDecodedHeader(ctx, cfg.GetPasswordEncoded())
	if encoded != "" {
		ctx.Request.Header.Del(cfg.GetPasswordEncoded())
	}

	passwordBytes := []byte(passwordValue)
	if encoded == "1" {
		// Decode password locally before applying
		padding := len(passwordValue) % 4
		if padding > 0 {
			passwordValue += string(bytes.Repeat([]byte("="), 4-padding))
		}

		if decodedPassword, err := base64.URLEncoding.DecodeString(passwordValue); err != nil {
			clear(passwordBytes)
			passwordBytes = nil

			_ = ctx.Error(errors.ErrPasswordEncoding)
		} else {
			clear(passwordBytes)
			passwordBytes = decodedPassword
		}
	}

	if a, ok := auth.(*AuthState); ok {
		// Apply credentials and header-derived context in a consolidated manner
		a.ApplyCredentials(NewCredentials(
			WithUsername(usernameValue),
			WithPassword(secret.FromBytes(passwordBytes)),
		))

		a.ApplyContextData(NewAuthContext(
			WithProtocol(getDecodedHeader(ctx, cfg.GetProtocol())),
			WithMethod(getDecodedHeader(ctx, cfg.GetAuthMethod())),
		))
	}

	clear(passwordBytes)

	// Initialize login attempts from header using the centralized manager.
	if a, ok := auth.(*AuthState); ok {
		a.SyncLoginAttemptsFromHeader(getDecodedHeader(ctx, cfg.GetLoginAttempt()))
	}
}

// processApplicationXWWWFormUrlencoded processes the application/x-www-form-urlencoded data from the request context and updates the AuthState object.
// It extracts the values for the fields method, realm, user_agent, username, password, protocol, port, tls, and security from the request form.
// If the realm field is not empty, it appends "@" + realm to the username field in the AuthState object.
// It sets the method, user_agent, username, usernameOrig, password, protocol, xLocalIP, xPort, xSSL, and xSSLProtocol fields in the AuthState object.
func processApplicationXWWWFormUrlencoded(ctx *gin.Context, auth State) {
	if a, ok := auth.(*AuthState); ok {
		if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromRequest, "request_form_decode_total", ctx.FullPath()); stop != nil {
			defer stop()
		}
	}

	// Build username incorporating optional realm suffix
	username := ctx.PostForm("username")
	realm := ctx.PostForm("realm")
	passwordValue := ctx.PostForm("password")

	if len(realm) > 0 {
		username = username + "@" + realm
	}

	passwordBytes := []byte(passwordValue)

	// Apply credentials via builder
	if a, ok := auth.(*AuthState); ok {
		a.ApplyCredentials(NewCredentials(
			WithUsername(username),
			WithPassword(secret.FromBytes(passwordBytes)),
		))
	}

	clear(passwordBytes)

	if ctx.Request.PostForm != nil {
		ctx.Request.PostForm.Del("password")
	}

	if ctx.Request.Form != nil {
		ctx.Request.Form.Del("password")
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

type authRequestDecoder func(ctx *gin.Context, request *authdto.Request) error

func processStructuredAuthRequest(ctx *gin.Context, auth State, metricName string, decoder authRequestDecoder) {
	if a, ok := auth.(*AuthState); ok {
		if stop := stats.PrometheusTimer(a.Cfg(), definitions.PromRequest, metricName, ctx.FullPath()); stop != nil {
			defer stop()
		}
	}

	var request authdto.Request

	if err := decoder(ctx, &request); err != nil {
		HandleJSONError(ctx, err)

		return
	}

	if request.Password == "" && ctx.Query("mode") != authModeNoAuth && ctx.Query("mode") != string(AuthModeListAccounts) {
		HandleJSONValidationError(ctx, "Password", "This field is required")

		return
	}

	ApplyStructuredAuthRequest(auth, &request)

	// If no user_agent was provided in the request body, fall back to the HTTP header.
	if request.UserAgent == "" {
		auth.WithUserAgent(ctx)
	}

	request = authdto.Request{}
	ctx.Request.Body = http.NoBody
	ctx.Request.ContentLength = 0

	// Apply DNS resolution logic after setting client IP
	if authState, ok := auth.(*AuthState); ok {
		authState.postResolvDNS(ctx)
	}
}

// processApplicationJSON decodes application/json authentication requests.
func processApplicationJSON(ctx *gin.Context, auth State) {
	processStructuredAuthRequest(ctx, auth, "request_json_decode_total", func(ctx *gin.Context, request *authdto.Request) error {
		return decodeStrictJSONRequest(ctx, request)
	})
}

// processApplicationCBOR decodes application/cbor authentication requests.
func processApplicationCBOR(ctx *gin.Context, auth State) {
	processStructuredAuthRequest(ctx, auth, "request_cbor_decode_total", func(ctx *gin.Context, request *authdto.Request) error {
		return cborcodec.DecodeReader(ctx.Request.Body, request)
	})
}

func decodeStrictJSONRequest(ctx *gin.Context, request *authdto.Request) error {
	decoder := stdjson.NewDecoder(ctx.Request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(request); err != nil {
		return err
	}

	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return stderrors.New("request body must contain a single JSON value")
		}

		return err
	}

	if binding.Validator == nil {
		return nil
	}

	return binding.Validator.ValidateStruct(request)
}

// ApplyStructuredAuthRequest updates the provided authentication state with
// data from the structured request payload, if available.
func ApplyStructuredAuthRequest(auth State, request *authdto.Request) {
	authState, ok := auth.(*AuthState)
	if !ok {
		return
	}

	creds := NewCredentials(buildCredentialOptions(request)...)
	authState.ApplyCredentials(creds)

	ctxData := NewAuthContext(buildAuthContextOptions(request)...)
	authState.ApplyContextData(ctxData)

	if request.AuthLoginAttempt > 0 {
		authState.Request.AuthLoginAttempt = request.AuthLoginAttempt
		authState.SyncLoginAttemptsFromAttemptOrdinal(request.AuthLoginAttempt)
	}
}

// buildCredentialOptions creates credential options from the request.
func buildCredentialOptions(request *authdto.Request) []CredentialOption {
	var opts []CredentialOption

	if request.Username != "" {
		opts = append(opts, WithUsername(request.Username))
	}

	if request.Password != "" {
		passwordBytes := []byte(request.Password)
		opts = append(opts, WithPassword(secret.FromBytes(passwordBytes)))
		clear(passwordBytes)

		request.Password = ""
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
		{request.ExternalSessionID, WithExternalSessionID},
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
// If the "Content-Type" is "application/json" or "application/cbor",
// it decodes the body with the corresponding structured decoder.
// If neither of the above conditions match, it sets the error associated with unsupported media type
// and sets the error type to gin.ErrorTypeBind on the Context.
func setupBodyBasedAuth(ctx *gin.Context, auth State) {
	if ctx.Request.Method == "POST" {
		contentType := ctx.GetHeader("Content-Type")

		if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
			processApplicationXWWWFormUrlencoded(ctx, auth)
		} else if strings.HasPrefix(contentType, "application/json") {
			processApplicationJSON(ctx, auth)
		} else if strings.HasPrefix(contentType, "application/cbor") {
			processApplicationCBOR(ctx, auth)
		} else {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{policyAttributeSuffixError: "Unsupported media type"})
			_ = ctx.Error(errors.ErrUnsupportedMediaType).SetType(gin.ErrorTypeBind)
		}
	}
}

// setupHTTPBasicAuth sets up basic authentication for HTTP requests.
// It takes in a gin.Context object and a pointer to an AuthState object.
// It calls the withClientInfo, withLocalInfo, withUserAgent, and withXSSL methods of the AuthState object to set client, local, user-agent, and X-SSL information, respectively
func setupHTTPBasicAuth(_ *gin.Context, _ State) {
	// NOTE: We must get username and password later!
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

func getDecodedHeader(ctx *gin.Context, headerName string) string {
	if ctx == nil || headerName == "" {
		return ""
	}

	return util.URLPartialDecode(ctx.GetHeader(headerName))
}

// setupAuth sets up the authentication based on the service parameter in the gin context.
// It takes the gin context and an AuthState struct as input.
//
// If the service parameter is "nginx" or "header", it calls the setupHeaderBasedAuth function.
// If the service parameter is "json" or "idp", it calls the setupBodyBasedAuth function.
// If the service parameter is "basic", it calls the setupHTTPBasicAuth function.
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
	if stop := setupAuthTimer(ctx, auth); stop != nil {
		defer stop()
	}

	ensureAuthProtocol(auth)

	auth.WithClientInfo(ctx)
	auth.WithLocalInfo(ctx)
	auth.WithUserAgent(ctx)
	auth.WithXSSL(ctx)

	svc := ctx.GetString(definitions.CtxServiceKey)
	setupAuthByService(ctx, auth, svc)

	if ctx.IsAborted() {
		return
	}

	if !validateSetupAuthCredentials(ctx, auth, svc) {
		return
	}

	auth.InitMethodAndUserAgent()
	auth.WithDefaults(ctx)
	auth.SetOperationMode(ctx)
}

// setupAuthTimer starts the request setup metric for AuthState-backed requests.
func setupAuthTimer(ctx *gin.Context, auth State) func() {
	a, ok := auth.(*AuthState)
	if !ok {
		return nil
	}

	return stats.PrometheusTimer(a.Cfg(), definitions.PromRequest, "request_setup_total", ctx.FullPath())
}

// ensureAuthProtocol initializes an empty protocol holder when none exists.
func ensureAuthProtocol(auth State) {
	if auth.GetProtocol() == nil || auth.GetProtocol().Get() == "" {
		auth.SetProtocol(&config.Protocol{})
	}
}

// setupAuthByService dispatches request decoding based on the configured service.
func setupAuthByService(ctx *gin.Context, auth State, svc string) {
	switch svc {
	case definitions.ServNginx, definitions.ServHeader:
		setupHeaderBasedAuth(ctx, auth)
	case definitions.ServJSON, definitions.ServCBOR, definitions.ServIDP:
		setupBodyBasedAuth(ctx, auth)
	case definitions.ServBasic:
		setupHTTPBasicAuth(ctx, auth)
	}
}

// validateSetupAuthCredentials rejects missing or invalid credentials for direct auth endpoints.
func validateSetupAuthCredentials(ctx *gin.Context, auth State, svc string) bool {
	if !shouldValidateSetupAuthCredentials(ctx, svc) {
		return true
	}

	username := auth.GetUsername()
	if username == "" {
		_ = ctx.Error(errors.ErrEmptyUsername)

		return false
	}

	if !util.ValidateUsername(username) {
		auth.SetUsername("")

		_ = ctx.Error(errors.ErrInvalidUsername)

		return false
	}

	if auth.GetPassword().IsZero() {
		_ = ctx.Error(errors.ErrEmptyPassword)

		return false
	}

	return true
}

// shouldValidateSetupAuthCredentials reports whether setup must enforce username/password fields.
func shouldValidateSetupAuthCredentials(ctx *gin.Context, svc string) bool {
	return ctx.Query("mode") != string(AuthModeListAccounts) &&
		ctx.Query("mode") != authModeNoAuth &&
		svc != definitions.ServBasic &&
		svc != definitions.ServIDP
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

	auth := NewAuthStateFromContextWithDeps(ctx, deps)

	if a, ok := auth.(*AuthState); ok {
		requestScope := a.scopeRequestContext(tctx, ctx)

		defer requestScope.Restore()

		a.traceSetupDetails(tsp)
		a.FinishSetup(ctx)
	}

	if ctx.Errors.Last() != nil || ctx.IsAborted() {
		return nil
	}

	return auth
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
	a.Runtime.Authorized = true     // default allow unless subject analysis rejects

	switch a.Request.Service {
	case definitions.ServBasic:
		a.SetProtocol(config.NewProtocol(definitions.ProtoHTTP))
	case definitions.ServIDP:
		a.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	}

	if a.Request.Protocol.Get() == "" {
		a.SetProtocol(config.NewProtocol(definitions.ProtoDefault))
	}

	return a
}

// WithLocalInfo adds the local IP and -port headers to the AuthState structure.
func (a *AuthState) WithLocalInfo(ctx *gin.Context) State {
	if a == nil {
		return nil
	}

	cfg := a.cfg()
	util.ApplyStringField(getDecodedHeader(ctx, cfg.GetLocalIP()), &a.Request.XLocalIP)
	util.ApplyStringField(getDecodedHeader(ctx, cfg.GetLocalPort()), &a.Request.XPort)

	return a
}

// postResolvDNS resolves the client IP to a host name if DNS client IP resolution is enabled in the configuration.
func (a *AuthState) postResolvDNS(ctx context.Context) {
	if a.cfg().GetServer().GetDNS().GetResolveClientIP() {
		resource := util.RequestResource(a.Request.HTTPClientContext, a.Request.HTTPClientRequest, a.Request.Service)
		stopTimer := stats.PrometheusTimer(a.Cfg(), definitions.PromDNS, definitions.DNSResolvePTR, resource)

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
	util.ApplyStringField(getDecodedHeader(ctx, cfg.GetOIDCCID()), &a.Request.OIDCCID)

	if util.DirectPeerIsTrustedProxy(ctx, cfg, a.Logger()) {
		util.ApplyStringField(getDecodedHeader(ctx, cfg.GetClientIP()), &a.Request.ClientIP)
		util.ApplyStringField(getDecodedHeader(ctx, cfg.GetClientPort()), &a.Request.XClientPort)
	}

	util.ApplyStringField(getDecodedHeader(ctx, cfg.GetClientID()), &a.Request.XClientID)
	util.ApplyStringField(getDecodedHeader(ctx, cfg.GetClientHost()), &a.Request.ClientHost)
	a.ApplyContextData(NewAuthContext(WithExternalSessionID(getDecodedHeader(ctx, cfg.GetExternalSessionID()))))

	if a.Request.ClientIP == "" {
		a.Request.ClientIP = util.RequestClientIPWithConfig(ctx, cfg, a.Logger())

		if a.Request.ClientIP == "" && cfg.GetServer().IsHAproxyProtocolEnabled() && ctx.Request != nil {
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
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSL()), &a.Request.XSSL)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLSessionID()), &a.Request.XSSLSessionID)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLVerify()), &a.Request.XSSLClientVerify)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLSubject()), &a.Request.XSSLClientDN)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLClientCN()), &a.Request.XSSLClientCN)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLIssuer()), &a.Request.XSSLIssuer)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLClientNotBefore()), &a.Request.XSSLClientNotBefore)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLClientNotAfter()), &a.Request.XSSLClientNotAfter)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLSubjectDN()), &a.Request.XSSLSubjectDN)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLIssuerDN()), &a.Request.XSSLIssuerDN)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLClientSubjectDN()), &a.Request.XSSLClientSubjectDN)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLClientIssuerDN()), &a.Request.XSSLClientIssuerDN)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLCipher()), &a.Request.XSSLCipher)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLProtocol()), &a.Request.XSSLProtocol)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLSerial()), &a.Request.SSLSerial)
	util.ApplyStringField(getDecodedHeader(ctx, h.GetSSLFingerprint()), &a.Request.SSLFingerprint)

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
				return defaultClientIPAny
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
		clientIP = defaultClientIPAny
	}

	sslFlag := "0"
	if a.Request.XSSL != "" || a.Request.XSSLProtocol != "" {
		sslFlag = "1"
	}

	// Short password hash (same function as for positive password cache)
	var pwShort string

	a.Request.Password.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		prepared := util.PreparePasswordBytes(value)
		defer clear(prepared)

		pwShort = util.GetHashBytes(prepared)
	})

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

	requestScope := a.scopeRequestContext(lcCtx, ctx)

	defer requestScope.Restore()

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

		// Set AdditionalAttributes in the gin.Context if they exist in the cached result
		if len(passDBResult.AdditionalAttributes) > 0 {
			ctx.Set(definitions.CtxAdditionalAttributesKey, passDBResult.AdditionalAttributes)
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
// If a brute force attack is rejected, it returns true. Configured policy controls may let processing continue.
func (a *AuthState) PreproccessAuthRequest(ctx *gin.Context) (reject bool) {
	tr := monittrace.New("nauthilus/auth")
	pctx, pspan := tr.Start(ctx.Request.Context(), "auth.environment",
		attribute.String("service", a.Request.Service),
		attribute.String("username", a.Request.Username),
	)

	requestScope := a.scopeRequestContext(pctx, ctx)

	defer requestScope.Restore()
	defer pspan.End()

	var cacheHit bool

	if found := a.GetFromLocalCache(ctx); !found {
		stats.GetMetrics().GetCacheMisses().Inc()

		if a.CheckBruteForce(ctx) {
			return a.handlePreAuthBruteForce(ctx, pspan)
		}
	} else {
		stats.GetMetrics().GetCacheHits().Inc()

		cacheHit = true
	}

	pspan.SetAttributes(attribute.Bool("cache.hit", cacheHit))

	return false
}

// handlePreAuthBruteForce applies configured and default brute-force decisions.
func (a *AuthState) handlePreAuthBruteForce(ctx *gin.Context, span trace.Span) bool {
	span.SetAttributes(attribute.Bool("bruteforce.blocked", true))

	if a.applyConfiguredPreAuthDecision(ctx) {
		span.SetAttributes(attribute.Bool("reject", true))

		return true
	}

	if a.applyConfiguredPreAuthControl(ctx, definitions.AuthResultFail) {
		span.SetAttributes(attribute.Bool("policy_skip_remaining", true))

		return false
	}

	if a.HasConfiguredPreAuthPolicyAuthority(ctx) {
		span.SetAttributes(attribute.Bool("policy_continue", true))

		return false
	}

	if a.applyDefaultPreAuthDecision(ctx) {
		span.SetAttributes(attribute.Bool("reject", true))

		return true
	}

	a.rejectDefaultPreAuthBruteForce(ctx, span)

	return true
}

// rejectDefaultPreAuthBruteForce performs the legacy rejection side effects.
func (a *AuthState) rejectDefaultPreAuthBruteForce(ctx *gin.Context, span trace.Span) {
	a.markEnvironmentRejected(ctx)
	a.UpdateBruteForceBucketsCounter(ctx)

	result := GetPassDBResultFromPool()
	a.PostLuaAction(ctx, result)
	PutPassDBResultToPool(result)
	a.AuthFail(ctx)

	span.SetAttributes(attribute.Bool("reject", true))
}

// ApplyCredentials applies non-empty credential fields to the AuthState.
func (a *AuthState) ApplyCredentials(c Credentials) {
	if a == nil {
		return
	}

	if c.Username != "" {
		a.Request.Username = c.Username
	}

	if !c.Password.IsZero() {
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

	if x.RequestMetadata != nil {
		a.Request.RequestMetadata = cloneRequestMetadata(x.RequestMetadata)
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
		{x.ExternalSessionID, &a.Request.ExternalSessionID},
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

	if a.Request.ExternalSessionID != "" && a.Request.HTTPClientContext != nil {
		a.Request.HTTPClientContext.Set(definitions.CtxExternalSessionKey, a.Request.ExternalSessionID)
	}

	// Handle Protocol specially as it requires type conversion
	if x.Protocol != "" {
		a.SetProtocol(config.NewProtocol(x.Protocol))
	}
}
