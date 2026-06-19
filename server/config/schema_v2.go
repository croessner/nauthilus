package config

import (
	"slices"
	"time"

	"github.com/croessner/nauthilus/v3/server/secret"
)

const defaultGRPCAuthorityAddress = "127.0.0.1:9444"
const defaultNauthilusAuthorityTimeout = 5 * time.Second
const defaultAuthorityTokenRefreshBeforeExpiry = 30 * time.Second
const defaultAuthorityTokenRefreshLockTTL = 10 * time.Second
const defaultAuthorityTokenCacheKeyPrefix = "grpc:authority_tokens:"
const defaultAuthPolicyName = "standard_auth"

const (
	// AuthorityTokenCacheBackendRedis selects Redis for caller-token caching.
	AuthorityTokenCacheBackendRedis = "redis"
	// AuthorityClientCredentialsMode is the supported authority caller-token mode.
	AuthorityClientCredentialsMode = "client_credentials"
	// AuthorityClientSecretBasicAuth authenticates the token endpoint with HTTP Basic.
	AuthorityClientSecretBasicAuth = "client_secret_basic"
	// AuthorityClientSecretPostAuth authenticates the token endpoint with a form secret.
	AuthorityClientSecretPostAuth = "client_secret_post"
	// AuthorityPrivateKeyJWTAuth authenticates the token endpoint with a private_key_jwt assertion.
	AuthorityPrivateKeyJWTAuth = "private_key_jwt"
	// RemoteBackendDefaultName is the public config key for the unnamed remote backend.
	RemoteBackendDefaultName = "default"
	// TLSVersion13 names TLS 1.3 in public config.
	TLSVersion13 = "TLS1.3"
)

// RuntimeSection groups process, server, and client runtime behavior.
type RuntimeSection struct {
	InstanceName string                `mapstructure:"instance_name"`
	Process      RuntimeProcessSection `mapstructure:"process"`
	Servers      RuntimeServersSection `mapstructure:"servers" validate:"omitempty"`
	Timeouts     Timeouts              `mapstructure:"timeouts" validate:"omitempty"`
	Clients      RuntimeClientsSection `mapstructure:"clients"`
}

// RuntimeProcessSection configures privilege dropping and chroot behavior.
type RuntimeProcessSection struct {
	RunAsUser  string `mapstructure:"run_as_user" validate:"omitempty"`
	RunAsGroup string `mapstructure:"run_as_group" validate:"omitempty"`
	Chroot     string `mapstructure:"chroot" validate:"omitempty,dir"`
}

// RuntimeServersSection groups inbound runtime servers.
type RuntimeServersSection struct {
	HTTP RuntimeHTTPServerSection  `mapstructure:"http" validate:"omitempty"`
	GRPC RuntimeGRPCServersSection `mapstructure:"grpc" validate:"omitempty"`
}

// RuntimeHTTPServerSection configures the inbound HTTP server.
type RuntimeHTTPServerSection struct {
	Address           string            `mapstructure:"address" validate:"omitempty,tcp_addr"`
	OpenAPIValidation OpenAPIValidation `mapstructure:"openapi_validation" validate:"omitempty"`
	HTTP3             bool              `mapstructure:"http3"`
	HAproxyV2         bool              `mapstructure:"haproxy_v2"`
	TrustedProxies    []string          `mapstructure:"trusted_proxies" validate:"omitempty,dive,ip|cidr"`
	TLS               TLS               `mapstructure:"tls" validate:"omitempty"`
	DisabledEndpoints Endpoint          `mapstructure:"disabled_endpoints" validate:"omitempty"`
	Middlewares       Middlewares       `mapstructure:"middlewares" validate:"omitempty"`
	Compression       Compression       `mapstructure:"compression" validate:"omitempty"`
	KeepAlive         KeepAlive         `mapstructure:"keep_alive" validate:"omitempty"`
	RateLimit         HTTPRateLimit     `mapstructure:"rate_limit" validate:"omitempty"`
	CORS              CORS              `mapstructure:"cors" validate:"omitempty"`
	SecurityTxt       SecurityTxt       `mapstructure:"security_txt" validate:"omitempty"`
}

// RuntimeGRPCServersSection groups inbound gRPC servers.
type RuntimeGRPCServersSection struct {
	Authority RuntimeGRPCAuthServerSection `mapstructure:"authority" validate:"omitempty"`
}

// RuntimeGRPCAuthServerSection configures the gRPC authority listener.
type RuntimeGRPCAuthServerSection struct {
	Address string                `mapstructure:"address" validate:"omitempty,tcp_addr"`
	TLS     RuntimeGRPCTLSSection `mapstructure:"tls" validate:"omitempty"`
	Enabled bool                  `mapstructure:"enabled"`
}

// IsEnabled reports whether the gRPC authority listener is enabled.
func (s *RuntimeGRPCAuthServerSection) IsEnabled() bool {
	if s == nil {
		return false
	}

	return s.Enabled
}

// GetAddress returns the configured gRPC authority address or the loopback default.
func (s *RuntimeGRPCAuthServerSection) GetAddress() string {
	if s == nil || s.Address == "" {
		return defaultGRPCAuthorityAddress
	}

	return s.Address
}

// GetTLS returns the gRPC authority TLS configuration.
func (s *RuntimeGRPCAuthServerSection) GetTLS() *RuntimeGRPCTLSSection {
	if s == nil {
		return &RuntimeGRPCTLSSection{}
	}

	return &s.TLS
}

// RuntimeGRPCTLSSection configures TLS for gRPC listeners.
type RuntimeGRPCTLSSection struct {
	Cert              string `mapstructure:"cert" validate:"omitempty,file"`
	Key               string `mapstructure:"key" validate:"omitempty,file"`
	ClientCA          string `mapstructure:"client_ca" validate:"omitempty,file"`
	MinTLSVersion     string `mapstructure:"min_tls_version" validate:"omitempty,oneof=TLS1.2 TLS1.3"`
	Enabled           bool   `mapstructure:"enabled"`
	RequireClientCert bool   `mapstructure:"require_client_cert"`
}

// IsEnabled reports whether TLS is enabled for the gRPC listener.
func (t *RuntimeGRPCTLSSection) IsEnabled() bool {
	if t == nil {
		return false
	}

	return t.Enabled
}

// GetCert returns the gRPC server certificate path.
func (t *RuntimeGRPCTLSSection) GetCert() string {
	if t == nil {
		return ""
	}

	return t.Cert
}

// GetKey returns the gRPC server private key path.
func (t *RuntimeGRPCTLSSection) GetKey() string {
	if t == nil {
		return ""
	}

	return t.Key
}

// GetClientCA returns the CA path used to verify gRPC client certificates.
func (t *RuntimeGRPCTLSSection) GetClientCA() string {
	if t == nil {
		return ""
	}

	return t.ClientCA
}

// GetMinTLSVersion returns the minimum TLS version configured for the gRPC listener.
func (t *RuntimeGRPCTLSSection) GetMinTLSVersion() string {
	if t == nil || t.MinTLSVersion == "" {
		return defaultTLSMinVersion
	}

	return t.MinTLSVersion
}

// RequiresClientCert reports whether client certificates are mandatory.
func (t *RuntimeGRPCTLSSection) RequiresClientCert() bool {
	if t == nil {
		return false
	}

	return t.RequireClientCert
}

// GetRuntimeGRPCAuthServer returns the configured gRPC authority listener settings.
func (f *FileSettings) GetRuntimeGRPCAuthServer() *RuntimeGRPCAuthServerSection {
	if f == nil || f.Runtime == nil {
		return &RuntimeGRPCAuthServerSection{Address: defaultGRPCAuthorityAddress}
	}

	return &f.Runtime.Servers.GRPC.Authority
}

// GetAuthPolicy returns the configured auth policy block with target defaults.
func (f *FileSettings) GetAuthPolicy() AuthPolicySection {
	if f == nil || f.Auth == nil {
		return defaultAuthPolicySection()
	}

	policyConfig := f.Auth.Policy
	applyAuthPolicyDefaults(&policyConfig)

	return policyConfig
}

// HTTPRateLimit configures the global HTTP rate limiter.
type HTTPRateLimit struct {
	PerSecond float64 `mapstructure:"per_second" validate:"omitempty,min=0"`
	Burst     int     `mapstructure:"burst" validate:"omitempty,min=0"`
}

// RuntimeClientsSection configures outbound HTTP and DNS clients.
type RuntimeClientsSection struct {
	HTTP HTTPClient                `mapstructure:"http" validate:"omitempty"`
	DNS  DNS                       `mapstructure:"dns" validate:"omitempty"`
	GRPC RuntimeGRPCClientsSection `mapstructure:"grpc" validate:"omitempty"`
}

// RuntimeGRPCClientsSection groups outbound gRPC clients.
type RuntimeGRPCClientsSection struct {
	NauthilusAuthorities map[string]*NauthilusAuthorityClientSection `mapstructure:"nauthilus_authorities" validate:"omitempty,dive"`
}

// NauthilusAuthorityClientSection configures one outbound authority client.
type NauthilusAuthorityClientSection struct {
	TLS             AuthorityTLSSection        `mapstructure:"tls" validate:"omitempty"`
	CallerAuth      AuthorityCallerAuthSection `mapstructure:"caller_auth" validate:"omitempty"`
	Address         string                     `mapstructure:"address" validate:"omitempty,tcp_addr"`
	Timeout         time.Duration              `mapstructure:"timeout" validate:"omitempty,gt=0,max=1m"`
	EdgeClusterID   string                     `mapstructure:"edge_cluster_id" validate:"omitempty,printascii"`
	EdgeInstanceID  string                     `mapstructure:"edge_instance_id" validate:"omitempty,printascii"`
	SplitStrictMode *bool                      `mapstructure:"split_strict_mode" validate:"omitempty"`
}

// GetAddress returns the authority network address.
func (s *NauthilusAuthorityClientSection) GetAddress() string {
	if s == nil {
		return ""
	}

	return s.Address
}

// GetTimeout returns the authority RPC timeout with the target default.
func (s *NauthilusAuthorityClientSection) GetTimeout() time.Duration {
	if s == nil || s.Timeout <= 0 {
		return defaultNauthilusAuthorityTimeout
	}

	return s.Timeout
}

// GetTLS returns the outbound authority TLS settings.
func (s *NauthilusAuthorityClientSection) GetTLS() *AuthorityTLSSection {
	if s == nil {
		return &AuthorityTLSSection{}
	}

	return &s.TLS
}

// GetCallerAuth returns the outbound authority caller-auth settings.
func (s *NauthilusAuthorityClientSection) GetCallerAuth() *AuthorityCallerAuthSection {
	if s == nil {
		return &AuthorityCallerAuthSection{}
	}

	return &s.CallerAuth
}

// GetEdgeClusterID returns the edge cluster metadata value.
func (s *NauthilusAuthorityClientSection) GetEdgeClusterID() string {
	if s == nil {
		return ""
	}

	return s.EdgeClusterID
}

// GetEdgeInstanceID returns the edge instance metadata value.
func (s *NauthilusAuthorityClientSection) GetEdgeInstanceID() string {
	if s == nil {
		return ""
	}

	return s.EdgeInstanceID
}

// IsSplitStrictMode reports whether split-mode safety checks are enforced.
func (s *NauthilusAuthorityClientSection) IsSplitStrictMode() bool {
	if s == nil || s.SplitStrictMode == nil {
		return true
	}

	return *s.SplitStrictMode
}

// AuthorityTLSSection configures TLS for an outbound authority client.
type AuthorityTLSSection struct {
	CA            string `mapstructure:"ca" validate:"omitempty,file"`
	Cert          string `mapstructure:"cert" validate:"omitempty,file"`
	Key           string `mapstructure:"key" validate:"omitempty,file"`
	ServerName    string `mapstructure:"server_name" validate:"omitempty,hostname_rfc1123"`
	MinTLSVersion string `mapstructure:"min_tls_version" validate:"omitempty,oneof=TLS1.2 TLS1.3"`
	Enabled       bool   `mapstructure:"enabled"`
}

// IsEnabled reports whether outbound authority TLS is enabled.
func (s *AuthorityTLSSection) IsEnabled() bool {
	if s == nil {
		return false
	}

	return s.Enabled
}

// GetMinTLSVersion returns the configured minimum TLS version.
func (s *AuthorityTLSSection) GetMinTLSVersion() string {
	if s == nil || s.MinTLSVersion == "" {
		return defaultTLSMinVersion
	}

	return s.MinTLSVersion
}

// AuthorityCallerAuthSection configures caller authentication for authority RPCs.
type AuthorityCallerAuthSection struct {
	BasicAuth  BasicAuth                  `mapstructure:"basic_auth" validate:"omitempty"`
	OIDCBearer AuthorityOIDCBearerSection `mapstructure:"oidc_bearer" validate:"omitempty"`
}

// HasCallerAuth reports whether an RPC caller credential source is configured.
func (s *AuthorityCallerAuthSection) HasCallerAuth() bool {
	if s == nil {
		return false
	}

	return s.BasicAuth.IsEnabled() || s.OIDCBearer.IsEnabled() || s.OIDCBearer.GetStaticTokenFile() != ""
}

// AuthorityOIDCBearerSection configures client-credentials bearer caller auth.
type AuthorityOIDCBearerSection struct {
	TokenCache               AuthorityTokenCacheSection `mapstructure:"token_cache" validate:"omitempty"`
	ClientSecret             secret.Value               `mapstructure:"client_secret" validate:"omitempty"`
	Mode                     string                     `mapstructure:"mode" validate:"omitempty,oneof=client_credentials"`
	TokenEndpoint            string                     `mapstructure:"token_endpoint" validate:"omitempty,url"`
	ClientID                 string                     `mapstructure:"client_id" validate:"omitempty,printascii,excludesall= "`
	TokenEndpointAuthMethod  string                     `mapstructure:"token_endpoint_auth_method" validate:"omitempty,oneof=client_secret_basic client_secret_post private_key_jwt"`
	ClientPrivateKeyFile     string                     `mapstructure:"client_private_key_file" validate:"omitempty,file"`
	ClientKeyID              string                     `mapstructure:"client_key_id" validate:"omitempty,printascii"`
	ClientAssertionAlg       string                     `mapstructure:"client_assertion_alg" validate:"omitempty,oneof=RS256 EdDSA"`
	Audience                 string                     `mapstructure:"audience" validate:"omitempty,printascii"`
	Scopes                   []string                   `mapstructure:"scopes" validate:"omitempty,dive,scope_token"`
	StaticTokenFile          string                     `mapstructure:"static_token_file" validate:"omitempty,file"`
	Enabled                  bool                       `mapstructure:"enabled"`
	StaticTokenEmergencyMode bool                       `mapstructure:"static_token_emergency_mode"`
}

// IsEnabled reports whether client-credentials caller auth is enabled.
func (s *AuthorityOIDCBearerSection) IsEnabled() bool {
	return s != nil && s.Enabled
}

// GetMode returns the configured token mode.
func (s *AuthorityOIDCBearerSection) GetMode() string {
	if s == nil {
		return ""
	}

	return s.Mode
}

// GetTokenEndpoint returns the OIDC token endpoint URL.
func (s *AuthorityOIDCBearerSection) GetTokenEndpoint() string {
	if s == nil {
		return ""
	}

	return s.TokenEndpoint
}

// GetClientID returns the OAuth client identifier.
func (s *AuthorityOIDCBearerSection) GetClientID() string {
	if s == nil {
		return ""
	}

	return s.ClientID
}

// GetTokenEndpointAuthMethod returns the token endpoint auth method.
func (s *AuthorityOIDCBearerSection) GetTokenEndpointAuthMethod() string {
	if s == nil {
		return ""
	}

	return s.TokenEndpointAuthMethod
}

// GetClientSecret returns the client secret.
func (s *AuthorityOIDCBearerSection) GetClientSecret() secret.Value {
	if s == nil {
		return secret.Value{}
	}

	return s.ClientSecret
}

// GetStaticTokenFile returns the development or emergency token-file path.
func (s *AuthorityOIDCBearerSection) GetStaticTokenFile() string {
	if s == nil {
		return ""
	}

	return s.StaticTokenFile
}

// StaticTokenAllowed reports whether a static token file is intentionally enabled.
func (s *AuthorityOIDCBearerSection) StaticTokenAllowed() bool {
	if s == nil {
		return false
	}

	return s.StaticTokenEmergencyMode
}

// GetTokenCache returns token-cache settings with defaults handled by the section.
func (s *AuthorityOIDCBearerSection) GetTokenCache() *AuthorityTokenCacheSection {
	if s == nil {
		return &AuthorityTokenCacheSection{}
	}

	return &s.TokenCache
}

// AuthorityTokenCacheSection configures Redis token-cache behavior.
type AuthorityTokenCacheSection struct {
	Backend             string        `mapstructure:"backend" validate:"omitempty,oneof=redis"`
	KeyPrefix           string        `mapstructure:"key_prefix" validate:"omitempty,printascii"`
	RefreshBeforeExpiry time.Duration `mapstructure:"refresh_before_expiry" validate:"omitempty,gt=0,max=10m"`
	RefreshLockTTL      time.Duration `mapstructure:"refresh_lock_ttl" validate:"omitempty,gt=0,max=1m"`
}

// GetBackend returns the cache backend name.
func (s *AuthorityTokenCacheSection) GetBackend() string {
	if s == nil || s.Backend == "" {
		return AuthorityTokenCacheBackendRedis
	}

	return s.Backend
}

// GetKeyPrefix returns the Redis key prefix for caller tokens.
func (s *AuthorityTokenCacheSection) GetKeyPrefix() string {
	if s == nil || s.KeyPrefix == "" {
		return defaultAuthorityTokenCacheKeyPrefix
	}

	return s.KeyPrefix
}

// GetRefreshBeforeExpiry returns the refresh skew.
func (s *AuthorityTokenCacheSection) GetRefreshBeforeExpiry() time.Duration {
	if s == nil || s.RefreshBeforeExpiry <= 0 {
		return defaultAuthorityTokenRefreshBeforeExpiry
	}

	return s.RefreshBeforeExpiry
}

// GetRefreshLockTTL returns the distributed refresh-lock TTL.
func (s *AuthorityTokenCacheSection) GetRefreshLockTTL() time.Duration {
	if s == nil || s.RefreshLockTTL <= 0 {
		return defaultAuthorityTokenRefreshLockTTL
	}

	return s.RefreshLockTTL
}

// ObservabilitySection groups logging, profiling, tracing, and metrics.
type ObservabilitySection struct {
	Log      Log                   `mapstructure:"log" validate:"omitempty"`
	Profiles ObservabilityProfiles `mapstructure:"profiles" validate:"omitempty"`
	Tracing  Tracing               `mapstructure:"tracing" validate:"omitempty"`
	Metrics  ObservabilityMetrics  `mapstructure:"metrics" validate:"omitempty"`
}

// ObservabilityProfiles configures runtime profiling toggles.
type ObservabilityProfiles struct {
	Pprof ObservabilityToggle `mapstructure:"pprof" validate:"omitempty"`
	Block ObservabilityToggle `mapstructure:"block" validate:"omitempty"`
}

// ObservabilityToggle is a generic enabled/disabled wrapper.
type ObservabilityToggle struct {
	Enabled bool `mapstructure:"enabled"`
}

// ObservabilityMetrics configures metrics-related runtime behavior.
type ObservabilityMetrics struct {
	MonitorConnections bool                `mapstructure:"monitor_connections"`
	PrometheusTimer    PrometheusTimer     `mapstructure:"prometheus_timer" validate:"omitempty"`
	EndpointAuth       MetricsEndpointAuth `mapstructure:"endpoint_auth" validate:"omitempty"`
}

// StorageSection groups persistence and caching backends.
type StorageSection struct {
	Redis Redis `mapstructure:"redis" validate:"omitempty"`
}

// AuthSection groups the authentication request model, controls, services, and backend order.
type AuthSection struct {
	Request     AuthRequestSection     `mapstructure:"request" validate:"omitempty"`
	Backchannel AuthBackchannelSection `mapstructure:"backchannel" validate:"omitempty"`
	Pipeline    AuthPipelineSection    `mapstructure:"pipeline" validate:"omitempty"`
	Upstreams   AuthUpstreamsSection   `mapstructure:"upstreams" validate:"omitempty"`
	Backends    AuthBackendsSection    `mapstructure:"backends" validate:"omitempty"`
	Controls    AuthControlsSection    `mapstructure:"controls" validate:"omitempty"`
	Services    AuthServicesSection    `mapstructure:"services" validate:"omitempty"`
	Policy      AuthPolicySection      `mapstructure:"policy" validate:"omitempty"`
}

// AuthRequestSection configures inbound request metadata handling.
type AuthRequestSection struct {
	Headers DefaultHTTPRequestHeader `mapstructure:"headers" validate:"omitempty"`
}

// AuthBackchannelSection configures API/backchannel authentication.
type AuthBackchannelSection struct {
	BasicAuth  BasicAuth `mapstructure:"basic_auth" validate:"omitempty"`
	OIDCBearer OIDCAuth  `mapstructure:"oidc_bearer" validate:"omitempty"`
}

// AuthPipelineSection configures authentication pipeline limits and shared behavior.
type AuthPipelineSection struct {
	MaxConcurrentRequests int32                  `mapstructure:"max_concurrent_requests" validate:"omitempty,gte=1"`
	MaxLoginAttempts      uint8                  `mapstructure:"max_login_attempts" validate:"omitempty"`
	WaitDelay             uint8                  `mapstructure:"wait_delay" validate:"omitempty"`
	LocalCacheTTL         time.Duration          `mapstructure:"local_cache_ttl" validate:"omitempty"`
	PasswordHistory       PasswordHistorySection `mapstructure:"password_history" validate:"omitempty"`
	MasterUser            MasterUser             `mapstructure:"master_user" validate:"omitempty"`
}

// PasswordHistorySection groups password-history related limits.
type PasswordHistorySection struct {
	MaxEntries int32 `mapstructure:"max_entries" validate:"omitempty,gte=1"`
}

// AuthUpstreamsSection configures protocol-specific upstream endpoints.
type AuthUpstreamsSection struct {
	SMTP ProtocolUpstream `mapstructure:"smtp" validate:"omitempty"`
	IMAP ProtocolUpstream `mapstructure:"imap" validate:"omitempty"`
	POP3 ProtocolUpstream `mapstructure:"pop3" validate:"omitempty"`
}

// ProtocolUpstream describes a single upstream address and port.
type ProtocolUpstream struct {
	Address string `mapstructure:"address" validate:"omitempty,hostname_rfc1123"`
	Port    int    `mapstructure:"port" validate:"omitempty,gte=1,lte=65535"`
}

// AuthBackendsSection configures backend selection and backend-specific settings.
type AuthBackendsSection struct {
	Order  []*Backend                       `mapstructure:"order" validate:"omitempty,dive"`
	LDAP   LDAPBackendSection               `mapstructure:"ldap" validate:"omitempty"`
	Lua    LuaBackendRoot                   `mapstructure:"lua" validate:"omitempty"`
	Remote map[string]*RemoteBackendSection `mapstructure:"remote" validate:"omitempty,dive"`
}

const (
	// RemoteBackendModeNauthilus selects a Nauthilus authority backend.
	RemoteBackendModeNauthilus = "nauthilus"

	// RemoteBackendOperationAuth permits password authentication RPCs.
	RemoteBackendOperationAuth = "auth"
	// RemoteBackendOperationLookupIdentity permits no-auth identity lookup RPCs.
	RemoteBackendOperationLookupIdentity = "lookup_identity"
	// RemoteBackendOperationListAccounts permits account listing RPCs.
	RemoteBackendOperationListAccounts = "list_accounts"
	// RemoteBackendOperationMFARead permits MFA read RPCs in later slices.
	RemoteBackendOperationMFARead = "mfa_read"
	// RemoteBackendOperationMFAVerify permits MFA verification RPCs in later slices.
	RemoteBackendOperationMFAVerify = "mfa_verify"
	// RemoteBackendOperationMFAWrite permits MFA write RPCs in later slices.
	RemoteBackendOperationMFAWrite = "mfa_write"
	// RemoteBackendOperationWebAuthnRead permits WebAuthn read RPCs in later slices.
	RemoteBackendOperationWebAuthnRead = "webauthn_read"
	// RemoteBackendOperationWebAuthnWrite permits WebAuthn write RPCs in later slices.
	RemoteBackendOperationWebAuthnWrite = "webauthn_write"
	// RemoteBackendOperationAttributeRead permits attribute read RPCs in later slices.
	RemoteBackendOperationAttributeRead = "attribute_read"
)

var validRemoteBackendOperations = map[string]struct{}{
	RemoteBackendOperationAuth:           {},
	RemoteBackendOperationLookupIdentity: {},
	RemoteBackendOperationListAccounts:   {},
	RemoteBackendOperationMFARead:        {},
	RemoteBackendOperationMFAVerify:      {},
	RemoteBackendOperationMFAWrite:       {},
	RemoteBackendOperationWebAuthnRead:   {},
	RemoteBackendOperationWebAuthnWrite:  {},
	RemoteBackendOperationAttributeRead:  {},
}

// RemoteBackendSection configures one named remote backend.
type RemoteBackendSection struct {
	Authority         string        `mapstructure:"authority" validate:"omitempty,printascii,excludesall= "`
	Mode              string        `mapstructure:"mode" validate:"omitempty,oneof=nauthilus"`
	AllowedOperations []string      `mapstructure:"allowed_operations" validate:"omitempty,dive,printascii,excludesall= "`
	Timeout           time.Duration `mapstructure:"timeout" validate:"omitempty,gt=0,max=1m"`
}

// GetAuthority returns the referenced outbound authority name.
func (s *RemoteBackendSection) GetAuthority() string {
	if s == nil {
		return ""
	}

	return s.Authority
}

// GetMode returns the remote backend mode.
func (s *RemoteBackendSection) GetMode() string {
	if s == nil || s.Mode == "" {
		return RemoteBackendModeNauthilus
	}

	return s.Mode
}

// GetAllowedOperations returns a copy of the allowed operation names.
func (s *RemoteBackendSection) GetAllowedOperations() []string {
	if s == nil {
		return nil
	}

	return append([]string(nil), s.AllowedOperations...)
}

// GetTimeout returns the backend-specific authority RPC timeout.
func (s *RemoteBackendSection) GetTimeout() time.Duration {
	if s == nil || s.Timeout <= 0 {
		return defaultNauthilusAuthorityTimeout
	}

	return s.Timeout
}

// AllowsOperation reports whether the operation is enabled for this backend.
func (s *RemoteBackendSection) AllowsOperation(operation string) bool {
	if s == nil {
		return false
	}

	return slices.Contains(s.AllowedOperations, operation)
}

// LDAPBackendSection configures LDAP backends and protocol mappings.
type LDAPBackendSection struct {
	Default *LDAPConf            `mapstructure:"default" validate:"required"`
	Pools   map[string]*LDAPConf `mapstructure:"pools" validate:"omitempty,validatDefaultBackendName,dive"`
	Search  []LDAPSearchProtocol `mapstructure:"search" validate:"omitempty,dive"`
}

// LuaBackendRoot is the schema root for Lua backend configuration.
type LuaBackendRoot struct {
	Backend LuaBackendSection `mapstructure:"backend" validate:"omitempty"`
}

// LuaBackendSection configures Lua backends and protocol mappings.
type LuaBackendSection struct {
	Default       *LuaConf            `mapstructure:"default" validate:"omitempty"`
	NamedBackends map[string]*LuaConf `mapstructure:"named_backends" validate:"omitempty,dive"`
	Search        []LuaSearchProtocol `mapstructure:"search" validate:"omitempty,dive"`
}

// AuthControlsSection configures all policy controls.
type AuthControlsSection struct {
	Enabled       []*Control                `mapstructure:"enabled" validate:"omitempty,dive"`
	TLSEncryption TLSEncryptionControl      `mapstructure:"tls_encryption" validate:"omitempty"`
	RBL           *RBLControlSection        `mapstructure:"rbl" validate:"omitempty"`
	RelayDomains  *RelayDomainsControl      `mapstructure:"relay_domains" validate:"omitempty"`
	BruteForce    *BruteForceControlSection `mapstructure:"brute_force" validate:"omitempty"`
	Lua           *LuaControlSection        `mapstructure:"lua" validate:"omitempty"`
}

// TLSEncryptionControl configures cleartext exceptions for TLS enforcement.
type TLSEncryptionControl struct {
	AllowCleartextNetworks []string `mapstructure:"allow_cleartext_networks" validate:"omitempty,dive"`
}

// RBLControlSection configures RBL-based policy checks.
type RBLControlSection struct {
	Lists       []RBL    `mapstructure:"lists" validate:"required,dive"`
	Threshold   int      `mapstructure:"threshold" validate:"omitempty,min=0,max=100"`
	IPAllowlist []string `mapstructure:"ip_allowlist" validate:"omitempty,dive,ip_addr|cidr"`
}

// RelayDomainsControl configures relay-domain policy behavior.
type RelayDomainsControl struct {
	Static    []string      `mapstructure:"static" validate:"required,dive,hostname_rfc1123_with_opt_trailing_dot"`
	Allowlist SoftWhitelist `mapstructure:"allowlist"`
}

// BruteForceControlSection configures brute-force detection and toleration behavior.
type BruteForceControlSection struct {
	Protocols                  []*Protocol      `mapstructure:"protocols" validate:"omitempty,dive"`
	IPAllowlist                []string         `mapstructure:"ip_allowlist" validate:"omitempty,dive,ip_addr|cidr"`
	Buckets                    []BruteForceRule `mapstructure:"buckets" validate:"required,dive"`
	Learning                   []*RuntimeModule `mapstructure:"learning" validate:"omitempty,dive"`
	CustomTolerations          []Tolerate       `mapstructure:"custom_tolerations" validate:"omitempty,dive"`
	IPScoping                  IPScoping        `mapstructure:"ip_scoping"`
	Allowlist                  SoftWhitelist    `mapstructure:"allowlist"`
	TolerateTTL                time.Duration    `mapstructure:"tolerate_ttl" validate:"omitempty,gt=0,max=8760h"`
	RWPWindow                  time.Duration    `mapstructure:"rwp_window" validate:"omitempty,gt=0,max=8760h"`
	ScaleFactor                float64          `mapstructure:"scale_factor" validate:"omitempty,min=0.1,max=10"`
	AllowedUniqueWrongPWHashes uint             `mapstructure:"rwp_allowed_unique_hashes" validate:"omitempty,min=1,max=100"`
	ToleratePercent            uint8            `mapstructure:"tolerate_percent" validate:"omitempty,min=0,max=100"`
	MinToleratePercent         uint8            `mapstructure:"min_tolerate_percent" validate:"omitempty,min=0,max=100"`
	MaxToleratePercent         uint8            `mapstructure:"max_tolerate_percent" validate:"omitempty,min=0,max=100"`
	AdaptiveToleration         bool             `mapstructure:"adaptive_toleration"`
	LogHistoryForKnownAccounts bool             `mapstructure:"pw_history_for_known_accounts"`
}

// LuaControlSection configures Lua-based hooks.
type LuaControlSection struct {
	Hooks []LuaHooks `mapstructure:"hooks" validate:"omitempty,dive"`
}

// AuthServicesSection configures background services.
type AuthServicesSection struct {
	Enabled             []*Service                  `mapstructure:"enabled" validate:"omitempty,dive"`
	BackendHealthChecks *BackendHealthChecksSection `mapstructure:"backend_health_checks" validate:"omitempty"`
}

// AuthPolicySection configures the declarative auth decision compiler.
type AuthPolicySection struct {
	Sets              PolicySetsConfig                       `mapstructure:"sets" validate:"omitempty"`
	SchedulerGuards   map[string]PolicySchedulerGuardConfig  `mapstructure:"scheduler_guards" validate:"omitempty"`
	Report            PolicyReportConfig                     `mapstructure:"report" validate:"omitempty"`
	AttributeSources  PolicyAttributeSourcesConfig           `mapstructure:"attribute_sources" validate:"omitempty"`
	ObligationTargets PolicyObligationTargetsConfig          `mapstructure:"obligation_targets" validate:"omitempty"`
	Mode              string                                 `mapstructure:"mode" validate:"omitempty,oneof=enforce observe"`
	DefaultPolicy     string                                 `mapstructure:"default_policy" validate:"omitempty,printascii"`
	RegistryScripts   []string                               `mapstructure:"registry_scripts" validate:"omitempty,dive,file"`
	RequestHeaders    []PolicyRequestHeaderAttributeConfig   `mapstructure:"request_headers" validate:"omitempty,dive"`
	RequestMetadata   []PolicyRequestMetadataAttributeConfig `mapstructure:"request_metadata" validate:"omitempty,dive"`
	AttributeExports  []PolicyAttributeExportConfig          `mapstructure:"attribute_exports" validate:"omitempty,dive"`
	Checks            []PolicyCheckConfig                    `mapstructure:"checks" validate:"omitempty,dive"`
	Policies          []PolicyRuleConfig                     `mapstructure:"policies" validate:"omitempty,dive"`
}

func defaultAuthPolicySection() AuthPolicySection {
	return AuthPolicySection{
		Mode:          "enforce",
		DefaultPolicy: defaultAuthPolicyName,
		Report: PolicyReportConfig{
			IncludeFSM:    true,
			IncludeChecks: true,
		},
	}
}

func applyAuthPolicyDefaults(policyConfig *AuthPolicySection) {
	if policyConfig == nil {
		return
	}

	if policyConfig.Mode == "" {
		policyConfig.Mode = "enforce"
	}

	if policyConfig.DefaultPolicy == "" {
		policyConfig.DefaultPolicy = defaultAuthPolicyName
	}

	if !policyConfig.Report.Enabled {
		if !policyConfig.Report.IncludeFSM {
			policyConfig.Report.IncludeFSM = true
		}

		if !policyConfig.Report.IncludeChecks {
			policyConfig.Report.IncludeChecks = true
		}
	}
}

// PolicyObligationTargetsConfig groups executable targets selected by policy obligations.
type PolicyObligationTargetsConfig struct {
	Lua PolicyLuaObligationTargetsConfig `mapstructure:"lua" validate:"omitempty"`
}

// PolicyLuaObligationTargetsConfig configures Lua obligation target scripts.
type PolicyLuaObligationTargetsConfig struct {
	Actions []LuaAction `mapstructure:"actions" validate:"omitempty,dive"`
}

// PolicyAttributeSourcesConfig groups request-time policy attribute producers.
type PolicyAttributeSourcesConfig struct {
	Lua PolicyLuaAttributeSourcesConfig `mapstructure:"lua" validate:"omitempty"`
}

// PolicyLuaAttributeSourcesConfig configures Lua attribute sources by XACML-aligned category.
type PolicyLuaAttributeSourcesConfig struct {
	Environment []LuaEnvironmentSource `mapstructure:"environment" validate:"omitempty,dive"`
	Subject     []LuaSubjectSource     `mapstructure:"subject" validate:"omitempty,dive"`
}

// PolicySetsConfig groups reusable policy operands.
type PolicySetsConfig struct {
	Networks    map[string][]string               `mapstructure:"networks" validate:"omitempty"`
	TimeWindows map[string]PolicyTimeWindowConfig `mapstructure:"time_windows" validate:"omitempty"`
}

// PolicySchedulerGuardConfig configures one compile-time scheduler skip guard.
type PolicySchedulerGuardConfig struct {
	If                 PolicyConditionConfig `mapstructure:"if" validate:"omitempty"`
	OnMissingAttribute string                `mapstructure:"on_missing_attribute" validate:"omitempty,printascii"`
}

// PolicyTimeWindowConfig configures a named local-time window set.
type PolicyTimeWindowConfig struct {
	Timezone  string                     `mapstructure:"timezone" validate:"omitempty,printascii"`
	Days      []string                   `mapstructure:"days" validate:"omitempty,dive,printascii"`
	Intervals []PolicyTimeIntervalConfig `mapstructure:"intervals" validate:"omitempty,dive"`
}

// PolicyTimeIntervalConfig configures one local-time interval.
type PolicyTimeIntervalConfig struct {
	Start string `mapstructure:"start" validate:"omitempty,printascii"`
	End   string `mapstructure:"end" validate:"omitempty,printascii"`
}

// PolicyReportConfig controls optional policy diagnostic reports.
type PolicyReportConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	IncludeFSM        bool `mapstructure:"include_fsm"`
	IncludeChecks     bool `mapstructure:"include_checks"`
	IncludeAttributes bool `mapstructure:"include_attributes"`
}

// PolicyRequestHeaderAttributeConfig exposes one allowlisted HTTP request header as a policy fact.
type PolicyRequestHeaderAttributeConfig struct {
	Normalize  PolicyRequestAttributeNormalizeConfig `mapstructure:"normalize" validate:"omitempty"`
	Header     string                                `mapstructure:"header" validate:"required,printascii"`
	Attribute  string                                `mapstructure:"attribute" validate:"required,printascii"`
	Visibility string                                `mapstructure:"visibility" validate:"omitempty,printascii"`
}

// PolicyRequestMetadataAttributeConfig exposes one allowlisted gRPC metadata key as a policy fact.
type PolicyRequestMetadataAttributeConfig struct {
	Normalize  PolicyRequestAttributeNormalizeConfig `mapstructure:"normalize" validate:"omitempty"`
	Key        string                                `mapstructure:"key" validate:"required,printascii"`
	Attribute  string                                `mapstructure:"attribute" validate:"required,printascii"`
	Visibility string                                `mapstructure:"visibility" validate:"omitempty,printascii"`
}

// PolicyRequestAttributeNormalizeConfig configures deterministic request-attribute value normalization.
type PolicyRequestAttributeNormalizeConfig struct {
	Trim      bool   `mapstructure:"trim"`
	Case      string `mapstructure:"case" validate:"omitempty,printascii"`
	MaxLength int    `mapstructure:"max_length" validate:"omitempty,gte=0"`
}

// PolicyAttributeExportConfig exposes one backend AuthState attribute as an opt-in policy subject fact.
type PolicyAttributeExportConfig struct {
	Name        string `mapstructure:"name" validate:"required,printascii"`
	Attribute   string `mapstructure:"attribute" validate:"required,printascii"`
	Type        string `mapstructure:"type" validate:"required,oneof=bool string string_list number"`
	Sensitivity string `mapstructure:"sensitivity" validate:"omitempty,oneof=public internal secret"`
}

// PolicyCheckConfig configures one fact-producing policy check.
type PolicyCheckConfig struct {
	RunIf       PolicyRunIfConfig `mapstructure:"run_if" validate:"omitempty"`
	ObserveSafe *bool             `mapstructure:"observe_safe" validate:"omitempty"`
	Operations  []string          `mapstructure:"operations" validate:"omitempty,dive,printascii"`
	After       []string          `mapstructure:"after" validate:"omitempty,dive,printascii"`
	SkipIf      []string          `mapstructure:"skip_if" validate:"omitempty,dive,printascii"`
	Name        string            `mapstructure:"name" validate:"omitempty,printascii"`
	Type        string            `mapstructure:"type" validate:"omitempty,printascii"`
	Stage       string            `mapstructure:"stage" validate:"omitempty,printascii"`
	ConfigRef   string            `mapstructure:"config_ref" validate:"omitempty,printascii"`
	Output      string            `mapstructure:"output" validate:"omitempty,printascii"`
}

// PolicyRunIfConfig configures the small structural check scheduler guard.
type PolicyRunIfConfig struct {
	AuthState string `mapstructure:"auth_state" validate:"omitempty,oneof=authenticated unauthenticated any"`
}

// PolicyRuleConfig configures one ordered policy rule.
type PolicyRuleConfig struct {
	If            PolicyConditionConfig `mapstructure:"if" validate:"omitempty"`
	Then          PolicyThenConfig      `mapstructure:"then" validate:"omitempty"`
	Name          string                `mapstructure:"name" validate:"omitempty,printascii"`
	Stage         string                `mapstructure:"stage" validate:"omitempty,printascii"`
	Operations    []string              `mapstructure:"operations" validate:"omitempty,dive,printascii"`
	RequireChecks []string              `mapstructure:"require_checks" validate:"omitempty,dive,printascii"`
}

// PolicyConditionConfig is the decoded YAML shape for a policy condition tree.
type PolicyConditionConfig struct {
	Not              *PolicyConditionConfig  `mapstructure:"not" validate:"omitempty"`
	Always           *bool                   `mapstructure:"always" validate:"omitempty"`
	Attribute        string                  `mapstructure:"attribute" validate:"omitempty,printascii"`
	Detail           string                  `mapstructure:"detail" validate:"omitempty,printascii"`
	Matches          string                  `mapstructure:"matches" validate:"omitempty"`
	CIDRContains     string                  `mapstructure:"cidr_contains" validate:"omitempty,printascii"`
	WithinTimeWindow string                  `mapstructure:"within_time_window" validate:"omitempty,printascii"`
	Is               any                     `mapstructure:"is" validate:"omitempty"`
	Eq               any                     `mapstructure:"eq" validate:"omitempty"`
	Ne               any                     `mapstructure:"ne" validate:"omitempty"`
	In               []any                   `mapstructure:"in" validate:"omitempty"`
	NotIn            []any                   `mapstructure:"not_in" validate:"omitempty"`
	Exists           *bool                   `mapstructure:"exists" validate:"omitempty"`
	Contains         any                     `mapstructure:"contains" validate:"omitempty"`
	ContainsAny      []any                   `mapstructure:"contains_any" validate:"omitempty"`
	ContainsAll      []any                   `mapstructure:"contains_all" validate:"omitempty"`
	ContainsNone     []any                   `mapstructure:"contains_none" validate:"omitempty"`
	GT               any                     `mapstructure:"gt" validate:"omitempty"`
	GTE              any                     `mapstructure:"gte" validate:"omitempty"`
	LT               any                     `mapstructure:"lt" validate:"omitempty"`
	LTE              any                     `mapstructure:"lte" validate:"omitempty"`
	All              []PolicyConditionConfig `mapstructure:"all" validate:"omitempty,dive"`
	Any              []PolicyConditionConfig `mapstructure:"any" validate:"omitempty,dive"`
}

// PolicyThenConfig configures the selected policy decision and enforcement markers.
type PolicyThenConfig struct {
	ResponseMessage  PolicyResponseMessageConfig  `mapstructure:"response_message" validate:"omitempty"`
	ResponseLanguage PolicyResponseLanguageConfig `mapstructure:"response_language" validate:"omitempty"`
	Control          PolicyDecisionControlConfig  `mapstructure:"control" validate:"omitempty"`
	Decision         string                       `mapstructure:"decision" validate:"omitempty,printascii"`
	Reason           string                       `mapstructure:"reason" validate:"omitempty,printascii"`
	OutcomeMarker    string                       `mapstructure:"outcome_marker" validate:"omitempty,printascii"`
	FSMEventMarker   string                       `mapstructure:"fsm_event_marker" validate:"omitempty,printascii"`
	ResponseMarker   string                       `mapstructure:"response_marker" validate:"omitempty,printascii"`
	Obligations      []PolicyEffectConfig         `mapstructure:"obligations" validate:"omitempty,dive"`
	Advice           []PolicyEffectConfig         `mapstructure:"advice" validate:"omitempty,dive"`
}

// PolicyResponseMessageConfig configures an optional client-visible message source.
type PolicyResponseMessageConfig struct {
	From      string `mapstructure:"from" validate:"omitempty,printascii"`
	Text      string `mapstructure:"text" validate:"omitempty"`
	I18NKey   string `mapstructure:"i18n_key" validate:"omitempty,printascii"`
	Attribute string `mapstructure:"attribute" validate:"omitempty,printascii"`
	Detail    string `mapstructure:"detail" validate:"omitempty,printascii"`
	Fallback  string `mapstructure:"fallback" validate:"omitempty"`
}

// PolicyResponseLanguageConfig configures optional response-rendering language metadata.
type PolicyResponseLanguageConfig struct {
	From      string `mapstructure:"from" validate:"omitempty,printascii"`
	Language  string `mapstructure:"language" validate:"omitempty,printascii"`
	Attribute string `mapstructure:"attribute" validate:"omitempty,printascii"`
	Fallback  string `mapstructure:"fallback" validate:"omitempty,printascii"`
}

// PolicyEffectConfig references a registered obligation or advice.
type PolicyEffectConfig struct {
	ID   string         `mapstructure:"id" validate:"omitempty,printascii"`
	Args map[string]any `mapstructure:"args" validate:"omitempty"`
}

// PolicyDecisionControlConfig configures stage-local policy control output.
type PolicyDecisionControlConfig struct {
	SkipRemainingStageChecks bool `mapstructure:"skip_remaining_stage_checks"`
}

// BackendHealthChecksSection configures backend reachability checks.
type BackendHealthChecksSection struct {
	Targets []*BackendServer `mapstructure:"targets" validate:"required,dive"`

	ConnectTimeout  time.Duration `mapstructure:"connect_timeout" validate:"omitempty,gt=0,max=1m"`
	TLSTimeout      time.Duration `mapstructure:"tls_timeout" validate:"omitempty,gt=0,max=1m"`
	DeepTimeout     time.Duration `mapstructure:"deep_timeout" validate:"omitempty,gt=0,max=5m"`
	ConnectInterval time.Duration `mapstructure:"connect_interval" validate:"omitempty,gt=0,max=24h"`
	DeepInterval    time.Duration `mapstructure:"deep_interval" validate:"omitempty,gt=0,max=24h"`

	FailureThreshold  int `mapstructure:"failure_threshold" validate:"omitempty,min=1,max=100"`
	RecoveryThreshold int `mapstructure:"recovery_threshold" validate:"omitempty,min=1,max=100"`
}

// IdentitySection groups frontend, MFA, and identity-provider protocols.
type IdentitySection struct {
	Session  IdentitySessionSection  `mapstructure:"session" validate:"omitempty"`
	Frontend IdentityFrontendSection `mapstructure:"frontend" validate:"omitempty"`
	MFA      IdentityMFASection      `mapstructure:"mfa" validate:"omitempty"`
	OIDC     OIDCWireConfig          `mapstructure:"oidc" validate:"omitempty"`
	SAML     SAML2Config             `mapstructure:"saml" validate:"omitempty"`
}

// IdentitySessionSection configures shared identity-session behavior.
type IdentitySessionSection struct {
	RememberMeTTL time.Duration `mapstructure:"remember_me_ttl"`
}

// IdentityFrontendSection configures the interactive frontend.
type IdentityFrontendSection struct {
	Enabled          bool                         `mapstructure:"enabled"`
	EncryptionSecret secret.Value                 `mapstructure:"encryption_secret" validate:"secret_required_if_enabled,secret_min=16,alphanumsymbol,secret_excludesall= "`
	Assets           IdentityFrontendAssets       `mapstructure:"assets" validate:"omitempty"`
	Localization     IdentityFrontendLocalization `mapstructure:"localization" validate:"omitempty"`
	Links            IdentityFrontendLinks        `mapstructure:"links" validate:"omitempty"`
	SecurityHeaders  FrontendSecurityHeaders      `mapstructure:"security_headers" validate:"omitempty"`
}

// IdentityFrontendAssets configures frontend asset locations.
type IdentityFrontendAssets struct {
	HTMLStaticContentPath string `mapstructure:"html_static_content_path" validate:"omitempty,dir"`
	LanguageResources     string `mapstructure:"language_resources" validate:"omitempty,dir"`
}

// IdentityFrontendLocalization configures supported languages.
type IdentityFrontendLocalization struct {
	Languages       []string `mapstructure:"languages" validate:"omitempty"`
	DefaultLanguage string   `mapstructure:"default_language" validate:"omitempty"`
}

// IdentityFrontendLinks configures legal and recovery links shown by the frontend.
type IdentityFrontendLinks struct {
	TermsOfServiceURL    string `mapstructure:"terms_of_service_url"`
	PrivacyPolicyURL     string `mapstructure:"privacy_policy_url"`
	PasswordForgottenURL string `mapstructure:"password_forgotten_url"`
}

// IdentityMFASection groups MFA-related configuration.
type IdentityMFASection struct {
	TOTP     IdentityTOTPSection `mapstructure:"totp" validate:"omitempty"`
	WebAuthn WebAuthn            `mapstructure:"webauthn" validate:"omitempty"`
}

// IdentityTOTPSection configures TOTP defaults.
type IdentityTOTPSection struct {
	Issuer string `mapstructure:"issuer" validate:"omitempty"`
	Skew   uint   `mapstructure:"skew" validate:"omitempty"`
}

// OIDCWireConfig is the wire-level OIDC schema used by config unmarshalling.
type OIDCWireConfig struct {
	Enabled                           bool                `mapstructure:"enabled"`
	Issuer                            string              `mapstructure:"issuer"`
	SigningKeys                       []OIDCKey           `mapstructure:"signing_keys"`
	AutoKeyRotation                   bool                `mapstructure:"auto_key_rotation"`
	KeyRotationInterval               time.Duration       `mapstructure:"key_rotation_interval"`
	KeyMaxAge                         time.Duration       `mapstructure:"key_max_age"`
	Clients                           []OIDCClient        `mapstructure:"clients"`
	CustomScopes                      []Oauth2CustomScope `mapstructure:"custom_scopes" validate:"omitempty,dive"`
	ScopesSupported                   []string            `mapstructure:"scopes_supported"`
	ResponseTypesSupported            []string            `mapstructure:"response_types_supported"`
	SubjectTypesSupported             []string            `mapstructure:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string            `mapstructure:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string            `mapstructure:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string            `mapstructure:"code_challenge_methods_supported"`
	ClaimsSupported                   []string            `mapstructure:"claims_supported"`
	AccessTokenType                   string              `mapstructure:"access_token_type"`
	Consent                           OIDCConsentSection  `mapstructure:"consent" validate:"omitempty"`
	Tokens                            OIDCTokensSection   `mapstructure:"tokens" validate:"omitempty"`
	Logout                            OIDCLogoutSection   `mapstructure:"logout" validate:"omitempty"`
	DeviceFlow                        OIDCDeviceFlow      `mapstructure:"device_flow" validate:"omitempty"`
}

// OIDCConsentSection configures consent defaults.
type OIDCConsentSection struct {
	TTL  time.Duration `mapstructure:"ttl"`
	Mode string        `mapstructure:"mode" validate:"omitempty,oneof=all_or_nothing granular_optional"`
}

// OIDCTokensSection configures token lifetimes and token endpoint behavior.
type OIDCTokensSection struct {
	DefaultAccessTokenLifetime  time.Duration `mapstructure:"default_access_token_lifetime"`
	DefaultRefreshTokenLifetime time.Duration `mapstructure:"default_refresh_token_lifetime"`
	RevokeRefreshToken          *bool         `mapstructure:"revoke_refresh_token"`
	TokenEndpointAllowGET       bool          `mapstructure:"token_endpoint_allow_get"`
}

// OIDCLogoutSection configures supported logout capabilities.
type OIDCLogoutSection struct {
	FrontChannelSupported        *bool `mapstructure:"front_channel_supported"`
	FrontChannelSessionSupported *bool `mapstructure:"front_channel_session_supported"`
	BackChannelSupported         *bool `mapstructure:"back_channel_supported"`
	BackChannelSessionSupported  *bool `mapstructure:"back_channel_session_supported"`
}

// OIDCDeviceFlow configures device-flow defaults.
type OIDCDeviceFlow struct {
	CodeExpiry      time.Duration `mapstructure:"code_expiry"`
	PollingInterval int           `mapstructure:"polling_interval"`
	UserCodeLength  int           `mapstructure:"user_code_length"`
}

func (f *FileSettings) materializeLegacySections() {
	if f == nil {
		return
	}

	if f.Runtime == nil && f.Observability == nil && f.Storage == nil && f.Auth == nil && f.Identity == nil {
		return
	}

	if f.Server == nil {
		f.Server = f.materializeServerSection()
	}

	if f.RBLs == nil {
		f.RBLs = f.materializeRBLSection()
	}

	if f.ClearTextList == nil {
		f.ClearTextList = f.materializeCleartextNetworks()
	}

	if f.RelayDomains == nil {
		f.RelayDomains = f.materializeRelayDomains()
	}

	if f.BackendServerMonitoring == nil {
		f.BackendServerMonitoring = f.materializeBackendServerMonitoring()
	}

	if f.BruteForce == nil {
		f.BruteForce = f.materializeBruteForce()
	}

	if f.Lua == nil {
		f.Lua = f.materializeLua()
	}

	if f.LDAP == nil {
		f.LDAP = f.materializeLDAP()
	}

	if f.IDP == nil {
		f.IDP = f.materializeIDP()
	}
}

func (f *FileSettings) materializeServerSection() *ServerSection {
	server := &ServerSection{}

	f.applyRuntimeSection(server)
	f.applyObservabilitySection(server)
	f.applyStorageSection(server)
	f.applyAuthSection(server)
	f.applyIdentitySection(server)

	return server
}

func (f *FileSettings) applyRuntimeSection(server *ServerSection) {
	if f == nil || server == nil || f.Runtime == nil {
		return
	}

	runtime := f.Runtime
	httpServer := runtime.Servers.HTTP

	server.InstanceName = runtime.InstanceName
	server.Address = httpServer.Address
	server.HTTP3 = httpServer.HTTP3
	server.HAproxyV2 = httpServer.HAproxyV2
	server.TLS = httpServer.TLS
	server.TrustedProxies = append([]string(nil), httpServer.TrustedProxies...)
	server.DisabledEndpoints = httpServer.DisabledEndpoints
	server.Middlewares = httpServer.Middlewares
	server.OpenAPIValidation = httpServer.OpenAPIValidation
	server.Compression = httpServer.Compression
	server.KeepAlive = httpServer.KeepAlive
	server.RateLimitPerSecond = httpServer.RateLimit.PerSecond
	server.RateLimitBurst = httpServer.RateLimit.Burst
	server.Timeouts = runtime.Timeouts
	server.CORS = httpServer.CORS
	server.SecurityTxt = httpServer.SecurityTxt
	server.HTTPClient = runtime.Clients.HTTP
	server.DNS = runtime.Clients.DNS
	server.RunAsUser = runtime.Process.RunAsUser
	server.RunAsGroup = runtime.Process.RunAsGroup
	server.Chroot = runtime.Process.Chroot
}

func (f *FileSettings) applyObservabilitySection(server *ServerSection) {
	if f == nil || server == nil || f.Observability == nil {
		return
	}

	observability := f.Observability

	server.Log = observability.Log
	server.Insights.EnablePprof = observability.Profiles.Pprof.Enabled
	server.Insights.EnableBlockProfile = observability.Profiles.Block.Enabled
	server.Insights.MonitorConnections = observability.Metrics.MonitorConnections
	server.Insights.Tracing = observability.Tracing
	server.PrometheusTimer = observability.Metrics.PrometheusTimer
	server.MetricsEndpointAuth = observability.Metrics.EndpointAuth
}

func (f *FileSettings) applyStorageSection(server *ServerSection) {
	if f == nil || server == nil || f.Storage == nil {
		return
	}

	server.Redis = f.Storage.Redis
	server.Redis.Master = server.Redis.Primary
	server.Redis.Primary = Master{}
}

func (f *FileSettings) applyAuthSection(server *ServerSection) {
	if f == nil || server == nil || f.Auth == nil {
		return
	}

	auth := f.Auth

	server.BasicAuth = auth.Backchannel.BasicAuth
	server.OIDCAuth = auth.Backchannel.OIDCBearer
	server.MaxConcurrentRequests = auth.Pipeline.MaxConcurrentRequests
	server.MaxLoginAttempts = auth.Pipeline.MaxLoginAttempts
	server.NginxWaitDelay = auth.Pipeline.WaitDelay
	server.LocalCacheAuthTTL = auth.Pipeline.LocalCacheTTL
	server.MaxPasswordHistoryEntries = auth.Pipeline.PasswordHistory.MaxEntries
	server.MasterUser = auth.Pipeline.MasterUser
	server.Backends = auth.Backends.Order
	server.Controls = auth.Controls.Enabled
	server.Services = auth.Services.Enabled
	server.DefaultHTTPRequestHeader = auth.Request.Headers
	server.BruteForceProtocols = auth.BruteForceProtocols()
	server.IMAPBackendAddress = auth.Upstreams.IMAP.Address
	server.IMAPBackendPort = auth.Upstreams.IMAP.Port
	server.POP3BackendAddress = auth.Upstreams.POP3.Address
	server.POP3BackendPort = auth.Upstreams.POP3.Port
	server.SMTPBackendAddress = auth.Upstreams.SMTP.Address
	server.SMTPBackendPort = auth.Upstreams.SMTP.Port
}

func (f *FileSettings) applyIdentitySection(server *ServerSection) {
	if f == nil || server == nil || f.Identity == nil {
		return
	}

	identity := f.Identity

	server.Frontend.Enabled = identity.Frontend.Enabled
	server.Frontend.EncryptionSecret = identity.Frontend.EncryptionSecret
	server.Frontend.HTMLStaticContentPath = identity.Frontend.Assets.HTMLStaticContentPath
	server.Frontend.LanguageResources = identity.Frontend.Assets.LanguageResources
	server.Frontend.Languages = append([]string(nil), identity.Frontend.Localization.Languages...)
	server.Frontend.DefaultLanguage = identity.Frontend.Localization.DefaultLanguage
	server.Frontend.TotpIssuer = identity.MFA.TOTP.Issuer
	server.Frontend.TotpSkew = identity.MFA.TOTP.Skew
	server.Frontend.SecurityHeaders = identity.Frontend.SecurityHeaders
}

func (f *FileSettings) materializeRBLSection() *RBLSection {
	if f == nil || f.Auth == nil || f.Auth.Controls.RBL == nil {
		return nil
	}

	return &RBLSection{
		Lists:       append([]RBL(nil), f.Auth.Controls.RBL.Lists...),
		Threshold:   f.Auth.Controls.RBL.Threshold,
		IPWhiteList: append([]string(nil), f.Auth.Controls.RBL.IPAllowlist...),
	}
}

func (f *FileSettings) materializeCleartextNetworks() []string {
	if f == nil || f.Auth == nil {
		return nil
	}

	return append([]string(nil), f.Auth.Controls.TLSEncryption.AllowCleartextNetworks...)
}

func (f *FileSettings) materializeRelayDomains() *RelayDomainsSection {
	if f == nil || f.Auth == nil || f.Auth.Controls.RelayDomains == nil {
		return nil
	}

	return &RelayDomainsSection{
		StaticDomains: append([]string(nil), f.Auth.Controls.RelayDomains.Static...),
		SoftWhitelist: f.Auth.Controls.RelayDomains.Allowlist,
	}
}

func (f *FileSettings) materializeBackendServerMonitoring() *BackendServerMonitoring {
	if f == nil || f.Auth == nil || f.Auth.Services.BackendHealthChecks == nil {
		return nil
	}

	wire := f.Auth.Services.BackendHealthChecks

	return &BackendServerMonitoring{
		BackendServers: append([]*BackendServer(nil), wire.Targets...),

		ConnectTimeout:  wire.ConnectTimeout,
		TLSTimeout:      wire.TLSTimeout,
		DeepTimeout:     wire.DeepTimeout,
		ConnectInterval: wire.ConnectInterval,
		DeepInterval:    wire.DeepInterval,

		FailureThreshold:  wire.FailureThreshold,
		RecoveryThreshold: wire.RecoveryThreshold,
	}
}

func (f *FileSettings) materializeBruteForce() *BruteForceSection {
	if f == nil || f.Auth == nil || f.Auth.Controls.BruteForce == nil {
		return nil
	}

	wire := f.Auth.Controls.BruteForce

	return &BruteForceSection{
		IPWhitelist:                append([]string(nil), wire.IPAllowlist...),
		Buckets:                    append([]BruteForceRule(nil), wire.Buckets...),
		Learning:                   append([]*RuntimeModule(nil), wire.Learning...),
		CustomTolerations:          append([]Tolerate(nil), wire.CustomTolerations...),
		IPScoping:                  wire.IPScoping,
		SoftWhitelist:              wire.Allowlist,
		TolerateTTL:                wire.TolerateTTL,
		RWPWindow:                  wire.RWPWindow,
		ScaleFactor:                wire.ScaleFactor,
		AllowedUniqueWrongPWHashes: wire.AllowedUniqueWrongPWHashes,
		ToleratePercent:            wire.ToleratePercent,
		MinToleratePercent:         wire.MinToleratePercent,
		MaxToleratePercent:         wire.MaxToleratePercent,
		AdaptiveToleration:         wire.AdaptiveToleration,
		LogHistoryForKnownAccounts: wire.LogHistoryForKnownAccounts,
	}
}

func (f *FileSettings) materializeLua() *LuaSection {
	if f == nil {
		return nil
	}

	luaSection := &LuaSection{}

	if f.Auth != nil {
		luaSection.Actions = nil
		luaSection.EnvironmentSources = nil
		luaSection.SubjectSources = nil
		luaSection.Hooks = nil

		if f.Auth.Controls.Lua != nil {
			luaSection.Hooks = append([]LuaHooks(nil), f.Auth.Controls.Lua.Hooks...)
		}

		luaSection.Actions = append([]LuaAction(nil), f.Auth.Policy.ObligationTargets.Lua.Actions...)
		luaSection.EnvironmentSources = append([]LuaEnvironmentSource(nil), f.Auth.Policy.AttributeSources.Lua.Environment...)
		luaSection.SubjectSources = append([]LuaSubjectSource(nil), f.Auth.Policy.AttributeSources.Lua.Subject...)

		luaSection.Config = f.Auth.Backends.Lua.Backend.Default
		luaSection.OptionalLuaBackends = f.Auth.Backends.Lua.Backend.NamedBackends
		luaSection.Search = append([]LuaSearchProtocol(nil), f.Auth.Backends.Lua.Backend.Search...)
	}

	if luaSection.Config == nil && len(luaSection.Actions) == 0 && len(luaSection.EnvironmentSources) == 0 &&
		len(luaSection.SubjectSources) == 0 && len(luaSection.Hooks) == 0 && len(luaSection.Search) == 0 &&
		len(luaSection.OptionalLuaBackends) == 0 {
		return nil
	}

	return luaSection
}

func (f *FileSettings) materializeLDAP() *LDAPSection {
	if f == nil || f.Auth == nil {
		return nil
	}

	ldapSection := &LDAPSection{
		Config:            f.Auth.Backends.LDAP.Default,
		OptionalLDAPPools: f.Auth.Backends.LDAP.Pools,
		Search:            append([]LDAPSearchProtocol(nil), f.Auth.Backends.LDAP.Search...),
	}

	if ldapSection.Config == nil && len(ldapSection.Search) == 0 && len(ldapSection.OptionalLDAPPools) == 0 {
		return nil
	}

	return ldapSection
}

func (f *FileSettings) materializeIDP() *IdPSection {
	if f == nil || f.Identity == nil {
		return nil
	}

	return &IdPSection{
		OIDC:                 f.Identity.OIDC.Materialize(),
		SAML2:                f.Identity.SAML,
		WebAuthn:             f.Identity.MFA.WebAuthn,
		RememberMeTTL:        f.Identity.Session.RememberMeTTL,
		TermsOfServiceURL:    f.Identity.Frontend.Links.TermsOfServiceURL,
		PrivacyPolicyURL:     f.Identity.Frontend.Links.PrivacyPolicyURL,
		PasswordForgottenURL: f.Identity.Frontend.Links.PasswordForgottenURL,
	}
}

// BruteForceProtocols returns the configured brute-force protocol list.
func (a *AuthSection) BruteForceProtocols() []*Protocol {
	if a == nil || a.Controls.BruteForce == nil {
		return nil
	}

	return append([]*Protocol(nil), a.Controls.BruteForce.Protocols...)
}

// Materialize converts the wire-level OIDC schema into the runtime OIDC config.
func (o OIDCWireConfig) Materialize() OIDCConfig {
	return OIDCConfig{
		Enabled:                            o.Enabled,
		Issuer:                             o.Issuer,
		SigningKeys:                        append([]OIDCKey(nil), o.SigningKeys...),
		AutoKeyRotation:                    o.AutoKeyRotation,
		KeyRotationInterval:                o.KeyRotationInterval,
		KeyMaxAge:                          o.KeyMaxAge,
		Clients:                            append([]OIDCClient(nil), o.Clients...),
		CustomScopes:                       append([]Oauth2CustomScope(nil), o.CustomScopes...),
		ScopesSupported:                    append([]string(nil), o.ScopesSupported...),
		ResponseTypesSupported:             append([]string(nil), o.ResponseTypesSupported...),
		SubjectTypesSupported:              append([]string(nil), o.SubjectTypesSupported...),
		IDTokenSigningAlgValuesSupported:   append([]string(nil), o.IDTokenSigningAlgValuesSupported...),
		TokenEndpointAuthMethodsSupported:  append([]string(nil), o.TokenEndpointAuthMethodsSupported...),
		CodeChallengeMethodsSupported:      append([]string(nil), o.CodeChallengeMethodsSupported...),
		ClaimsSupported:                    append([]string(nil), o.ClaimsSupported...),
		FrontChannelLogoutSupported:        o.Logout.FrontChannelSupported,
		FrontChannelLogoutSessionSupported: o.Logout.FrontChannelSessionSupported,
		BackChannelLogoutSupported:         o.Logout.BackChannelSupported,
		BackChannelLogoutSessionSupported:  o.Logout.BackChannelSessionSupported,
		AccessTokenType:                    o.AccessTokenType,
		DefaultAccessTokenLifetime:         o.Tokens.DefaultAccessTokenLifetime,
		DefaultRefreshTokenLifetime:        o.Tokens.DefaultRefreshTokenLifetime,
		RevokeRefreshToken:                 o.Tokens.RevokeRefreshToken,
		ConsentTTL:                         o.Consent.TTL,
		ConsentMode:                        o.Consent.Mode,
		TokenEndpointAllowGET:              o.Tokens.TokenEndpointAllowGET,
		DeviceCodeExpiry:                   o.DeviceFlow.CodeExpiry,
		DeviceCodePollingInterval:          o.DeviceFlow.PollingInterval,
		DeviceCodeUserCodeLength:           o.DeviceFlow.UserCodeLength,
	}
}
