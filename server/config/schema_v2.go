package config

import (
	"time"

	"github.com/croessner/nauthilus/server/secret"
)

// RuntimeSection groups process, listener, and HTTP runtime behavior.
type RuntimeSection struct {
	InstanceName string                `mapstructure:"instance_name"`
	Process      RuntimeProcessSection `mapstructure:"process"`
	Listen       RuntimeListenSection  `mapstructure:"listen"`
	HTTP         RuntimeHTTPSection    `mapstructure:"http"`
	Clients      RuntimeClientsSection `mapstructure:"clients"`
}

// RuntimeProcessSection configures privilege dropping and chroot behavior.
type RuntimeProcessSection struct {
	RunAsUser  string `mapstructure:"run_as_user" validate:"omitempty"`
	RunAsGroup string `mapstructure:"run_as_group" validate:"omitempty"`
	Chroot     string `mapstructure:"chroot" validate:"omitempty,dir"`
}

// RuntimeListenSection configures inbound listener settings.
type RuntimeListenSection struct {
	Address        string   `mapstructure:"address" validate:"omitempty,tcp_addr"`
	HTTP3          bool     `mapstructure:"http3"`
	HAproxyV2      bool     `mapstructure:"haproxy_v2"`
	TrustedProxies []string `mapstructure:"trusted_proxies" validate:"omitempty,dive,ip|cidr"`
	TLS            TLS      `mapstructure:"tls" validate:"omitempty"`
}

// RuntimeHTTPSection configures HTTP middleware, timeouts, and endpoint behavior.
type RuntimeHTTPSection struct {
	DisabledEndpoints Endpoint      `mapstructure:"disabled_endpoints" validate:"omitempty"`
	Middlewares       Middlewares   `mapstructure:"middlewares" validate:"omitempty"`
	Compression       Compression   `mapstructure:"compression" validate:"omitempty"`
	KeepAlive         KeepAlive     `mapstructure:"keep_alive" validate:"omitempty"`
	RateLimit         HTTPRateLimit `mapstructure:"rate_limit" validate:"omitempty"`
	Timeouts          Timeouts      `mapstructure:"timeouts" validate:"omitempty"`
	CORS              CORS          `mapstructure:"cors" validate:"omitempty"`
}

// HTTPRateLimit configures the global HTTP rate limiter.
type HTTPRateLimit struct {
	PerSecond float64 `mapstructure:"per_second" validate:"omitempty,min=0"`
	Burst     int     `mapstructure:"burst" validate:"omitempty,min=0"`
}

// RuntimeClientsSection configures outbound HTTP and DNS clients.
type RuntimeClientsSection struct {
	HTTP HTTPClient `mapstructure:"http" validate:"omitempty"`
	DNS  DNS        `mapstructure:"dns" validate:"omitempty"`
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
	MonitorConnections bool            `mapstructure:"monitor_connections"`
	PrometheusTimer    PrometheusTimer `mapstructure:"prometheus_timer" validate:"omitempty"`
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
	Order []*Backend         `mapstructure:"order" validate:"omitempty,dive"`
	LDAP  LDAPBackendSection `mapstructure:"ldap" validate:"omitempty"`
	Lua   LuaBackendRoot     `mapstructure:"lua" validate:"omitempty"`
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
	Learning                   []*Feature       `mapstructure:"learning" validate:"omitempty,dive"`
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

// LuaControlSection configures Lua-based actions, controls, filters, and hooks.
type LuaControlSection struct {
	Actions  []LuaAction  `mapstructure:"actions" validate:"omitempty,dive"`
	Controls []LuaFeature `mapstructure:"controls" validate:"omitempty,dive"`
	Filters  []LuaFilter  `mapstructure:"filters" validate:"omitempty,dive"`
	Hooks    []LuaHooks   `mapstructure:"hooks" validate:"omitempty,dive"`
}

// AuthServicesSection configures background services.
type AuthServicesSection struct {
	Enabled             []*Service                  `mapstructure:"enabled" validate:"omitempty,dive"`
	BackendHealthChecks *BackendHealthChecksSection `mapstructure:"backend_health_checks" validate:"omitempty"`
}

// BackendHealthChecksSection configures backend reachability checks.
type BackendHealthChecksSection struct {
	Targets []*BackendServer `mapstructure:"targets" validate:"required,dive"`
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

	if f.Runtime != nil || f.Observability != nil || f.Storage != nil || f.Auth != nil || f.Identity != nil {
		f.Server = f.materializeServerSection()
		f.RBLs = f.materializeRBLSection()
		f.ClearTextList = f.materializeCleartextNetworks()
		f.RelayDomains = f.materializeRelayDomains()
		f.BackendServerMonitoring = f.materializeBackendServerMonitoring()
		f.BruteForce = f.materializeBruteForce()
		f.Lua = f.materializeLua()
		f.LDAP = f.materializeLDAP()
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

	server.InstanceName = runtime.InstanceName
	server.Address = runtime.Listen.Address
	server.HTTP3 = runtime.Listen.HTTP3
	server.HAproxyV2 = runtime.Listen.HAproxyV2
	server.TLS = runtime.Listen.TLS
	server.TrustedProxies = append([]string(nil), runtime.Listen.TrustedProxies...)
	server.DisabledEndpoints = runtime.HTTP.DisabledEndpoints
	server.Middlewares = runtime.HTTP.Middlewares
	server.Compression = runtime.HTTP.Compression
	server.KeepAlive = runtime.HTTP.KeepAlive
	server.RateLimitPerSecond = runtime.HTTP.RateLimit.PerSecond
	server.RateLimitBurst = runtime.HTTP.RateLimit.Burst
	server.Timeouts = runtime.HTTP.Timeouts
	server.CORS = runtime.HTTP.CORS
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

	return &BackendServerMonitoring{
		BackendServers: append([]*BackendServer(nil), f.Auth.Services.BackendHealthChecks.Targets...),
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
		Learning:                   append([]*Feature(nil), wire.Learning...),
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
		luaSection.Controls = nil
		luaSection.Filters = nil
		luaSection.Hooks = nil

		if f.Auth.Controls.Lua != nil {
			luaSection.Actions = append([]LuaAction(nil), f.Auth.Controls.Lua.Actions...)
			luaSection.Controls = append([]LuaFeature(nil), f.Auth.Controls.Lua.Controls...)
			luaSection.Filters = append([]LuaFilter(nil), f.Auth.Controls.Lua.Filters...)
			luaSection.Hooks = append([]LuaHooks(nil), f.Auth.Controls.Lua.Hooks...)
		}

		luaSection.normalizeConfiguredFeatures()

		luaSection.Config = f.Auth.Backends.Lua.Backend.Default
		luaSection.OptionalLuaBackends = f.Auth.Backends.Lua.Backend.NamedBackends
		luaSection.Search = append([]LuaSearchProtocol(nil), f.Auth.Backends.Lua.Backend.Search...)
	}

	if luaSection.Config == nil && len(luaSection.Actions) == 0 && len(luaSection.Controls) == 0 &&
		len(luaSection.Filters) == 0 && len(luaSection.Hooks) == 0 && len(luaSection.Search) == 0 &&
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
