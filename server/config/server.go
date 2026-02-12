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

package config

import (
	"strings"
	"time"
	"unicode"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/go-playground/validator/v10"
)

// ServerSection represents the configuration for a server, including network settings, TLS, logging, backends, features,
// protocol handling, and integrations with other systems such as Redis and Prometheus.
type ServerSection struct {
	Address                   string                   `mapstructure:"address" validate:"omitempty,tcp_addr"`
	MaxConcurrentRequests     int32                    `mapstructure:"max_concurrent_requests" validate:"omitempty,gte=1"`
	MaxPasswordHistoryEntries int32                    `mapstructure:"max_password_history_entries" validate:"omitempty,gte=1"`
	HTTP3                     bool                     `mapstructure:"http3"`
	HAproxyV2                 bool                     `mapstructure:"haproxy_v2"`
	SMTPBackendAddress        string                   `mapstructure:"smtp_backend_address" validate:"omitempty,hostname_rfc1123"`
	SMTPBackendPort           int                      `mapstructure:"smtp_backend_port" validate:"omitempty,gte=1,lte=65535"`
	IMAPBackendAddress        string                   `mapstructure:"imap_backend_address" validate:"omitempty,hostname_rfc1123"`
	IMAPBackendPort           int                      `mapstructure:"imap_backend_port" validate:"omitempty,gte=1,lte=65535"`
	POP3BackendAddress        string                   `mapstructure:"pop3_backend_address" validate:"omitempty,hostname_rfc1123"`
	POP3BackendPort           int                      `mapstructure:"pop3_backend_port" validate:"omitempty,gte=1,lte=65535"`
	NginxWaitDelay            uint8                    `mapstructure:"nginx_wait_delay" validate:"omitempty"`
	MaxLoginAttempts          uint8                    `mapstructure:"max_login_attempts" validate:"omitempty"`
	LuaScriptTimeout          time.Duration            `mapstructure:"lua_script_timeout" validate:"omitempty"`
	LocalCacheAuthTTL         time.Duration            `mapstructure:"local_cache_auth_ttl" validate:"omitempty"`
	RateLimitPerSecond        float64                  `mapstructure:"rate_limit_per_second" validate:"omitempty,min=0"`
	RateLimitBurst            int                      `mapstructure:"rate_limit_burst" validate:"omitempty,min=0"`
	DisabledEndpoints         Endpoint                 `mapstructure:"disabled_endpoints" validate:"omitempty"`
	TLS                       TLS                      `mapstructure:"tls" validate:"omitempty"`
	BasicAuth                 BasicAuth                `mapstructure:"basic_auth" validate:"omitempty"`
	OIDCAuth                  OIDCAuth                 `mapstructure:"oidc_auth" validate:"omitempty"`
	InstanceName              string                   `mapstructure:"instance_name" validate:"omitempty,max=255,printascii"`
	Log                       Log                      `mapstructure:"log" validate:"omitempty"`
	Backends                  []*Backend               `mapstructure:"backends" validate:"omitempty,dive"`
	Features                  []*Feature               `mapstructure:"features" validate:"omitempty,dive"`
	BruteForceProtocols       []*Protocol              `mapstructure:"brute_force_protocols" validate:"omitempty,dive"`
	DNS                       DNS                      `mapstructure:"dns" validate:"omitempty"`
	Insights                  Insights                 `mapstructure:"insights" validate:"omitempty"`
	Redis                     Redis                    `mapstructure:"redis" validate:"required"`
	MasterUser                MasterUser               `mapstructure:"master_user" validate:"omitempty"`
	Frontend                  Frontend                 `mapstructure:"frontend" validate:"omitempty"`
	Dedup                     Dedup                    `mapstructure:"dedup" validate:"omitempty"`
	PrometheusTimer           PrometheusTimer          `mapstructure:"prometheus_timer" validate:"omitempty"`
	DefaultHTTPRequestHeader  DefaultHTTPRequestHeader `mapstructure:"default_http_request_header" validate:"omitempty"`
	HTTPClient                HTTPClient               `mapstructure:"http_client" validate:"omitempty"`
	Compression               Compression              `mapstructure:"compression" validate:"omitempty"`
	KeepAlive                 KeepAlive                `mapstructure:"keep_alive" validate:"omitempty"`
	// Middlewares holds feature switches to enable/disable individual HTTP middlewares.
	// By default, all middlewares are considered enabled if not explicitly disabled in the config file.
	Middlewares Middlewares `mapstructure:"middlewares" validate:"omitempty"`
	Timeouts    Timeouts    `mapstructure:"timeouts" validate:"omitempty"`

	TrustedProxies []string `mapstructure:"trusted_proxies" validate:"omitempty,dive,ip|cidr"`
}

// Middlewares defines switches for enabling/disabling individual HTTP middlewares.
// All switches default to true when omitted in configuration to preserve legacy behavior.
type Middlewares struct {
	Logging              *bool `mapstructure:"logging" validate:"omitempty"`
	Limit                *bool `mapstructure:"limit" validate:"omitempty"`
	Recovery             *bool `mapstructure:"recovery" validate:"omitempty"`
	TrustedProxies       *bool `mapstructure:"trusted_proxies" validate:"omitempty"`
	RequestDecompression *bool `mapstructure:"request_decompression" validate:"omitempty"`
	ResponseCompression  *bool `mapstructure:"response_compression" validate:"omitempty"`
	Metrics              *bool `mapstructure:"metrics" validate:"omitempty"`
	Rate                 *bool `mapstructure:"rate" validate:"omitempty"`
}

// GetMiddlewares returns the middlewares section or a zero-value if nil.
func (s *ServerSection) GetMiddlewares() *Middlewares {
	if s == nil {
		return &Middlewares{}
	}

	return &s.Middlewares
}

func boolOrDefaultTrue(v *bool) bool {
	if v == nil {
		return true
	}

	return *v
}

func (m *Middlewares) IsLoggingEnabled() bool        { return boolOrDefaultTrue(m.Logging) }
func (m *Middlewares) IsLimitEnabled() bool          { return boolOrDefaultTrue(m.Limit) }
func (m *Middlewares) IsRecoveryEnabled() bool       { return boolOrDefaultTrue(m.Recovery) }
func (m *Middlewares) IsTrustedProxiesEnabled() bool { return boolOrDefaultTrue(m.TrustedProxies) }
func (m *Middlewares) IsRequestDecompressionEnabled() bool {
	return boolOrDefaultTrue(m.RequestDecompression)
}

func (m *Middlewares) IsResponseCompressionEnabled() bool {
	return boolOrDefaultTrue(m.ResponseCompression)
}

func (m *Middlewares) IsMetricsEnabled() bool { return boolOrDefaultTrue(m.Metrics) }
func (m *Middlewares) IsRateEnabled() bool    { return boolOrDefaultTrue(m.Rate) }

// GetListenAddress retrieves the server's listen address from the ServerSection configuration.
// Returns an empty string if the ServerSection is nil.
func (s *ServerSection) GetListenAddress() string {
	if s == nil {
		return ""
	}

	return s.Address
}

// GetMaxConcurrentRequests retrieves the maximum number of concurrent requests allowed as configured in ServerSection.
// Returns 1000 as a default value if the ServerSection is nil.
func (s *ServerSection) GetMaxConcurrentRequests() int32 {
	if s == nil {
		return 1000
	}

	if s.MaxConcurrentRequests < 1 {
		return 1000
	}

	return s.MaxConcurrentRequests
}

// GetMaxPasswordHistoryEntries retrieves the maximum number of password history entries defined in the ServerSection configuration.
// Returns definitions.MaxPasswordHistoryEntries as a default value if the ServerSection is nil.
func (s *ServerSection) GetMaxPasswordHistoryEntries() int32 {
	if s == nil {
		return definitions.MaxPasswordHistoryEntries
	}

	if s.MaxPasswordHistoryEntries < 1 {
		return definitions.MaxPasswordHistoryEntries
	}

	return s.MaxPasswordHistoryEntries
}

// GetRateLimitPerSecond returns tokens per second for the IP rate limiter.
// Defaults to 100.0 if not configured.
func (s *ServerSection) GetRateLimitPerSecond() float64 {
	if s == nil {
		return 100.0
	}

	if s.RateLimitPerSecond <= 0 {
		return 100.0
	}

	return s.RateLimitPerSecond
}

// GetRateLimitBurst returns burst size for the IP rate limiter.
// Defaults to 200 if not configured.
func (s *ServerSection) GetRateLimitBurst() int {
	if s == nil {
		return 200
	}

	if s.RateLimitBurst <= 0 {
		return 200
	}

	return s.RateLimitBurst
}

// IsHTTP3Enabled checks if HTTP/3 protocol support is enabled in the server configuration and returns the corresponding boolean value.
// Returns false as a default value if the ServerSection is nil.
func (s *ServerSection) IsHTTP3Enabled() bool {
	if s == nil {
		return false
	}

	return s.HTTP3
}

// IsHAproxyProtocolEnabled checks if the HAProxy protocol (version 2) is enabled in the server configuration and returns the result.
// Returns false as a default value if the ServerSection is nil.
func (s *ServerSection) IsHAproxyProtocolEnabled() bool {
	if s == nil {
		return false
	}

	return s.HAproxyV2
}

// GetInstanceName retrieves the instance name defined in the ServerSection configuration.
// Returns definitions.InstanceName as a default value if the ServerSection is nil.
func (s *ServerSection) GetInstanceName() string {
	if s == nil {
		return definitions.InstanceName
	}

	return s.InstanceName
}

// GetSMTPBackendAddress returns the address of the SMTP backend server.
func (s *ServerSection) GetSMTPBackendAddress() string {
	if s == nil {
		return ""
	}

	return s.SMTPBackendAddress
}

// GetSMTPBackendPort returns the port of the SMTP backend server.
func (s *ServerSection) GetSMTPBackendPort() int {
	if s == nil {
		return 0
	}

	return s.SMTPBackendPort
}

// GetIMAPBackendAddress returns the address of the IMAP backend server.
func (s *ServerSection) GetIMAPBackendAddress() string {
	if s == nil {
		return ""
	}

	return s.IMAPBackendAddress
}

// GetIMAPBackendPort returns the port of the IMAP backend server.
func (s *ServerSection) GetIMAPBackendPort() int {
	if s == nil {
		return 0
	}

	return s.IMAPBackendPort
}

// GetPOP3BackendAddress returns the address of the POP3 backend server.
func (s *ServerSection) GetPOP3BackendAddress() string {
	if s == nil {
		return ""
	}

	return s.POP3BackendAddress
}

// GetPOP3BackendPort returns the port of the POP3 backend server.
func (s *ServerSection) GetPOP3BackendPort() int {
	if s == nil {
		return 0
	}

	return s.POP3BackendPort
}

// GetNginxWaitDelay returns the wait delay for Nginx in seconds.
func (s *ServerSection) GetNginxWaitDelay() uint8 {
	if s == nil {
		return 0
	}

	return s.NginxWaitDelay
}

// GetMaxLoginAttempts returns the maximum number of login attempts.
func (s *ServerSection) GetMaxLoginAttempts() uint8 {
	if s == nil {
		return 0
	}

	return s.MaxLoginAttempts
}

// GetLuaScriptTimeout returns the timeout for Lua scripts.
func (s *ServerSection) GetLuaScriptTimeout() time.Duration {
	if s == nil {
		return 0
	}

	return s.LuaScriptTimeout
}

// GetLocalCacheAuthTTL returns the TTL for local cache authentication.
func (s *ServerSection) GetLocalCacheAuthTTL() time.Duration {
	if s == nil {
		return 0
	}

	return s.LocalCacheAuthTTL
}

// GetEndpoint retrieves a pointer to the DisabledEndpoints configuration from the ServerSection instance.
// Returns a new empty Endpoint struct if the ServerSection is nil.
func (s *ServerSection) GetEndpoint() *Endpoint {
	if s == nil {
		return &Endpoint{}
	}

	return &s.DisabledEndpoints
}

// GetBasicAuth retrieves a pointer to the BasicAuth configuration from the ServerSection instance.
// Returns a new empty BasicAuth struct if the ServerSection is nil.
func (s *ServerSection) GetBasicAuth() *BasicAuth {
	if s == nil {
		return &BasicAuth{}
	}

	return &s.BasicAuth
}

// GetOIDCAuth retrieves a pointer to the OIDCAuth configuration from the ServerSection instance.
// Returns a new empty OIDCAuth struct if the ServerSection is nil.
func (s *ServerSection) GetOIDCAuth() *OIDCAuth {
	if s == nil {
		return &OIDCAuth{}
	}

	return &s.OIDCAuth
}

// GetTLS retrieves the TLS configuration from the ServerSection instance.
// Returns a new empty TLS struct if the ServerSection is nil.
func (s *ServerSection) GetTLS() *TLS {
	if s == nil {
		return &TLS{}
	}

	return &s.TLS
}

// GetLog retrieves the logging configuration of the ServerSection instance.
// Returns a new empty Log struct if the ServerSection is nil.
func (s *ServerSection) GetLog() *Log {
	if s == nil {
		return &Log{}
	}

	return &s.Log
}

// GetBackends retrieves the list of backends configured in the ServerSection instance.
// Returns an empty slice if the ServerSection is nil.
func (s *ServerSection) GetBackends() []*Backend {
	if s == nil {
		return []*Backend{}
	}

	return s.Backends
}

// GetFeatures retrieves the list of features configured in the ServerSection instance.
// Returns an empty slice if the ServerSection is nil.
func (s *ServerSection) GetFeatures() []*Feature {
	if s == nil {
		return []*Feature{}
	}

	return s.Features
}

// GetBruteForceProtocols retrieves the list of brute force protection protocols configured in the ServerSection.
// Returns an empty slice if the ServerSection is nil.
func (s *ServerSection) GetBruteForceProtocols() []*Protocol {
	if s == nil {
		return []*Protocol{}
	}

	return s.BruteForceProtocols
}

// GetRedis returns a pointer to the Redis configuration of the ServerSection instance.
// Returns a new empty Redis struct if the ServerSection is nil.
func (s *ServerSection) GetRedis() *Redis {
	if s == nil {
		return &Redis{}
	}

	return &s.Redis
}

// GetMasterUser retrieves a pointer to the MasterUser configuration from the ServerSection instance.
// Returns a new empty MasterUser struct if the ServerSection is nil.
func (s *ServerSection) GetMasterUser() *MasterUser {
	if s == nil {
		return &MasterUser{}
	}

	return &s.MasterUser
}

// GetDNS retrieves the DNS configuration from the ServerSection instance.
// Returns a new empty DNS struct if the ServerSection is nil.
func (s *ServerSection) GetDNS() *DNS {
	if s == nil {
		return &DNS{}
	}

	return &s.DNS
}

// GetInsights retrieves a pointer to the Insights configuration from the ServerSection instance.
// Returns a new empty Insights struct if the ServerSection is nil.
func (s *ServerSection) GetInsights() *Insights {
	if s == nil {
		return &Insights{}
	}

	return &s.Insights
}

// GetHTTPClient retrieves the HTTP client configuration from the ServerSection instance.
// Returns a new empty HTTPClient struct if the ServerSection is nil.
func (s *ServerSection) GetHTTPClient() *HTTPClient {
	if s == nil {
		return &HTTPClient{}
	}

	return &s.HTTPClient
}

// GetPrometheusTimer retrieves a pointer to the PrometheusTimer configuration from the ServerSection instance.
// Returns a new empty PrometheusTimer struct if the ServerSection is nil.
func (s *ServerSection) GetPrometheusTimer() *PrometheusTimer {
	if s == nil {
		return &PrometheusTimer{}
	}

	return &s.PrometheusTimer
}

// GetDefaultHTTPRequestHeader retrieves a pointer to the DefaultHTTPRequestHeader configuration from the ServerSection instance.
// Returns a new empty DefaultHTTPRequestHeader struct if the ServerSection is nil.
func (s *ServerSection) GetDefaultHTTPRequestHeader() *DefaultHTTPRequestHeader {
	if s == nil {
		return &DefaultHTTPRequestHeader{}
	}

	return &s.DefaultHTTPRequestHeader
}

// GetCompression retrieves a pointer to the Compression configuration from the ServerSection instance.
// Returns a new empty Compression struct if the ServerSection is nil.
func (s *ServerSection) GetCompression() *Compression {
	if s == nil {
		return &Compression{}
	}

	return &s.Compression
}

// GetKeepAlive retrieves a pointer to the KeepAlive configuration from the ServerSection instance.
// Returns a new empty KeepAlive struct if the ServerSection is nil.
func (s *ServerSection) GetKeepAlive() *KeepAlive {
	if s == nil {
		return &KeepAlive{}
	}

	return &s.KeepAlive
}

// GetDisabledEndpoints returns the disabled endpoints configuration; never nil.
func (s *ServerSection) GetDisabledEndpoints() *Endpoint {
	if s == nil {
		return &Endpoint{}
	}

	return &s.DisabledEndpoints
}

// GetFrontend retrieves the frontend configuration from the ServerSection.
func (s *ServerSection) GetFrontend() *Frontend {
	if s == nil {
		return &Frontend{}
	}

	return &s.Frontend
}

// Endpoint defines a structure for configuring various types of authentication and custom hooks.
type Endpoint struct {
	AuthHeader    bool `mapstructure:"auth_header"`
	AuthJSON      bool `mapstructure:"auth_json"`
	AuthBasic     bool `mapstructure:"auth_basic"`
	AuthNginx     bool `mapstructure:"auth_nginx"`
	AuthSASLAuthd bool `mapstructure:"auth_saslauthd"`
	AuthJWT       bool `mapstructure:"auth_jwt"`
	CustomHooks   bool `mapstructure:"custom_hooks"`
	Configuration bool `mapstructure:"configuration"`
}

// IsAuthHeaderDisabled checks if header-based authentication is enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsAuthHeaderDisabled() bool {
	if e == nil {
		return false
	}

	return e.AuthHeader
}

// IsAuthJSONDisabled checks if JSON-based authentication is enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsAuthJSONDisabled() bool {
	if e == nil {
		return false
	}

	return e.AuthJSON
}

// IsAuthBasicDisabled checks if Basic authentication is enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsAuthBasicDisabled() bool {
	if e == nil {
		return false
	}

	return e.AuthBasic
}

// IsAuthNginxDisabled checks if Nginx-based authentication is enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsAuthNginxDisabled() bool {
	if e == nil {
		return false
	}

	return e.AuthNginx
}

// IsAuthSASLAuthdDisabled checks if SASL authentication is enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsAuthSASLAuthdDisabled() bool {
	if e == nil {
		return false
	}

	return e.AuthSASLAuthd
}

// IsAuthJWTDisabled checks if JWT authentication is enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsAuthJWTDisabled() bool {
	if e == nil {
		return false
	}

	return e.AuthJWT
}

// IsCustomHooksDisabled checks if custom hooks are enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsCustomHooksDisabled() bool {
	if e == nil {
		return false
	}

	return e.CustomHooks
}

// IsConfigurationDisabled checks if the configuration setting is enabled for the endpoint and returns the corresponding boolean value.
// Returns false if the Endpoint is nil.
func (e *Endpoint) IsConfigurationDisabled() bool {
	if e == nil {
		return false
	}

	return e.Configuration
}

// TLS represents the configuration for enabling TLS and managing certificates.
type TLS struct {
	Enabled              bool     `mapstructure:"enabled"`
	SkipVerify           bool     `mapstructure:"skip_verify"`
	HTTPClientSkipVerify bool     `mapstructure:"http_client_skip_verify"`
	MinTLSVersion        string   `mapstructure:"min_tls_version" validate:"omitempty,oneof=TLS1.2 TLS1.3"`
	Cert                 string   `mapstructure:"cert" validate:"omitempty,file"`
	Key                  string   `mapstructure:"key" validate:"omitempty,file"`
	CAFile               string   `mapstructure:"ca_file" validate:"omitempty,file"`
	CipherSuites         []string `mapstructure:"cipher_suites" validate:"omitempty,dive,alphanumsymbol"`
}

// IsEnabled returns true if TLS is enabled, otherwise false.
// Returns false if the TLS is nil.
func (t *TLS) IsEnabled() bool {
	if t == nil {
		return false
	}

	return t.Enabled
}

// GetCert returns the TLS certificate as a string.
// Returns an empty string if the TLS is nil.
func (t *TLS) GetCert() string {
	if t == nil {
		return ""
	}

	return t.Cert
}

// GetKey returns the TLS key as a string.
// Returns an empty string if the TLS is nil.
func (t *TLS) GetKey() string {
	if t == nil {
		return ""
	}

	return t.Key
}

// GetCAFile returns the CA certificate file path as a string. Returns an empty string if the TLS receiver is nil.
func (t *TLS) GetCAFile() string {
	if t == nil {
		return ""
	}

	return t.CAFile
}

// GetHTTPClientSkipVerify returns the value of the HTTPClientSkipVerify field, indicating whether TLS verification is skipped.
// Returns false if the TLS is nil.
// Deprecated: Use GetSkipVerify() instead
func (t *TLS) GetHTTPClientSkipVerify() bool {
	if t == nil {
		return false
	}

	return t.HTTPClientSkipVerify
}

// GetSkipVerify returns the value of the SkipVerify field, indicating whether TLS certificate verification is skipped.
// Returns false if the TLS receiver is nil.
func (t *TLS) GetSkipVerify() bool {
	if t == nil {
		return false
	}

	return t.SkipVerify
}

// GetCipherSuites returns the list of configured cipher suites as a slice of strings. Returns an empty slice if the TLS is nil.
func (t *TLS) GetCipherSuites() []string {
	if t == nil {
		return []string{}
	}

	return t.CipherSuites
}

// GetMinTLSVersion returns the minimum TLS version configured. Defaults to "TLS1.2" if unset or if the receiver is nil.
func (t *TLS) GetMinTLSVersion() string {
	if t == nil {
		return "TLS1.2"
	}

	if t.MinTLSVersion == "" {
		return "TLS1.2"
	}

	return t.MinTLSVersion
}

type HTTPClient struct {
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host" validate:"omitempty,gte=1"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections" validate:"omitempty,gte=1"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host" validate:"omitempty,gte=0"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout" validate:"omitempty,gte=0"`
	Proxy               string        `mapstructure:"proxy"`
	TLS                 TLS           `mapstructure:"tls"`
}

// GetMaxConnsPerHost returns the maximum number of connections allowed per host for the HTTP client.
// Returns 0 if the HTTPClient is nil.
func (c *HTTPClient) GetMaxConnsPerHost() int {
	if c == nil {
		return 0
	}

	return c.MaxConnsPerHost
}

// GetMaxIdleConns returns the maximum number of idle connections allowed for the HTTP client.
// Returns 0 if the HTTPClient is nil.
func (c *HTTPClient) GetMaxIdleConns() int {
	if c == nil {
		return 0
	}

	return c.MaxIdleConns
}

// GetMaxIdleConnsPerHost returns the maximum number of idle connections allowed per host for the HTTP client.
// Returns 0 if the HTTPClient is nil.
func (c *HTTPClient) GetMaxIdleConnsPerHost() int {
	if c == nil {
		return 0
	}

	return c.MaxIdleConnsPerHost
}

// GetIdleConnTimeout returns the idle connection timeout duration configured for the HTTP client.
// Returns 0 if the HTTPClient is nil.
func (c *HTTPClient) GetIdleConnTimeout() time.Duration {
	if c == nil {
		return 0
	}

	return c.IdleConnTimeout
}

// GetProxy returns the proxy URL configured for the HTTP client.
// Returns an empty string if the HTTPClient is nil.
func (c *HTTPClient) GetProxy() string {
	if c == nil {
		return ""
	}

	return c.Proxy
}

// GetTLS returns the TLS configuration associated with the HTTP client. Returns an empty TLS struct if the receiver is nil.
func (c *HTTPClient) GetTLS() *TLS {
	if c == nil {
		return &TLS{}
	}

	return &c.TLS
}

// BasicAuth represents the configuration for basic HTTP authentication.
type BasicAuth struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password string `mapstructure:"password" validate:"omitempty,min=16,alphanumsymbol,excludesall= "`
}

// IsEnabled returns true if basic HTTP authentication is enabled, otherwise false.
// Returns false if the BasicAuth is nil.
func (b *BasicAuth) IsEnabled() bool {
	if b == nil {
		return false
	}

	return b.Enabled
}

// GetUsername returns the username configured for basic HTTP authentication.
// Returns an empty string if the BasicAuth is nil.
func (b *BasicAuth) GetUsername() string {
	if b == nil {
		return ""
	}

	return b.Username
}

// GetPassword retrieves the password for the BasicAuth configuration.
// Returns an empty string if the BasicAuth is nil.
func (b *BasicAuth) GetPassword() string {
	if b == nil {
		return ""
	}

	return b.Password
}

// OIDCAuth represents the configuration for OIDC Bearer token authentication
// on the backchannel API. When enabled, the OIDC Bearer middleware validates
// tokens issued by the built-in IdP (client_credentials flow) for /api/v1/* routes.
// This is independent of idp.oidc.enabled, which controls whether the IdP itself is active.
type OIDCAuth struct {
	Enabled bool `mapstructure:"enabled"`
}

// IsEnabled returns true if OIDC Bearer authentication is enabled for the backchannel API.
// Returns false if the OIDCAuth is nil.
func (o *OIDCAuth) IsEnabled() bool {
	if o == nil {
		return false
	}

	return o.Enabled
}

// Log represents the configuration for logging.
type Log struct {
	JSON       bool         `mapstructure:"json"`
	Color      bool         `mapstructure:"color"`
	Level      Verbosity    `mapstructure:"level"`
	AddSource  bool         `mapstructure:"add_source"`
	DbgModules []*DbgModule `mapstructure:"debug_modules" validate:"omitempty,dive"`
}

// GetLogLevel returns the name of the current logging level configured in the Log instance.
// Returns 0 if the Log is nil or the Level is nil.
func (l *Log) GetLogLevel() int {
	if l == nil {
		return 0
	}

	return l.Level.Level()
}

// GetLogLevelName returns the name of the current logging level as a string.
// Returns an empty string if the Log is nil or the Level is nil.
func (l *Log) GetLogLevelName() string {
	if l == nil {
		return ""
	}

	return l.Level.Get()
}

// GetDebugModules retrieves the list of debug modules configured in the Log instance.
// Returns an empty slice if the Log is nil.
func (l *Log) GetDebugModules() []*DbgModule {
	if l == nil {
		return []*DbgModule{}
	}

	return l.DbgModules
}

// IsLogFormatJSON indicates whether the log format is set to JSON based on the `JSON` field in the `Log` struct.
// Returns false if the Log is nil.
func (l *Log) IsLogFormatJSON() bool {
	if l == nil {
		return false
	}

	return l.JSON
}

// IsLogUsesColor determines if colored output is enabled for logging.
// Returns false if the Log is nil.
func (l *Log) IsLogUsesColor() bool {
	if l == nil {
		return false
	}

	return l.Color
}

// IsAddSourceEnabled indicates whether slog should add source information (file:line) to log records.
// Returns false if Log is nil; default behavior is configured via config defaults.
func (l *Log) IsAddSourceEnabled() bool {
	if l == nil {
		return false
	}

	return l.AddSource
}

// Insights is a configuration structure for enabling profiling, block profiling, and connection monitoring capabilities.
type Insights struct {
	EnablePprof        bool    `mapstructure:"enable_pprof"`
	EnableBlockProfile bool    `mapstructure:"enable_block_profile"`
	MonitorConnections bool    `mapstructure:"monitor_connections"`
	Tracing            Tracing `mapstructure:"tracing" validate:"omitempty"`
}

// IsPprofEnabled checks if pprof profiling is enabled in the Insights configuration.
// Returns false if the Insights is nil.
func (i *Insights) IsPprofEnabled() bool {
	if i == nil {
		return false
	}

	return i.EnablePprof
}

// IsBlockProfileEnabled checks if block profiling is enabled in the Insights configuration.
// Returns false if the Insights is nil.
func (i *Insights) IsBlockProfileEnabled() bool {
	if i == nil {
		return false
	}

	return i.EnableBlockProfile
}

// IsMonitorConnectionsEnabled returns true if connection monitoring is enabled.
// Returns false if the Insights is nil.
func (i *Insights) IsMonitorConnectionsEnabled() bool {
	if i == nil {
		return false
	}

	return i.MonitorConnections
}

// Tracing holds OpenTelemetry tracing configuration options.
type Tracing struct {
	Enabled      bool     `mapstructure:"enabled"`
	Exporter     string   `mapstructure:"exporter" validate:"omitempty,oneof=otlphttp none"`
	Endpoint     string   `mapstructure:"endpoint" validate:"omitempty"`
	SamplerRatio float64  `mapstructure:"sampler_ratio" validate:"omitempty,gte=0,lte=1"`
	ServiceName  string   `mapstructure:"service_name" validate:"omitempty,max=255,printascii"`
	Propagators  []string `mapstructure:"propagators" validate:"omitempty,dive,oneof=tracecontext baggage b3 b3multi jaeger"`
	EnableRedis  bool     `mapstructure:"enable_redis"`
	TLS          TLS      `mapstructure:"tls" validate:"omitempty"`
	// LogExportResults toggles INFO-level logging for successful trace export batches.
	// When true, the exporter logs an INFO message for each successful batch export.
	// Default is false to avoid noisy logs.
	LogExportResults bool `mapstructure:"log_export_results"`
}

// GetTracing returns the tracing configuration; returns an empty struct if Insights is nil.
func (i *Insights) GetTracing() *Tracing {
	if i == nil {
		return &Tracing{}
	}

	return &i.Tracing
}

// IsTracingEnabled returns true if tracing is enabled in the Insights configuration.
func (i *Insights) IsTracingEnabled() bool {
	if i == nil {
		return false
	}

	return i.Tracing.Enabled
}

// Tracing getters to ensure consistent access across the codebase

// IsEnabled returns true if tracing is enabled, otherwise false; returns false if the Tracing receiver is nil.
func (t *Tracing) IsEnabled() bool {
	if t == nil {
		return false
	}

	return t.Enabled
}

// GetExporter returns the configured tracing exporter as a string. Returns an empty string if the Tracing receiver is nil.
func (t *Tracing) GetExporter() string {
	if t == nil {
		return ""
	}

	return t.Exporter
}

// GetEndpoint returns the tracing endpoint as a string. Returns an empty string if the Tracing instance is nil.
func (t *Tracing) GetEndpoint() string {
	if t == nil {
		return ""
	}

	return t.Endpoint
}

// GetSamplerRatio returns the configured sampler ratio for tracing as a float64. Defaults to 0 if the Tracing receiver is nil.
func (t *Tracing) GetSamplerRatio() float64 {
	if t == nil {
		return 0
	}

	return t.SamplerRatio
}

// GetServiceName returns the configured service name for tracing as a string. Returns an empty string if the receiver is nil.
func (t *Tracing) GetServiceName() string {
	if t == nil {
		return ""
	}

	return t.ServiceName
}

// GetPropagators returns the list of configured text map propagators for tracing. Returns nil if the receiver is nil.
func (t *Tracing) GetPropagators() []string {
	if t == nil {
		return nil
	}

	return t.Propagators
}

// IsRedisEnabled returns true if Redis tracing is enabled; returns false if the Tracing receiver is nil.
func (t *Tracing) IsRedisEnabled() bool {
	if t == nil {
		return false
	}

	return t.EnableRedis
}

// GetTLS returns the TLS configuration pointer. If the Tracing receiver is nil, it returns a pointer to an empty TLS instance.
func (t *Tracing) GetTLS() *TLS {
	if t == nil {
		return &TLS{}
	}

	return &t.TLS
}

// IsLogExportResultsEnabled returns true if successful trace export batches should be logged at INFO level.
// Returns false if the Tracing receiver is nil.
func (t *Tracing) IsLogExportResultsEnabled() bool {
	if t == nil {
		return false
	}

	return t.LogExportResults
}

// DNS represents the Domain Name System configuration settings, including resolver, timeout, and client IP resolution options.
type DNS struct {
	Resolver        string        `mapstructure:"resolver" validate:"omitempty,tcp_addr"`
	Timeout         time.Duration `mapstructure:"timeout" validate:"omitempty,gt=0,max=30s"`
	ResolveClientIP bool          `mapstructure:"resolve_client_ip"`
}

// GetResolver returns the configured DNS resolver address as a string.
// Returns an empty string if the DNS is nil.
func (d *DNS) GetResolver() string {
	if d == nil {
		return ""
	}

	return d.Resolver
}

// GetTimeout returns the timeout duration configured for the DNS resolver.
// Returns 0 if the DNS is nil.
func (d *DNS) GetTimeout() time.Duration {
	if d == nil {
		return 0
	}

	return d.Timeout
}

// GetResolveClientIP returns the value of the ResolveClientIP field indicating whether client IP resolution is enabled.
// Returns false if the DNS is nil.
func (d *DNS) GetResolveClientIP() bool {
	if d == nil {
		return false
	}

	return d.ResolveClientIP
}

// Redis represents the configuration settings for a Redis instance, including master, replica, sentinel, and cluster setups.
type Redis struct {
	DatabaseNmuber   int           `mapstructure:"database_number" validate:"omitempty,gte=0,lte=15"`
	Prefix           string        `mapstructure:"prefix" validate:"omitempty,printascii,excludesall= "`
	PasswordNonce    string        `mapstructure:"password_nonce" validate:"required,min=16,alphanumsymbol,excludesall= "`
	EncryptionSecret string        `mapstructure:"encryption_secret" validate:"required,min=16,alphanumsymbol,excludesall= "`
	PoolSize         int           `mapstructure:"pool_size" validate:"omitempty,gte=1"`
	IdlePoolSize     int           `mapstructure:"idle_pool_size" validate:"omitempty,gte=0"`
	TLS              TLS           `mapstructure:"tls" validate:"omitempty"`
	PosCacheTTL      time.Duration `mapstructure:"positive_cache_ttl" validate:"omitempty,max=8760h"`
	NegCacheTTL      time.Duration `mapstructure:"negative_cache_ttl" validate:"omitempty,max=8760h"`
	Master           Master        `mapstructure:"master" validate:"omitempty"`
	Replica          Replica       `mapstructure:"replica" validate:"omitempty"`
	Sentinels        Sentinels     `mapstructure:"sentinels" validate:"omitempty"`
	Cluster          Cluster       `mapstructure:"cluster" validate:"omitempty"`

	// Connection/timeout tuning; defaults mirror previous hard-coded values
	// Sensible bounds via validator tags to avoid extreme misconfiguration
	// PoolTimeout: time to wait for a free connection from the pool (1ms–30s)
	PoolTimeout *time.Duration `mapstructure:"pool_timeout" validate:"omitempty,min=1ms,max=30s"`
	// DialTimeout: TCP connect timeout (1ms–60s)
	DialTimeout *time.Duration `mapstructure:"dial_timeout" validate:"omitempty,min=1ms,max=60s"`
	// ReadTimeout: per-read operation timeout (1ms–60s)
	ReadTimeout *time.Duration `mapstructure:"read_timeout" validate:"omitempty,min=1ms,max=60s"`
	// WriteTimeout: per-write operation timeout (1ms–60s)
	WriteTimeout *time.Duration `mapstructure:"write_timeout" validate:"omitempty,min=1ms,max=60s"`
	PoolFIFO     *bool          `mapstructure:"pool_fifo" validate:"omitempty"`
	// ConnMaxIdleTime: maximum time a connection may remain idle before being closed (0s–24h)
	ConnMaxIdleTime *time.Duration `mapstructure:"conn_max_idle_time" validate:"omitempty,min=0s,max=24h"`
	MaxRetries      *int           `mapstructure:"max_retries" validate:"omitempty,gte=0"`

	// AccountLocalCache allows configuring an in-process cache for username->account mapping
	AccountLocalCache AccountLocalCache `mapstructure:"account_local_cache" validate:"omitempty"`

	// Batching config: optional client-side command batching to reduce Redis round-trips
	Batching RedisBatching `mapstructure:"batching" validate:"omitempty"`

	// ClientTracking enables optional Redis client-side caching (RESP3 tracking).
	// When enabled, the Redis client issues `CLIENT TRACKING ON` on each new
	// connection with the configured flags. This can reduce read RTTs by
	// serving cached values and receiving invalidation push messages from Redis.
	ClientTracking RedisClientTracking `mapstructure:"client_tracking" validate:"omitempty"`

	// IdentityEnabled toggles whether the client should issue CLIENT SETINFO on connect.
	// Defaults to false for maximum compatibility with older Redis or proxies.
	IdentityEnabled bool `mapstructure:"identity_enabled"`

	// MaintNotificationsEnabled toggles CLIENT MAINT_NOTIFICATIONS support (RESP3 push based).
	// Only applicable to standalone and cluster clients. Defaults to false for compatibility.
	MaintNotificationsEnabled bool `mapstructure:"maint_notifications_enabled"`

	// Protocol sets the Redis protocol version (2 or 3). If not set (0), it defaults to 2
	// unless features requiring RESP3 (like client-side tracking or maintenance notifications)
	// are enabled. Forcing 2 can resolve parsing issues with asynchronous push messages in pipelines.
	Protocol int `mapstructure:"protocol" validate:"omitempty,oneof=0 2 3"`
}

// RedisBatching controls optional client-side command batching.
// When enabled, individual commands issued by the application are queued briefly
// and flushed as a single Redis pipeline based on size/time thresholds.
// This can significantly reduce network round-trips under high concurrency.
type RedisBatching struct {
	// Enabled toggles the batching hook.
	Enabled bool `mapstructure:"enabled"`

	// MaxBatchSize defines how many commands are flushed at most in a single pipeline.
	// Defaults to 16. Safe range enforced via validation in getters.
	MaxBatchSize int `mapstructure:"max_batch_size" validate:"omitempty,gte=2,lte=1024"`

	// MaxWait defines the maximum time a command may wait in the queue before we force a flush.
	// Defaults to 2ms. Allowed range 0–200ms (0 disables the timer; only size-based flushing).
	MaxWait time.Duration `mapstructure:"max_wait" validate:"omitempty,min=0s,max=200ms"`

	// QueueCapacity bounds the internal queue. When full, commands bypass batching and execute immediately.
	// Defaults to 8192. 0 means unbuffered (effectively disables batching under load).
	QueueCapacity int `mapstructure:"queue_capacity" validate:"omitempty,gte=0,lte=100000"`

	// SkipCommands lists command names that must not be batched (lowercase, e.g. "blpop").
	// Useful to exclude blocking commands or PubSub.
	SkipCommands []string `mapstructure:"skip_commands" validate:"omitempty,dive,printascii"`

	// PipelineTimeout specifies the maximum time to wait for a pipeline batch to send, with valid range 0s to 10s.
	PipelineTimeout time.Duration `mapstructure:"pipeline_timeout" validate:"omitempty,min=0s,max=10s"`
}

// AccountLocalCache config for the in-process username->account cache
type AccountLocalCache struct {
	Enabled  bool          `mapstructure:"enabled"`
	TTL      time.Duration `mapstructure:"ttl" validate:"omitempty,min=0s,max=24h"`
	Shards   int           `mapstructure:"shards" validate:"omitempty,gte=1,lte=1024"`
	CleanUp  time.Duration `mapstructure:"cleanup_interval" validate:"omitempty,min=0s,max=1h"`
	MaxItems int           `mapstructure:"max_items" validate:"omitempty,gte=0"`
}

// RedisClientTracking config controls Redis client-side caching (CLIENT TRACKING)
// Requires Redis 6+ and RESP3. Use with care in environments where push
// notifications are allowed and network is stable.
type RedisClientTracking struct {
	// Enabled toggles client-side tracking.
	Enabled bool `mapstructure:"enabled"`

	// BCast enables broadcast mode (TRACKING BCAST) to receive invalidations
	// for all keys that are touched by this connection without per-key tracking.
	BCast bool `mapstructure:"bcast"`

	// NoLoop prevents this client from receiving invalidations for writes that
	// originated from the same connection.
	NoLoop bool `mapstructure:"noloop"`

	// OptIn requires explicit CACHING yes on commands to be tracked.
	OptIn bool `mapstructure:"opt_in"`

	// OptOut tracks all commands unless CACHING no is provided.
	OptOut bool `mapstructure:"opt_out"`

	// Prefixes restrict tracking to specific key prefixes. Empty means no restriction.
	Prefixes []string `mapstructure:"prefixes" validate:"omitempty,dive,printascii"`
}

// GetDatabaseNumber retrieves the configured database number for the Redis instance.
// Returns 0 if the Redis is nil.
func (r *Redis) GetDatabaseNumber() int {
	if r == nil {
		return 0
	}

	return r.DatabaseNmuber
}

// GetPrefix retrieves the prefix associated with the Redis instance configuration.
// Returns an empty string if the Redis is nil.
func (r *Redis) GetPrefix() string {
	if r == nil {
		return ""
	}

	if r.Prefix == "" {
		return "nt:"
	}

	return r.Prefix
}

// GetPasswordNonce retrieves the password nonce configured for the Redis instance.
// Returns an empty string if the Redis is nil.
func (r *Redis) GetPasswordNonce() string {
	if r == nil {
		return ""
	}

	return r.PasswordNonce
}

// GetEncryptionSecret returns the encryption secret for Redis.
func (r *Redis) GetEncryptionSecret() string {
	if r == nil {
		return ""
	}

	return r.EncryptionSecret
}

// GetPoolSize retrieves the size of the connection pool configured for the Redis instance.
// Returns 0 if the Redis is nil.
func (r *Redis) GetPoolSize() int {
	if r == nil {
		return 0
	}

	return r.PoolSize
}

// IsIdentityEnabled returns true if CLIENT SETINFO should be sent on connect.
// Defaults to false when Redis config is nil.
func (r *Redis) IsIdentityEnabled() bool {
	if r == nil {
		return false
	}

	return r.IdentityEnabled
}

// IsMaintNotificationsEnabled returns true if CLIENT MAINT_NOTIFICATIONS should be enabled (where supported).
// Defaults to false when Redis config is nil.
func (r *Redis) IsMaintNotificationsEnabled() bool {
	if r == nil {
		return false
	}

	return r.MaintNotificationsEnabled
}

// GetBatching returns a pointer to the RedisBatching config; never nil.
func (r *Redis) GetBatching() *RedisBatching {
	if r == nil {
		return &RedisBatching{}
	}

	return &r.Batching
}

// IsBatchingEnabled returns true if the batching hook is enabled.
func (b *RedisBatching) IsBatchingEnabled() bool {
	if b == nil {
		return false
	}

	return b.Enabled
}

// GetMaxBatchSize returns the max batch size with a safe default.
func (b *RedisBatching) GetMaxBatchSize() int {
	if b == nil || b.MaxBatchSize <= 0 {
		return 16
	}

	if b.MaxBatchSize < 2 {
		return 2
	}
	if b.MaxBatchSize > 1024 {
		return 1024
	}

	return b.MaxBatchSize
}

// GetMaxWait returns the max wait duration with a safe default and cap.
func (b *RedisBatching) GetMaxWait() time.Duration {
	if b == nil {
		return 2 * time.Millisecond
	}

	if b.MaxWait < 0 {
		return 0
	}

	if b.MaxWait == 0 {
		return 2 * time.Millisecond
	}

	if b.MaxWait > 200*time.Millisecond {
		return 200 * time.Millisecond
	}

	return b.MaxWait
}

// GetQueueCapacity returns the internal queue capacity with a default.
func (b *RedisBatching) GetQueueCapacity() int {
	if b == nil || b.QueueCapacity < 0 {
		return 8192
	}

	if b.QueueCapacity == 0 {
		return 8192
	}

	if b.QueueCapacity > 100000 {
		return 100000
	}

	return b.QueueCapacity
}

// GetSkipCommands returns the list of commands to skip (lowercased), may be empty.
func (b *RedisBatching) GetSkipCommands() []string {
	if b == nil || len(b.SkipCommands) == 0 {
		return nil
	}

	// Normalize to lowercase to simplify matching.
	out := make([]string, 0, len(b.SkipCommands))
	for _, s := range b.SkipCommands {
		out = append(out, strings.ToLower(s))
	}

	return out
}

// GetPipelineTimeout returns the pipeline timeout duration with a default fallback value of 5 seconds.
func (b *RedisBatching) GetPipelineTimeout() time.Duration {
	if b == nil {
		return 5 * time.Second
	}

	if b.PipelineTimeout <= 0 {
		return 5 * time.Second
	}

	return b.PipelineTimeout
}

// GetIdlePoolSize retrieves the number of idle connections allowed in the connection pool.
// Returns 0 if the Redis is nil.
func (r *Redis) GetIdlePoolSize() int {
	if r == nil {
		return 0
	}

	return r.IdlePoolSize
}

// GetTLS returns a pointer to the TLS configuration of the Redis instance.
// Returns a new empty TLS struct if the Redis is nil.
func (r *Redis) GetTLS() *TLS {
	if r == nil {
		return &TLS{}
	}

	return &r.TLS
}

// GetPosCacheTTL retrieves the positive cache time-to-live (TTL) duration configured for the Redis instance.
// Returns 0 if the Redis is nil.
func (r *Redis) GetPosCacheTTL() time.Duration {
	if r == nil {
		return 0
	}

	return r.PosCacheTTL
}

// GetNegCacheTTL retrieves the negative cache time-to-live (TTL) duration configured for the Redis instance.
// Returns 0 if the Redis is nil.
func (r *Redis) GetNegCacheTTL() time.Duration {
	if r == nil {
		return 0
	}

	return r.NegCacheTTL
}

// GetProtocol returns the configured Redis protocol or 2 if not set.
func (r *Redis) GetProtocol() int {
	if r == nil {
		return 2
	}

	return r.Protocol
}

// GetPoolTimeout returns the configured pool timeout or the default of 1s.
func (r *Redis) GetPoolTimeout() time.Duration {
	if r == nil || r.PoolTimeout == nil {
		return 1 * time.Second
	}

	return *r.PoolTimeout
}

// GetDialTimeout returns the configured dial timeout or the default of 5s.
func (r *Redis) GetDialTimeout() time.Duration {
	if r == nil || r.DialTimeout == nil {
		return 5 * time.Second
	}

	return *r.DialTimeout
}

// GetReadTimeout returns the configured read timeout or the default of 1s.
func (r *Redis) GetReadTimeout() time.Duration {
	if r == nil || r.ReadTimeout == nil {
		return 1 * time.Second
	}

	return *r.ReadTimeout
}

// GetWriteTimeout returns the configured write timeout or the default of 1s.
func (r *Redis) GetWriteTimeout() time.Duration {
	if r == nil || r.WriteTimeout == nil {
		return 1 * time.Second
	}

	return *r.WriteTimeout
}

// GetPoolFIFO returns whether FIFO should be used in the connection pool. Defaults to true.
func (r *Redis) GetPoolFIFO() bool {
	if r == nil || r.PoolFIFO == nil {
		return true
	}

	return *r.PoolFIFO
}

// GetConnMaxIdleTime returns the maximum idle time for a connection or the default of 90s.
func (r *Redis) GetConnMaxIdleTime() time.Duration {
	if r == nil || r.ConnMaxIdleTime == nil {
		return 90 * time.Second
	}

	return *r.ConnMaxIdleTime
}

// GetMaxRetries returns the maximum retry count or the default of 1.
func (r *Redis) GetMaxRetries() int {
	if r == nil || r.MaxRetries == nil {
		return 1
	}

	return *r.MaxRetries
}

// GetAccountLocalCache returns pointer to account local cache config
func (r *Redis) GetAccountLocalCache() *AccountLocalCache {
	if r == nil {
		return &AccountLocalCache{}
	}

	return &r.AccountLocalCache
}

func (a *AccountLocalCache) IsEnabled() bool {
	if a == nil {
		return false
	}

	return a.Enabled
}

func (a *AccountLocalCache) GetTTL() time.Duration {
	if a == nil || a.TTL <= 0 {
		return 60 * time.Second
	}

	return a.TTL
}

func (a *AccountLocalCache) GetShards() int {
	if a == nil || a.Shards <= 0 {
		return 32
	}

	return a.Shards
}

func (a *AccountLocalCache) GetCleanupInterval() time.Duration {
	if a == nil || a.CleanUp <= 0 {
		return 10 * time.Minute
	}

	return a.CleanUp
}

func (a *AccountLocalCache) GetMaxItems() int {
	if a == nil || a.MaxItems < 0 {
		return 0
	}

	return a.MaxItems
}

// GetClientTracking returns a pointer to the client tracking config; never nil.
func (r *Redis) GetClientTracking() *RedisClientTracking {
	if r == nil {
		return &RedisClientTracking{}
	}

	return &r.ClientTracking
}

// IsEnabled returns true if client-side tracking is enabled.
func (c *RedisClientTracking) IsEnabled() bool {
	if c == nil {
		return false
	}

	return c.Enabled
}

// IsBCast returns true if broadcast mode should be used.
func (c *RedisClientTracking) IsBCast() bool {
	if c == nil {
		return false
	}

	return c.BCast
}

// IsNoLoop returns true if NOLOOP is enabled.
func (c *RedisClientTracking) IsNoLoop() bool {
	if c == nil {
		return false
	}

	return c.NoLoop
}

// IsOptIn returns true if OPTIN is enabled.
func (c *RedisClientTracking) IsOptIn() bool {
	if c == nil {
		return false
	}

	return c.OptIn
}

// IsOptOut returns true if OPTOUT is enabled.
func (c *RedisClientTracking) IsOptOut() bool {
	if c == nil {
		return false
	}

	return c.OptOut
}

// GetPrefixes returns configured prefixes for CLIENT TRACKING PREFIX.
func (c *RedisClientTracking) GetPrefixes() []string {
	if c == nil {
		return nil
	}

	return c.Prefixes
}

// GetStandaloneMaster returns a pointer to the Master configuration of the Redis instance.
// Returns an empty Master struct if the Redis is nil.
func (r *Redis) GetStandaloneMaster() Master {
	if r == nil {
		return Master{}
	}

	return r.Master
}

// GetStandaloneReplica returns a pointer to the Replica configuration of the Redis instance.
// Returns an empty Replica struct if the Redis is nil.
func (r *Redis) GetStandaloneReplica() Replica {
	if r == nil {
		return Replica{}
	}

	return r.Replica
}

// GetSentinel returns a pointer to the Sentinels configuration of the Redis instance.
// Returns a new empty Sentinels struct if the Redis is nil.
func (r *Redis) GetSentinel() *Sentinels {
	if r == nil {
		return &Sentinels{}
	}

	return &r.Sentinels
}

// GetCluster returns a pointer to the Cluster configuration of the Redis instance.
// Returns a new empty Cluster struct if the Redis is nil.
func (r *Redis) GetCluster() *Cluster {
	if r == nil {
		return &Cluster{}
	}

	return &r.Cluster
}

// Master represents the configuration for the master Redis instance.
// Includes fields for address, username, and password for the master instance.
type Master struct {
	Address  string `mapstructure:"address" validate:"omitempty,hostname_port"`
	Username string `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password string `mapstructure:"password" validate:"omitempty,excludesall= "`
}

// GetAddress returns the address of the master Redis instance stored in the Master struct.
func (m Master) GetAddress() string {
	return m.Address
}

// GetUsername returns the username of the master Redis instance stored in the Master struct.
func (m Master) GetUsername() string {
	return m.Username
}

// GetPassword returns the password of the master Redis instance stored in the Master struct.
func (m Master) GetPassword() string {
	return m.Password
}

// Replica represents the configuration for a Redis replica instance.
type Replica struct {
	Address   string   `mapstructure:"address" validate:"omitempty,hostname_port"`
	Addresses []string `mapstructure:"addresses" validate:"omitempty,dive,hostname_port"`
}

// GetAddress returns the address of the Redis replica instance as a string.
// Deprecated: Use GetAddresses() instead for retrieving all replica addresses
func (r Replica) GetAddress() string {
	return r.Address
}

// GetAddresses retrieves the list of addresses associated with the Redis replica instance.
func (r Replica) GetAddresses() []string {
	return r.Addresses
}

// Sentinels represents the configuration for Redis Sentinel.
type Sentinels struct {
	Master    string   `mapstructure:"master" validate:"required,printascii,excludesall= "`
	Addresses []string `mapstructure:"addresses" validate:"required,dive,hostname_port"`
	Username  string   `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password  string   `mapstructure:"password" validate:"omitempty,excludesall= "`
}

// GetMasterName returns the name of the master Redis instance configured in the Sentinels struct.
// Returns an empty string if the Sentinels is nil.
func (s *Sentinels) GetMasterName() string {
	if s == nil {
		return ""
	}

	return s.Master
}

// GetAddresses returns the list of addresses for the Redis Sentinel configuration.
// Returns an empty slice if the Sentinels is nil.
func (s *Sentinels) GetAddresses() []string {
	if s == nil {
		return []string{}
	}

	return s.Addresses
}

// GetUsername retrieves the username configured for the Redis Sentinel connection.
// Returns an empty string if the Sentinels is nil.
func (s *Sentinels) GetUsername() string {
	if s == nil {
		return ""
	}

	return s.Username
}

// GetPassword retrieves the password configured for the Redis Sentinel connection.
// Returns an empty string if the Sentinels is nil.
func (s *Sentinels) GetPassword() string {
	if s == nil {
		return ""
	}

	return s.Password
}

// Cluster represents the configuration for a Redis cluster setup.
type Cluster struct {
	Addresses            []string      `mapstructure:"addresses" validate:"required,dive,hostname_port"`
	Username             string        `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password             string        `mapstructure:"password" validate:"omitempty,excludesall= "`
	RouteByLatency       bool          `mapstructure:"route_by_latency"`
	RouteRandomly        bool          `mapstructure:"route_randomly"`
	ReadOnly             bool          `mapstructure:"read_only"` // Deprecated: Use RouteReadsToReplicas instead
	RouteReadsToReplicas bool          `mapstructure:"route_reads_to_replicas"`
	MaxRedirects         int           `mapstructure:"max_redirects" validate:"omitempty,gte=0"`
	ReadTimeout          time.Duration `mapstructure:"read_timeout" validate:"omitempty"`
	WriteTimeout         time.Duration `mapstructure:"write_timeout" validate:"omitempty"`
}

// GetAddresses retrieves the list of Redis cluster addresses configured in the Cluster instance.
// Returns an empty slice if the Cluster is nil.
func (c *Cluster) GetAddresses() []string {
	if c == nil {
		return []string{}
	}

	return c.Addresses
}

// GetUsername retrieves the username configured for the Redis cluster.
// Returns an empty string if the Cluster is nil.
func (c *Cluster) GetUsername() string {
	if c == nil {
		return ""
	}

	return c.Username
}

// GetPassword retrieves the password configured for the Redis cluster.
// Returns an empty string if the Cluster is nil.
func (c *Cluster) GetPassword() string {
	if c == nil {
		return ""
	}

	return c.Password
}

// GetRouteByLatency returns whether commands should be routed to the closest node.
// Returns false if the Cluster is nil.
func (c *Cluster) GetRouteByLatency() bool {
	if c == nil {
		return false
	}

	return c.RouteByLatency
}

// GetRouteRandomly returns whether commands should be routed randomly across nodes.
// Returns false if the Cluster is nil.
func (c *Cluster) GetRouteRandomly() bool {
	if c == nil {
		return false
	}

	return c.RouteRandomly
}

// GetReadOnly returns whether read-only commands should be allowed from replicas.
// Returns false if the Cluster is nil.
// Deprecated: Use GetRouteReadsToReplicas instead.
func (c *Cluster) GetReadOnly() bool {
	if c == nil {
		return false
	}

	// For backward compatibility, check both parameters
	return c.ReadOnly || c.RouteReadsToReplicas
}

// GetRouteReadsToReplicas returns whether read commands should be routed to replica nodes.
// Returns false if the Cluster is nil.
func (c *Cluster) GetRouteReadsToReplicas() bool {
	if c == nil {
		return false
	}

	// For backward compatibility, check both parameters
	return c.RouteReadsToReplicas || c.ReadOnly
}

// GetMaxRedirects returns the maximum number of redirects to follow.
// Returns 0 if the Cluster is nil.
func (c *Cluster) GetMaxRedirects() int {
	if c == nil {
		return 0
	}

	return c.MaxRedirects
}

// GetReadTimeout returns the timeout for read operations.
// Returns 0 if the Cluster is nil.
func (c *Cluster) GetReadTimeout() time.Duration {
	if c == nil {
		return 0
	}

	return c.ReadTimeout
}

// GetWriteTimeout returns the timeout for write operations.
// Returns 0 if the Cluster is nil.
func (c *Cluster) GetWriteTimeout() time.Duration {
	if c == nil {
		return 0
	}

	return c.WriteTimeout
}

// MasterUser represents a user configuration with flags for enabling and setting delimiters.
type MasterUser struct {
	Enabled   bool   `mapstructure:"enabled"`
	Delimiter string `mapstructure:"delimiter" validate:"omitempty,len=1,printascii"`
}

// IsEnabled determines if the MasterUser is enabled by checking the Enabled field.
// Returns false if the MasterUser is nil.
func (m *MasterUser) IsEnabled() bool {
	if m == nil {
		return false
	}

	return m.Enabled
}

// GetDelimiter retrieves the delimiter value associated with the MasterUser configuration.
// Returns an empty string if the MasterUser is nil.
func (m *MasterUser) GetDelimiter() string {
	if m == nil {
		return ""
	}

	return m.Delimiter
}

// Frontend represents configuration options for the frontend of the application.
type Frontend struct {
	Enabled               bool     `mapstructure:"enabled"`
	EncryptionSecret      string   `mapstructure:"encryption_secret" validate:"required_if=Enabled true,min=16,alphanumsymbol,excludesall= "`
	HTMLStaticContentPath string   `mapstructure:"html_static_content_path" validate:"omitempty,dir"`
	LanguageResources     string   `mapstructure:"language_resources" validate:"omitempty,dir"`
	Languages             []string `mapstructure:"languages" validate:"omitempty"`
	DefaultLanguage       string   `mapstructure:"default_language" validate:"omitempty"`
	TotpIssuer            string   `mapstructure:"totp_issuer" validate:"omitempty"`
	TotpSkew              uint     `mapstructure:"totp_skew" validate:"omitempty"`
}

// IsEnabled checks if the Frontend is enabled.
// Returns false if the Frontend is nil.
func (f *Frontend) IsEnabled() bool {
	if f == nil {
		return false
	}

	return f.Enabled
}

// GetHTMLStaticContentPath retrieves the HTML static content path from the Frontend configuration.
// Returns an empty string if the Frontend is nil.
func (f *Frontend) GetHTMLStaticContentPath() string {
	if f == nil {
		return ""
	}

	return f.HTMLStaticContentPath
}

// GetLanguageResources retrieves the language resources path from the Frontend configuration.
func (f *Frontend) GetLanguageResources() string {
	if f == nil {
		return ""
	}

	return f.LanguageResources
}

// GetLanguages retrieves the languages from the Frontend configuration.
func (f *Frontend) GetLanguages() []string {
	if f == nil {
		return nil
	}

	return f.Languages
}

// GetDefaultLanguage retrieves the default language from the Frontend configuration.
func (f *Frontend) GetDefaultLanguage() string {
	if f == nil {
		return ""
	}

	return f.DefaultLanguage
}

// GetTotpIssuer retrieves the TOTP issuer from the Frontend configuration.
// Returns an empty string if the Frontend is nil.
func (f *Frontend) GetTotpIssuer() string {
	if f == nil {
		return ""
	}

	return f.TotpIssuer
}

// GetTotpSkew retrieves the TOTP skew from the Frontend configuration.
func (f *Frontend) GetTotpSkew() uint {
	if f == nil {
		return 0
	}

	return f.TotpSkew
}

// GetEncryptionSecret retrieves the encryption secret from the Frontend configuration.
// This secret is used to derive keys for secure cookie encryption.
func (f *Frontend) GetEncryptionSecret() string {
	if f == nil {
		return ""
	}

	return f.EncryptionSecret
}

// isAlphanumSymbol is a validation function for validating if the current field's value
// is a valid alphanumeric unicode value including symbols.
// This validator allows Unicode letters, numbers, and symbols, but excludes control characters and whitespace.
// It is an extension of the alphanumunicode validator that also allows symbols.
func isAlphanumSymbol(fl validator.FieldLevel) bool {
	// Check if the string contains any control characters or whitespace
	return !strings.ContainsFunc(fl.Field().String(), func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	})
}

// isScopeToken validates a scope-token according to RFC 6749 (OAuth 2.0) ABNF.
// Allowed: %x21 / %x23-5B / %x5D-7E (no spaces, quotes, or backslashes; ASCII only).
func isScopeToken(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return false
	}

	for _, r := range value {
		if r < 0x21 || r > 0x7E || r == 0x22 || r == 0x5C {
			return false
		}
	}

	return true
}

// isOIDCClaimName validates an OIDC claim name as a non-empty JSON member name.
// It allows any Unicode characters except control characters.
func isOIDCClaimName(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return false
	}

	return !strings.ContainsFunc(value, unicode.IsControl)
}

// isOIDCClaimType validates an OIDC claim type against the supported set.
func isOIDCClaimType(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return false
	}

	switch value {
	case definitions.ClaimTypeString,
		definitions.ClaimTypeBoolean,
		definitions.ClaimTypeFloat,
		definitions.ClaimTypeInteger,
		definitions.ClaimTypeStringArray,
		definitions.ClaimTypeBooleanArray,
		definitions.ClaimTypeFloatArray,
		definitions.ClaimTypeIntegerArray,
		definitions.ClaimTypeObject,
		definitions.ClaimTypeAddress:
		return true
	default:
		return false
	}
}

// hostnameRFC1123WithOptionalTrailingDot validates that the field value is a valid RFC1123 hostname
// and additionally allows an optional trailing dot (FQDN form).
// Implementation detail: If the value ends with a dot, the dot is stripped before validating
// using the built-in "hostname_rfc1123" rule from go-playground/validator.
func hostnameRFC1123WithOptionalTrailingDot(fl validator.FieldLevel) bool {
	s := fl.Field().String()

	// Allow optional trailing dot for FQDNs, but not a string that is only "."
	if strings.HasSuffix(s, ".") {
		s = strings.TrimSuffix(s, ".")
		if s == "" {
			return false
		}
	}

	// Reuse the standard validator's built-in hostname_rfc1123 rule
	v := validator.New()
	return v.Var(s, "hostname_rfc1123") == nil
}

// PrometheusTimer is a configuration structure for enabling and setting labels for Prometheus metrics timers.
type PrometheusTimer struct {
	Enabled bool     `mapstructure:"enabled"`
	Labels  []string `mapstructure:"labels" validate:"omitempty,dive,oneof=action account backend brute_force feature filter post_action request store_totp dns auth"`
}

// IsEnabled indicates whether the Prometheus timer is enabled based on the Enabled property of PrometheusTimer.
// Returns false if the PrometheusTimer is nil.
func (p *PrometheusTimer) IsEnabled() bool {
	if p == nil {
		return false
	}

	return p.Enabled
}

// GetLabels returns the list of labels configured for the PrometheusTimer.
// Returns an empty slice if the PrometheusTimer is nil.
func (p *PrometheusTimer) GetLabels() []string {
	if p == nil {
		return []string{}
	}

	return p.Labels
}

// DefaultHTTPRequestHeader represents the default headers to include in every HTTP request.
// This struct includes fields for authentication, SSL/TLS, and client/server metadata.
type DefaultHTTPRequestHeader struct {
	Username           string `mapstructure:"username" validate:"omitempty,printascii,excludesall= "`
	Password           string `mapstructure:"password" validate:"omitempty,printascii,excludesall= "`
	PasswordEncoded    string `mapstructure:"password_encoded" validate:"omitempty,printascii,excludesall= "`
	Protocol           string `mapstructure:"protocol" validate:"omitempty,printascii,excludesall= "`
	LoginAttempt       string `mapstructure:"login_attempt" validate:"omitempty,printascii,excludesall= "`
	AuthMethod         string `mapstructure:"auth_method" validate:"omitempty,printascii,excludesall= "`
	LocalIP            string `mapstructure:"local_ip" validate:"omitempty,printascii,excludesall= "`
	LocalPort          string `mapstructure:"local_port" validate:"omitempty,printascii,excludesall= "`
	ClientIP           string `mapstructure:"client_ip" validate:"omitempty,printascii,excludesall= "`
	ClientPort         string `mapstructure:"client_port" validate:"omitempty,printascii,excludesall= "`
	ClientHost         string `mapstructure:"client_host" validate:"omitempty,printascii,excludesall= "`
	ClientID           string `mapstructure:"client_id" validate:"omitempty,printascii,excludesall= "`
	SSL                string `mapstructure:"ssl" validate:"omitempty,printascii,excludesall= "`
	SSLSessionID       string `mapstructure:"ssl_session_id" validate:"omitempty,printascii,excludesall= "`
	SSLVerify          string `mapstructure:"ssl_verify" validate:"omitempty,printascii,excludesall= "`
	SSLSubject         string `mapstructure:"ssl_subject" validate:"omitempty,printascii,excludesall= "`
	SSLClientCN        string `mapstructure:"ssl_client_cn" validate:"omitempty,printascii,excludesall= "`
	SSLIssuer          string `mapstructure:"ssl_issuer" validate:"omitempty,printascii,excludesall= "`
	SSLClientNotBefore string `mapstructure:"ssl_client_not_before" validate:"omitempty,printascii,excludesall= "`
	SSLClientNotAfter  string `mapstructure:"ssl_client_not_after" validate:"omitempty,printascii,excludesall= "`
	SSLSubjectDN       string `mapstructure:"ssl_subject_dn" validate:"omitempty,printascii,excludesall= "`
	SSLIssuerDN        string `mapstructure:"ssl_issuer_dn" validate:"omitempty,printascii,excludesall= "`
	SSLClientSubjectDN string `mapstructure:"ssl_client_subject_dn" validate:"omitempty,printascii,excludesall= "`
	SSLClientIssuerDN  string `mapstructure:"ssl_client_issuer_dn" validate:"omitempty,printascii,excludesall= "`
	SSLCipher          string `mapstructure:"ssl_cipher" validate:"omitempty,printascii,excludesall= "`
	SSLProtocol        string `mapstructure:"ssl_protocol" validate:"omitempty,printascii,excludesall= "`
	SSLSerial          string `mapstructure:"ssl_serial" validate:"omitempty,printascii,excludesall= "`
	SSLFingerprint     string `mapstructure:"ssl_fingerprint" validate:"omitempty,printascii,excludesall= "`
	OIDCCID            string `mapstructure:"oidc_cid" validate:"omitempty,printascii,excludesall= "`
}

// GetUsername retrieves the username value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetUsername() string {
	if d == nil {
		return ""
	}

	return d.Username
}

// GetPassword retrieves the password value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetPassword() string {
	if d == nil {
		return ""
	}

	return d.Password
}

// GetPasswordEncoded retrieves the encoded password value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetPasswordEncoded() string {
	if d == nil {
		return ""
	}

	return d.PasswordEncoded
}

// GetProtocol retrieves the protocol value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetProtocol() string {
	if d == nil {
		return ""
	}

	return d.Protocol
}

// GetLoginAttempt retrieves the login attempt value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetLoginAttempt() string {
	if d == nil {
		return ""
	}

	return d.LoginAttempt
}

// GetAuthMethod retrieves the authentication method value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetAuthMethod() string {
	if d == nil {
		return ""
	}

	return d.AuthMethod
}

// GetLocalIP retrieves the local IP address from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetLocalIP() string {
	if d == nil {
		return ""
	}

	return d.LocalIP
}

// GetLocalPort retrieves the local port value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetLocalPort() string {
	if d == nil {
		return ""
	}

	return d.LocalPort
}

// GetClientIP retrieves the client's IP address from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetClientIP() string {
	if d == nil {
		return ""
	}

	return d.ClientIP
}

// GetClientPort retrieves the client port value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetClientPort() string {
	if d == nil {
		return ""
	}

	return d.ClientPort
}

// GetClientHost retrieves the client host value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetClientHost() string {
	if d == nil {
		return ""
	}

	return d.ClientHost
}

// GetClientID retrieves the client identifier from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetClientID() string {
	if d == nil {
		return ""
	}

	return d.ClientID
}

// GetSSL retrieves the SSL value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSL() string {
	if d == nil {
		return ""
	}

	return d.SSL
}

// GetSSLSessionID retrieves the SSL session ID from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLSessionID() string {
	if d == nil {
		return ""
	}

	return d.SSLSessionID
}

// GetSSLVerify retrieves the SSL verification setting from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLVerify() string {
	if d == nil {
		return ""
	}

	return d.SSLVerify
}

// GetSSLSubject retrieves the SSL subject value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLSubject() string {
	if d == nil {
		return ""
	}

	return d.SSLSubject
}

// GetSSLClientCN retrieves the Common Name (CN) from the SSL client certificate in the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLClientCN() string {
	if d == nil {
		return ""
	}

	return d.SSLClientCN
}

// GetSSLIssuer retrieves the SSL issuer value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLIssuer() string {
	if d == nil {
		return ""
	}

	return d.SSLIssuer
}

// GetSSLClientNotBefore retrieves the SSL client certificate start date from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLClientNotBefore() string {
	if d == nil {
		return ""
	}

	return d.SSLClientNotBefore
}

// GetSSLClientNotAfter retrieves the SSL client certificate expiration date from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLClientNotAfter() string {
	if d == nil {
		return ""
	}

	return d.SSLClientNotAfter
}

// GetSSLSubjectDN retrieves the SSL subject distinguished name (DN) from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLSubjectDN() string {
	if d == nil {
		return ""
	}

	return d.SSLSubjectDN
}

// GetSSLIssuerDN retrieves the SSL issuer distinguished name (DN) from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLIssuerDN() string {
	if d == nil {
		return ""
	}

	return d.SSLIssuerDN
}

// GetSSLClientSubjectDN retrieves the SSL client subject distinguished name (DN) from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLClientSubjectDN() string {
	if d == nil {
		return ""
	}

	return d.SSLClientSubjectDN
}

// GetSSLClientIssuerDN retrieves the SSL client issuer distinguished name (DN) from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLClientIssuerDN() string {
	if d == nil {
		return ""
	}

	return d.SSLClientIssuerDN
}

// GetSSLCipher retrieves the SSL cipher value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLCipher() string {
	if d == nil {
		return ""
	}

	return d.SSLCipher
}

// GetSSLProtocol retrieves the SSL protocol value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLProtocol() string {
	if d == nil {
		return ""
	}

	return d.SSLProtocol
}

// GetSSLSerial retrieves the SSL serial number from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLSerial() string {
	if d == nil {
		return ""
	}

	return d.SSLSerial
}

// GetSSLFingerprint retrieves the SSL fingerprint value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetSSLFingerprint() string {
	if d == nil {
		return ""
	}

	return d.SSLFingerprint
}

// GetOIDCCID retrieves the OIDC Client ID value from the DefaultHTTPRequestHeader struct.
// Returns an empty string if the DefaultHTTPRequestHeader is nil.
func (d *DefaultHTTPRequestHeader) GetOIDCCID() string {
	if d == nil {
		return ""
	}

	return d.OIDCCID
}

// Compression represents the configuration for HTTP response compression.
type Compression struct {
	Enabled bool `mapstructure:"enabled"`
	// Deprecated: level is deprecated in favor of level_gzip since 1.9.9. It will be removed in a future release.
	Level int `mapstructure:"level" validate:"omitempty,gte=1,lte=9"`

	// LevelGzip defines the gzip compression level (1-9, where 1 is fastest and 9 is best compression).
	// If not set (0), the server will fall back to the deprecated 'level' value for backward compatibility.
	LevelGzip int `mapstructure:"level_gzip" validate:"omitempty,gte=1,lte=9"`

	// LevelZstd configures the zstd compression level mapping (0=Default, 1=BestSpeed, 2=BetterCompression, 3=BestCompression).
	LevelZstd int `mapstructure:"level_zstd" validate:"omitempty,gte=0,lte=3"`

	// LevelBrotli configures the brotli compression level mapping (0=Default, 1=BestSpeed, 2=BetterCompression, 3=BestCompression).
	LevelBrotli int `mapstructure:"level_brotli" validate:"omitempty,gte=0,lte=3"`

	// MinLength specifies the minimum content length (in bytes) required for compression to be applied. Defaults to 0.
	MinLength int `mapstructure:"min_length" validate:"omitempty,gte=0"`

	// Deprecated: content_types has no effect since 1.9.2 and will be removed in a future release.
	ContentTypes []string `mapstructure:"content_types" validate:"omitempty,dive,printascii"`

	// Algorithms defines the enabled compression algorithms in order of preference, e.g. ["br", "zstd", "gzip"].
	Algorithms []string `mapstructure:"algorithms" validate:"omitempty,dive,printascii"`
}

// IsEnabled returns true if compression is enabled, otherwise false.
// Returns false if the Compression is nil.
func (c *Compression) IsEnabled() bool {
	if c == nil {
		return false
	}

	return c.Enabled
}

// GetLevel returns the (deprecated) gzip compression level (1-9).
// Deprecated: Use GetLevelGzip() instead. This remains for backward compatibility.
// Returns 0 if the Compression is nil.
func (c *Compression) GetLevel() int {
	if c == nil {
		return 0
	}

	return c.Level
}

// GetLevelGzip returns the configured gzip compression level (1-9).
// If LevelGzip is not set (>0), it falls back to the deprecated Level field for backward compatibility.
// Returns 0 if the Compression is nil.
func (c *Compression) GetLevelGzip() int {
	if c == nil {
		return 0
	}

	if c.LevelGzip > 0 {
		return c.LevelGzip
	}

	return c.Level
}

// GetContentTypes returns the list of content types that should be compressed.
// Returns an empty slice if the Compression is nil.
func (c *Compression) GetContentTypes() []string {
	if c == nil {
		return []string{}
	}

	return c.ContentTypes
}

// GetMinLength returns the minimum content length required for compression.
// Returns 0 if the Compression is nil.
func (c *Compression) GetMinLength() int {
	if c == nil {
		return 0
	}

	return c.MinLength
}

// GetAlgorithms returns the enabled compression algorithms in order of preference.
// Returns an empty slice if the Compression is nil.
func (c *Compression) GetAlgorithms() []string {
	if c == nil {
		return []string{}
	}

	return c.Algorithms
}

// GetLevelZstd returns the configured zstd compression level mapping.
// Returns 0 if the Compression is nil.
func (c *Compression) GetLevelZstd() int {
	if c == nil {
		return 0
	}

	return c.LevelZstd
}

// GetLevelBrotli returns the configured Brotli compression level (1-11).
// Returns 0 if the Compression is nil.
func (c *Compression) GetLevelBrotli() int {
	if c == nil {
		return 0
	}

	return c.LevelBrotli
}

// KeepAlive represents the configuration for HTTP connection keep-alive optimization.
type KeepAlive struct {
	Enabled             bool          `mapstructure:"enabled"`
	Timeout             time.Duration `mapstructure:"timeout" validate:"omitempty,gt=0"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections" validate:"omitempty,gte=1"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host" validate:"omitempty,gte=0"`
}

// IsEnabled returns true if keep-alive optimization is enabled, otherwise false.
// Returns false if the KeepAlive is nil.
func (k *KeepAlive) IsEnabled() bool {
	if k == nil {
		return false
	}

	return k.Enabled
}

// GetTimeout returns the keep-alive timeout duration.
// Returns 0 if the KeepAlive is nil.
func (k *KeepAlive) GetTimeout() time.Duration {
	if k == nil {
		return 0
	}

	return k.Timeout
}

// GetMaxIdleConns returns the maximum number of idle connections.
// Returns 0 if the KeepAlive is nil.
func (k *KeepAlive) GetMaxIdleConns() int {
	if k == nil {
		return 0
	}

	return k.MaxIdleConns
}

// GetMaxIdleConnsPerHost returns the maximum number of idle connections per host.
// Returns 0 if the KeepAlive is nil.
func (k *KeepAlive) GetMaxIdleConnsPerHost() int {
	if k == nil {
		return 0
	}

	return k.MaxIdleConnsPerHost
}

// Dedup controls in-process request deduplication behavior.
// NOTE: distributed (Redis-based) deduplication has been removed and the option
// 'server.dedup.distributed_enabled' is deprecated and ignored.
// Only in-process (singleflight) dedup remains supported.
type Dedup struct {
	// Deprecated: no longer used. Kept for backward compatibility with existing configs.
	DistributedEnabled bool `mapstructure:"distributed_enabled"`
	// Deprecated: no longer used. Kept for backward compatibility with existing configs.
	InProcessEnabled bool `mapstructure:"in_process_enabled"`
}

// GetDedup returns the Dedup configuration section. If ServerSection is nil,
// it returns a zero-value Dedup.
func (s *ServerSection) GetDedup() *Dedup {
	if s == nil {
		return &Dedup{}
	}

	return &s.Dedup
}

// IsDistributedEnabled reports whether distributed (Redis) deduplication is enabled.
// Deprecated: Distributed deduplication has been removed; this always returns false.
func (d *Dedup) IsDistributedEnabled() bool {
	return false
}

// IsInProcessEnabled reports whether in-process singleflight deduplication is enabled.
// Deprecated: In-process deduplication has been removed; this always returns false.
func (d *Dedup) IsInProcessEnabled() bool {
	return false
}

// Timeouts groups operation-specific timeouts under server.timeouts in the config.
type Timeouts struct {
	RedisRead        time.Duration `mapstructure:"redis_read"`
	RedisWrite       time.Duration `mapstructure:"redis_write"`
	LDAPSearch       time.Duration `mapstructure:"ldap_search"`
	LDAPBind         time.Duration `mapstructure:"ldap_bind"`
	LDAPModify       time.Duration `mapstructure:"ldap_modify"`
	SingleflightWork time.Duration `mapstructure:"singleflight_work"`
	LuaBackend       time.Duration `mapstructure:"lua_backend"`
	LuaScript        time.Duration `mapstructure:"lua_script"`
}

// GetRedisRead returns the timeout for Redis read operations. Defaults to 1s if unset/invalid.
func (t *Timeouts) GetRedisRead() time.Duration {
	if t == nil || t.RedisRead <= 0 {
		return 1 * time.Second
	}

	return t.RedisRead
}

// GetRedisWrite returns the timeout for Redis write operations. Defaults to 2s if unset/invalid.
func (t *Timeouts) GetRedisWrite() time.Duration {
	if t == nil || t.RedisWrite <= 0 {
		return 2 * time.Second
	}

	return t.RedisWrite
}

// GetLDAPSearch returns timeout for LDAP search operations. Defaults to 3s if unset/invalid.
func (t *Timeouts) GetLDAPSearch() time.Duration {
	if t == nil || t.LDAPSearch <= 0 {
		return 3 * time.Second
	}

	return t.LDAPSearch
}

// GetLDAPBind returns timeout for LDAP bind/auth operations. Defaults to 3s if unset/invalid.
func (t *Timeouts) GetLDAPBind() time.Duration {
	if t == nil || t.LDAPBind <= 0 {
		return 3 * time.Second
	}

	return t.LDAPBind
}

// GetLDAPModify returns timeout for LDAP modify operations. Defaults to 5s if unset/invalid.
func (t *Timeouts) GetLDAPModify() time.Duration {
	if t == nil || t.LDAPModify <= 0 {
		return 5 * time.Second
	}

	return t.LDAPModify
}

// GetSingleflightWork returns timeout for the actual singleflight leader work.
// Deprecated: This method is no more used and will be removed in a future release.
func (t *Timeouts) GetSingleflightWork() time.Duration {
	return 0 * time.Second
}

// GetLuaBackend returns timeout for Lua backend operations. Defaults to 5s if unset/invalid.
func (t *Timeouts) GetLuaBackend() time.Duration {
	if t == nil || t.LuaBackend <= 0 {
		return 5 * time.Second
	}

	return t.LuaBackend
}

func (t *Timeouts) GetLuaScript() time.Duration {
	if t.LuaScript == 0 {
		return 30 * time.Second
	}

	return t.LuaScript
}

func (s *ServerSection) GetTrustedProxies() []string {
	if s == nil {
		return []string{}
	}

	return s.TrustedProxies
}

func (s *ServerSection) GetEnvironment() Environment {
	return GetEnvironment()
}

func (s *ServerSection) GetTimeouts() *Timeouts {
	if s == nil {
		return &Timeouts{}
	}

	return &s.Timeouts
}
