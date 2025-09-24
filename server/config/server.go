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
	DisabledEndpoints         Endpoint                 `mapstructure:"disabled_endpoints" validate:"omitempty"`
	TLS                       TLS                      `mapstructure:"tls" validate:"omitempty"`
	BasicAuth                 BasicAuth                `mapstructure:"basic_auth" validate:"omitempty"`
	JWTAuth                   JWTAuth                  `mapstructure:"jwt_auth" validate:"omitempty"`
	InstanceName              string                   `mapstructure:"instance_name" validate:"omitempty,max=255,printascii"`
	Log                       Log                      `mapstructure:"log" validate:"omitempty"`
	Backends                  []*Backend               `mapstructure:"backends" validate:"omitempty,dive"`
	Features                  []*Feature               `mapstructure:"features" validate:"omitempty,dive"`
	BruteForceProtocols       []*Protocol              `mapstructure:"brute_force_protocols" validate:"omitempty,dive"`
	HydraAdminUrl             string                   `mapstructure:"ory_hydra_admin_url" validate:"omitempty,http_url"`
	DNS                       DNS                      `mapstructure:"dns" validate:"omitempty"`
	Insights                  Insights                 `mapstructure:"insights" validate:"omitempty"`
	Redis                     Redis                    `mapstructure:"redis" vslidate:"required"`
	MasterUser                MasterUser               `mapstructure:"master_user" validate:"omitempty"`
	Frontend                  Frontend                 `mapstructure:"frontend" validate:"omitempty"`
	PrometheusTimer           PrometheusTimer          `mapstructure:"prometheus_timer" validate:"omitempty"`
	DefaultHTTPRequestHeader  DefaultHTTPRequestHeader `mapstructure:"default_http_request_header" validate:"omitempty"`
	HTTPClient                HTTPClient               `mapstructure:"http_client" validate:"omitempty"`
	Compression               Compression              `mapstructure:"compression" validate:"omitempty"`
	KeepAlive                 KeepAlive                `mapstructure:"keep_alive" validate:"omitempty"`
}

// GetListenAddress retrieves the server's listen address from the ServerSection configuration.
// Returns an empty string if the ServerSection is nil.
func (s *ServerSection) GetListenAddress() string {
	if s == nil {
		return ""
	}

	return s.Address
}

// GetMaxConcurrentRequests retrieves the maximum number of concurrent requests allowed as configured in ServerSection.
// Returns 10 as a default value if the ServerSection is nil.
func (s *ServerSection) GetMaxConcurrentRequests() int32 {
	if s == nil {
		return 100
	}

	if s.MaxConcurrentRequests < 1 {
		return 100
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

// GetJWTAuth retrieves a pointer to the JWTAuth configuration from the ServerSection instance.
// Returns a new empty JWTAuth struct if the ServerSection is nil.
func (s *ServerSection) GetJWTAuth() *JWTAuth {
	if s == nil {
		return &JWTAuth{}
	}

	return &s.JWTAuth
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

// JWTAuth represents the configuration for JWT authentication.
type JWTAuth struct {
	Enabled            bool          `mapstructure:"enabled"`
	SecretKey          string        `mapstructure:"secret_key" validate:"omitempty,min=32,alphanumsymbol,excludesall= "`
	TokenExpiry        time.Duration `mapstructure:"token_expiry" validate:"omitempty,gt=0"`
	RefreshToken       bool          `mapstructure:"refresh_token"`
	RefreshTokenExpiry time.Duration `mapstructure:"refresh_token_expiry" validate:"omitempty,gt=0"`
	Users              []*JWTUser    `mapstructure:"users" validate:"omitempty,dive"`
	StoreInRedis       bool          `mapstructure:"store_in_redis"`
}

// JWTUser represents a user configuration for JWT authentication.
type JWTUser struct {
	Username string   `mapstructure:"username" validate:"required,excludesall= "`
	Password string   `mapstructure:"password" validate:"required,min=8,excludesall= "`
	Roles    []string `mapstructure:"roles" validate:"omitempty,dive"`
}

// IsEnabled returns true if basic HTTP authentication is enabled, otherwise false.
// Returns false if the BasicAuth is nil.
func (b *BasicAuth) IsEnabled() bool {
	if b == nil {
		return false
	}

	return b.Enabled
}

// IsEnabled returns true if JWT authentication is enabled, otherwise false.
// Returns false if the JWTAuth is nil.
func (j *JWTAuth) IsEnabled() bool {
	if j == nil {
		return false
	}

	return j.Enabled
}

// GetSecretKey returns the secret key used for JWT signing.
// Returns an empty string if the JWTAuth is nil.
func (j *JWTAuth) GetSecretKey() string {
	if j == nil {
		return ""
	}

	return j.SecretKey
}

// GetTokenExpiry returns the token expiry duration.
// Returns 0 if the JWTAuth is nil.
func (j *JWTAuth) GetTokenExpiry() time.Duration {
	if j == nil {
		return 0
	}

	return j.TokenExpiry
}

// IsRefreshTokenEnabled returns true if refresh tokens are enabled.
// Returns false if the JWTAuth is nil.
func (j *JWTAuth) IsRefreshTokenEnabled() bool {
	if j == nil {
		return false
	}

	return j.RefreshToken
}

// GetRefreshTokenExpiry returns the refresh token expiry duration.
// Returns 0 if the JWTAuth is nil.
func (j *JWTAuth) GetRefreshTokenExpiry() time.Duration {
	if j == nil {
		return 0
	}

	return j.RefreshTokenExpiry
}

// GetUsers returns the list of JWT users.
// Returns an empty slice if the JWTAuth is nil.
func (j *JWTAuth) GetUsers() []*JWTUser {
	if j == nil {
		return []*JWTUser{}
	}

	return j.Users
}

// IsStoreInRedisEnabled returns true if tokens should be stored in Redis.
// Returns false if the JWTAuth is nil.
func (j *JWTAuth) IsStoreInRedisEnabled() bool {
	if j == nil {
		return false
	}

	return j.StoreInRedis
}

// GetUsername returns the username of the JWT user.
// Returns an empty string if the JWTUser is nil.
func (u *JWTUser) GetUsername() string {
	if u == nil {
		return ""
	}

	return u.Username
}

// GetPassword returns the password of the JWT user.
// Returns an empty string if the JWTUser is nil.
func (u *JWTUser) GetPassword() string {
	if u == nil {
		return ""
	}

	return u.Password
}

// GetRoles returns the roles of the JWT user.
// Returns an empty slice if the JWTUser is nil.
func (u *JWTUser) GetRoles() []string {
	if u == nil {
		return []string{}
	}

	return u.Roles
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

// Log represents the configuration for logging.
type Log struct {
	JSON       bool         `mapstructure:"json"`
	Color      bool         `mapstructure:"color"`
	Level      Verbosity    `mapstructure:"level"`
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

// Insights is a configuration structure for enabling profiling, block profiling, and connection monitoring capabilities.
type Insights struct {
	EnablePprof        bool `mapstructure:"enable_pprof"`
	EnableBlockProfile bool `mapstructure:"enable_block_profile"`
	MonitorConnections bool `mapstructure:"monitor_connections"`
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
	DatabaseNmuber int           `mapstructure:"database_number" validate:"omitempty,gte=0,lte=15"`
	Prefix         string        `mapstructure:"prefix" validate:"omitempty,printascii,excludesall= "`
	PasswordNonce  string        `mapstructure:"password_nonce" validate:"omitempty,min=16,alphanumsymbol,excludesall= "`
	PoolSize       int           `mapstructure:"pool_size" validate:"omitempty,gte=1"`
	IdlePoolSize   int           `mapstructure:"idle_pool_size" validate:"omitempty,gte=0"`
	TLS            TLS           `mapstructure:"tls" validate:"omitempty"`
	PosCacheTTL    time.Duration `mapstructure:"positive_cache_ttl" validate:"omitempty,max=8760h"`
	NegCacheTTL    time.Duration `mapstructure:"negative_cache_ttl" validate:"omitempty,max=8760h"`
	Master         Master        `mapstructure:"master" validate:"omitempty"`
	Replica        Replica       `mapstructure:"replica" validate:"omitempty"`
	Sentinels      Sentinels     `mapstructure:"sentinels" validate:"omitempty"`
	Cluster        Cluster       `mapstructure:"cluster" validate:"omitempty"`
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

// GetPoolSize retrieves the size of the connection pool configured for the Redis instance.
// Returns 0 if the Redis is nil.
func (r *Redis) GetPoolSize() int {
	if r == nil {
		return 0
	}

	return r.PoolSize
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
	Enabled            bool   `mapstructure:"enabled"`
	CSRFSecret         string `mapstructure:"csrf_secret" validate:"omitempty,len=32,alphanumsymbol,excludesall= "`
	CookieStoreAuthKey string `mapstructure:"cookie_store_auth_key" validate:"omitempty,len=32,alphanumsymbol,excludesall= "`
	CookieStoreEncKey  string `mapstructure:"cookie_store_encryption_key" validate:"omitempty,alphanumsymbol,excludesall= ,validateCookieStoreEncKey"`
}

// IsEnabled checks if the Frontend is enabled.
// Returns false if the Frontend is nil.
func (f *Frontend) IsEnabled() bool {
	if f == nil {
		return false
	}

	return f.Enabled
}

// GetCSRFSecret retrieves the CSRF secret from the Frontend configuration.
// Returns an empty string if the Frontend is nil.
func (f *Frontend) GetCSRFSecret() string {
	if f == nil {
		return ""
	}

	return f.CSRFSecret
}

// GetCookieStoreAuthKey retrieves the cookie store authentication key from the Frontend configuration.
// Returns an empty string if the Frontend is nil.
func (f *Frontend) GetCookieStoreAuthKey() string {
	if f == nil {
		return ""
	}

	return f.CookieStoreAuthKey
}

// GetCookieStoreEncKey retrieves the cookie store encryption key from the Frontend configuration.
// Returns an empty string if the Frontend is nil.
func (f *Frontend) GetCookieStoreEncKey() string {
	if f == nil {
		return ""
	}

	return f.CookieStoreEncKey
}

func validateCookieStoreEncKey(fl validator.FieldLevel) bool {
	length := len(fl.Field().String())

	return length == 16 || length == 24 || length == 32
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

// PrometheusTimer is a configuration structure for enabling and setting labels for Prometheus metrics timers.
type PrometheusTimer struct {
	Enabled bool     `mapstructure:"enabled"`
	Labels  []string `mapstructure:"labels" validate:"omitempty,dive,oneof=action account backend brute_force feature filter post_action request store_totp dns"`
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
