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
	"time"

	"github.com/go-playground/validator/v10"
)

// ServerSection represents the configuration for a server, including network settings, TLS, logging, backends, features,
// protocol handling, and integrations with other systems such as Redis and Prometheus.
type ServerSection struct {
	Address                   string                   `mapstructure:"address" validate:"omitempty,tcp_addr"`
	MaxConcurrentRequests     int32                    `mapstructure:"max_concurrent_requests" validate:"required,gte=1"`
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
}

// GetListenAddress retrieves the server's listen address from the ServerSection configuration.
func (s *ServerSection) GetListenAddress() string {
	return s.Address
}

// GetMaxConcurrentRequests retrieves the maximum number of concurrent requests allowed as configured in ServerSection.
func (s *ServerSection) GetMaxConcurrentRequests() int32 {
	return s.MaxConcurrentRequests
}

// GetMaxPasswordHistoryEntries retrieves the maximum number of password history entries defined in the ServerSection configuration.
func (s *ServerSection) GetMaxPasswordHistoryEntries() int32 {
	return s.MaxPasswordHistoryEntries
}

// IsHTTP3Enabled checks if HTTP/3 protocol support is enabled in the server configuration and returns the corresponding boolean value.
func (s *ServerSection) IsHTTP3Enabled() bool {
	return s.HTTP3
}

// IsHAproxyProtocolEnabled checks if the HAProxy protocol (version 2) is enabled in the server configuration and returns the result.
func (s *ServerSection) IsHAproxyProtocolEnabled() bool {
	return s.HAproxyV2
}

// GetInstanceName retrieves the instance name defined in the ServerSection configuration.
func (s *ServerSection) GetInstanceName() string {
	return s.InstanceName
}

// GetEndpoint retrieves a pointer to the DisabledEndpoints configuration from the ServerSection instance.
func (s *ServerSection) GetEndpoint() *Endpoint {
	return &s.DisabledEndpoints
}

// GetBasicAuth retrieves a pointer to the BasicAuth configuration from the ServerSection instance.
func (s *ServerSection) GetBasicAuth() *BasicAuth {
	return &s.BasicAuth
}

// GetJWTAuth retrieves a pointer to the JWTAuth configuration from the ServerSection instance.
func (s *ServerSection) GetJWTAuth() *JWTAuth {
	return &s.JWTAuth
}

// GetTLS retrieves the TLS configuration from the ServerSection instance.
func (s *ServerSection) GetTLS() *TLS {
	return &s.TLS
}

// GetLog retrieves the logging configuration of the ServerSection instance.
func (s *ServerSection) GetLog() *Log {
	return &s.Log
}

// GetBackends retrieves the list of backends configured in the ServerSection instance.
func (s *ServerSection) GetBackends() []*Backend {
	return s.Backends
}

// GetFeatures retrieves the list of features configured in the ServerSection instance.
func (s *ServerSection) GetFeatures() []*Feature {
	return s.Features
}

// GetBruteForceProtocols retrieves the list of brute force protection protocols configured in the ServerSection.
func (s *ServerSection) GetBruteForceProtocols() []*Protocol {
	return s.BruteForceProtocols
}

// GetRedis returns a pointer to the Redis configuration of the ServerSection instance.
func (s *ServerSection) GetRedis() *Redis {
	return &s.Redis
}

// GetMasterUser retrieves a pointer to the MasterUser configuration from the ServerSection instance.
func (s *ServerSection) GetMasterUser() *MasterUser {
	return &s.MasterUser
}

// GetDNS retrieves the DNS configuration from the ServerSection instance.
func (s *ServerSection) GetDNS() *DNS {
	return &s.DNS
}

// GetInsights retrieves a pointer to the Insights configuration from the ServerSection instance.
func (s *ServerSection) GetInsights() *Insights {
	return &s.Insights
}

// GetHTTPClient retrieves the HTTP client configuration from the ServerSection instance.
func (s *ServerSection) GetHTTPClient() *HTTPClient {
	return &s.HTTPClient
}

// GetPrometheusTimer retrieves a pointer to the PrometheusTimer configuration from the ServerSection instance.
func (s *ServerSection) GetPrometheusTimer() *PrometheusTimer {
	return &s.PrometheusTimer
}

// GetDefaultHTTPRequestHeader retrieves a pointer to the DefaultHTTPRequestHeader configuration from the ServerSection instance.
func (s *ServerSection) GetDefaultHTTPRequestHeader() *DefaultHTTPRequestHeader {
	return &s.DefaultHTTPRequestHeader
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
}

// IsAuthHeaderDisabled checks if header-based authentication is enabled for the endpoint and returns the corresponding boolean value.
func (e *Endpoint) IsAuthHeaderDisabled() bool {
	return e.AuthHeader
}

// IsAuthJSONDisabled checks if JSON-based authentication is enabled for the endpoint and returns the corresponding boolean value.
func (e *Endpoint) IsAuthJSONDisabled() bool {
	return e.AuthJSON
}

// IsAuthBasicDisabled checks if Basic authentication is enabled for the endpoint and returns the corresponding boolean value.
func (e *Endpoint) IsAuthBasicDisabled() bool {
	return e.AuthBasic
}

// IsAuthNginxDisabled checks if Nginx-based authentication is enabled for the endpoint and returns the corresponding boolean value.
func (e *Endpoint) IsAuthNginxDisabled() bool {
	return e.AuthNginx
}

// IsAuthSASLAuthdDisabled checks if SASL authentication is enabled for the endpoint and returns the corresponding boolean value.
func (e *Endpoint) IsAuthSASLAuthdDisabled() bool {
	return e.AuthSASLAuthd
}

// IsAuthJWTDisabled checks if JWT authentication is enabled for the endpoint and returns the corresponding boolean value.
func (e *Endpoint) IsAuthJWTDisabled() bool {
	return e.AuthJWT
}

// IsCustomHooksDisabled checks if custom hooks are enabled for the endpoint and returns the corresponding boolean value.
func (e *Endpoint) IsCustomHooksDisabled() bool {
	return e.CustomHooks
}

// TLS represents the configuration for enabling TLS and managing certificates.
type TLS struct {
	Enabled              bool   `mapstructure:"enabled"`
	Cert                 string `mapstructure:"cert" validate:"omitempty,file"`
	Key                  string `mapstructure:"key" validate:"omitempty,file"`
	HTTPClientSkipVerify bool   `mapstructure:"http_client_skip_verify"`
}

// IsEnabled returns true if TLS is enabled, otherwise false.
func (t *TLS) IsEnabled() bool {
	return t.Enabled
}

// GetCert returns the TLS certificate as a string.
func (t *TLS) GetCert() string {
	return t.Cert
}

// GetKey returns the TLS key as a string.
func (t *TLS) GetKey() string {
	return t.Key
}

// GetHTTPClientSkipVerify returns the value of the HTTPClientSkipVerify field, indicating whether TLS verification is skipped.
func (t *TLS) GetHTTPClientSkipVerify() bool {
	return t.HTTPClientSkipVerify
}

type HTTPClient struct {
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host" validate:"omitempty,gte=1"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections" validate:"omitempty,gte=1"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host" validate:"omitempty,gte=0"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout" validate:"omitempty,gte=0"`
	Proxy               string        `mapstructure:"proxy"`
}

// GetMaxConnsPerHost returns the maximum number of connections allowed per host for the HTTP client.
func (c *HTTPClient) GetMaxConnsPerHost() int {
	return c.MaxConnsPerHost
}

// GetMaxIdleConns returns the maximum number of idle connections allowed for the HTTP client.
func (c *HTTPClient) GetMaxIdleConns() int {
	return c.MaxIdleConns
}

// GetMaxIdleConnsPerHost returns the maximum number of idle connections allowed per host for the HTTP client.
func (c *HTTPClient) GetMaxIdleConnsPerHost() int {
	return c.MaxIdleConnsPerHost
}

// GetIdleConnTimeout returns the idle connection timeout duration configured for the HTTP client.
func (c *HTTPClient) GetIdleConnTimeout() time.Duration {
	return c.IdleConnTimeout
}

// GetProxy returns the proxy URL configured for the HTTP client.
func (c *HTTPClient) GetProxy() string {
	return c.Proxy
}

// BasicAuth represents the configuration for basic HTTP authentication.
type BasicAuth struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password string `mapstructure:"password" validate:"omitempty,min=16,alphanumunicode,excludesall= "`
}

// JWTAuth represents the configuration for JWT authentication.
type JWTAuth struct {
	Enabled            bool          `mapstructure:"enabled"`
	SecretKey          string        `mapstructure:"secret_key" validate:"omitempty,min=32,alphanumunicode,excludesall= "`
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
func (b *BasicAuth) IsEnabled() bool {
	return b.Enabled
}

// IsEnabled returns true if JWT authentication is enabled, otherwise false.
func (j *JWTAuth) IsEnabled() bool {
	return j.Enabled
}

// GetSecretKey returns the secret key used for JWT signing.
func (j *JWTAuth) GetSecretKey() string {
	return j.SecretKey
}

// GetTokenExpiry returns the token expiry duration.
func (j *JWTAuth) GetTokenExpiry() time.Duration {
	return j.TokenExpiry
}

// IsRefreshTokenEnabled returns true if refresh tokens are enabled.
func (j *JWTAuth) IsRefreshTokenEnabled() bool {
	return j.RefreshToken
}

// GetRefreshTokenExpiry returns the refresh token expiry duration.
func (j *JWTAuth) GetRefreshTokenExpiry() time.Duration {
	return j.RefreshTokenExpiry
}

// GetUsers returns the list of JWT users.
func (j *JWTAuth) GetUsers() []*JWTUser {
	return j.Users
}

// IsStoreInRedisEnabled returns true if tokens should be stored in Redis.
func (j *JWTAuth) IsStoreInRedisEnabled() bool {
	return j.StoreInRedis
}

// GetUsername returns the username of the JWT user.
func (u *JWTUser) GetUsername() string {
	return u.Username
}

// GetPassword returns the password of the JWT user.
func (u *JWTUser) GetPassword() string {
	return u.Password
}

// GetRoles returns the roles of the JWT user.
func (u *JWTUser) GetRoles() []string {
	return u.Roles
}

// GetUsername returns the username configured for basic HTTP authentication.
func (b *BasicAuth) GetUsername() string {
	return b.Username
}

// GetPassword retrieves the password for the BasicAuth configuration.
func (b *BasicAuth) GetPassword() string {
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
func (l *Log) GetLogLevel() int {
	return l.Level.Level()
}

// GetLogLevelName returns the name of the current logging level as a string.
func (l *Log) GetLogLevelName() string {
	return l.Level.Get()
}

// GetDebugModules retrieves the list of debug modules configured in the Log instance.
func (l *Log) GetDebugModules() []*DbgModule {
	return l.DbgModules
}

// IsLogFormatJSON indicates whether the log format is set to JSON based on the `JSON` field in the `Log` struct.
func (l *Log) IsLogFormatJSON() bool {
	return l.JSON
}

// IsLogUsesColor determines if colored output is enabled for logging.
func (l *Log) IsLogUsesColor() bool {
	return l.Color
}

// Insights is a configuration structure for enabling profiling and block profiling capabilities.
type Insights struct {
	EnablePprof        bool `mapstructure:"enable_pprof"`
	EnableBlockProfile bool `mapstructure:"enable_block_profile"`
}

// IsPprofEnabled checks if pprof profiling is enabled in the Insights configuration.
func (i *Insights) IsPprofEnabled() bool {
	return i.EnablePprof
}

// IsBlockProfileEnabled checks if block profiling is enabled in the Insights configuration.
func (i *Insights) IsBlockProfileEnabled() bool {
	return i.EnableBlockProfile
}

// DNS represents the Domain Name System configuration settings, including resolver, timeout, and client IP resolution options.
type DNS struct {
	Resolver        string        `mapstructure:"resolver" validate:"omitempty,tcp_addr"`
	Timeout         time.Duration `mapstructure:"timeout" validate:"omitempty,gt=0,max=30s"`
	ResolveClientIP bool          `mapstructure:"resolve_client_ip"`
}

// GetResolver returns the configured DNS resolver address as a string.
func (d *DNS) GetResolver() string {
	return d.Resolver
}

// GetTimeout returns the timeout duration configured for the DNS resolver.
func (d *DNS) GetTimeout() time.Duration {
	return d.Timeout
}

// GetResolveClientIP returns the value of the ResolveClientIP field indicating whether client IP resolution is enabled.
func (d *DNS) GetResolveClientIP() bool {
	return d.ResolveClientIP
}

// Redis represents the configuration settings for a Redis instance, including master, replica, sentinel, and cluster setups.
type Redis struct {
	DatabaseNmuber int           `mapstructure:"database_number" validate:"omitempty,gte=0,lte=15"`
	Prefix         string        `mapstructure:"prefix" validate:"omitempty,printascii,excludesall= "`
	PasswordNonce  string        `mapstructure:"password_nonce" validate:"omitempty,min=16,alphanumunicode,excludesall= "`
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
func (r *Redis) GetDatabaseNumber() int {
	return r.DatabaseNmuber
}

// GetPrefix retrieves the prefix associated with the Redis instance configuration.
func (r *Redis) GetPrefix() string {
	return r.Prefix
}

// GetPasswordNonce retrieves the password nonce configured for the Redis instance.
func (r *Redis) GetPasswordNonce() string {
	return r.PasswordNonce
}

// GetPoolSize retrieves the size of the connection pool configured for the Redis instance.
func (r *Redis) GetPoolSize() int {
	return r.PoolSize
}

// GetIdlePoolSize retrieves the number of idle connections allowed in the connection pool.
func (r *Redis) GetIdlePoolSize() int {
	return r.IdlePoolSize
}

// GetTLS returns a pointer to the TLS configuration of the Redis instance.
func (r *Redis) GetTLS() *TLS {
	return &r.TLS
}

// GetPosCacheTTL retrieves the positive cache time-to-live (TTL) duration configured for the Redis instance.
func (r *Redis) GetPosCacheTTL() time.Duration {
	return r.PosCacheTTL
}

// GetNegCacheTTL retrieves the negative cache time-to-live (TTL) duration configured for the Redis instance.
func (r *Redis) GetNegCacheTTL() time.Duration {
	return r.NegCacheTTL
}

// GetStandaloneMaster returns a pointer to the Master configuration of the Redis instance.
func (r *Redis) GetStandaloneMaster() Master {
	return r.Master
}

// GetStandaloneReplica returns a pointer to the Replica configuration of the Redis instance.
func (r *Redis) GetStandaloneReplica() Replica {
	return r.Replica
}

// GetSentinel returns a pointer to the Sentinels configuration of the Redis instance.
func (r *Redis) GetSentinel() *Sentinels {
	return &r.Sentinels
}

// GetCluster returns a pointer to the Cluster configuration of the Redis instance.
func (r *Redis) GetCluster() *Cluster {
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
func (s *Sentinels) GetMasterName() string {
	return s.Master
}

// GetAddresses returns the list of addresses for the Redis Sentinel configuration.
func (s *Sentinels) GetAddresses() []string {
	return s.Addresses
}

// GetUsername retrieves the username configured for the Redis Sentinel connection.
func (s *Sentinels) GetUsername() string {
	return s.Username
}

// GetPassword retrieves the password configured for the Redis Sentinel connection.
func (s *Sentinels) GetPassword() string {
	return s.Password
}

// Cluster represents the configuration for a Redis cluster setup.
type Cluster struct {
	Addresses      []string      `mapstructure:"addresses" validate:"required,dive,hostname_port"`
	Username       string        `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password       string        `mapstructure:"password" validate:"omitempty,excludesall= "`
	RouteByLatency bool          `mapstructure:"route_by_latency"`
	RouteRandomly  bool          `mapstructure:"route_randomly"`
	ReadOnly       bool          `mapstructure:"read_only"`
	MaxRedirects   int           `mapstructure:"max_redirects" validate:"omitempty,gte=0"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout" validate:"omitempty"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout" validate:"omitempty"`
}

// GetAddresses retrieves the list of Redis cluster addresses configured in the Cluster instance.
func (c *Cluster) GetAddresses() []string {
	return c.Addresses
}

// GetUsername retrieves the username configured for the Redis cluster.
func (c *Cluster) GetUsername() string {
	return c.Username
}

// GetPassword retrieves the password configured for the Redis cluster.
func (c *Cluster) GetPassword() string {
	return c.Password
}

// GetRouteByLatency returns whether commands should be routed to the closest node.
func (c *Cluster) GetRouteByLatency() bool {
	return c.RouteByLatency
}

// GetRouteRandomly returns whether commands should be routed randomly across nodes.
func (c *Cluster) GetRouteRandomly() bool {
	return c.RouteRandomly
}

// GetReadOnly returns whether read-only commands should be allowed from replicas.
func (c *Cluster) GetReadOnly() bool {
	return c.ReadOnly
}

// GetMaxRedirects returns the maximum number of redirects to follow.
func (c *Cluster) GetMaxRedirects() int {
	return c.MaxRedirects
}

// GetReadTimeout returns the timeout for read operations.
func (c *Cluster) GetReadTimeout() time.Duration {
	return c.ReadTimeout
}

// GetWriteTimeout returns the timeout for write operations.
func (c *Cluster) GetWriteTimeout() time.Duration {
	return c.WriteTimeout
}

// MasterUser represents a user configuration with flags for enabling and setting delimiters.
type MasterUser struct {
	Enabled   bool   `mapstructure:"enabled"`
	Delimiter string `mapstructure:"delimiter" validate:"omitempty,len=1,printascii"`
}

// IsEnabled determines if the MasterUser is enabled by checking the Enabled field.
func (m *MasterUser) IsEnabled() bool {
	return m.Enabled
}

// GetDelimiter retrieves the delimiter value associated with the MasterUser configuration.
func (m *MasterUser) GetDelimiter() string {
	return m.Delimiter
}

// Frontend represents configuration options for the frontend of the application.
type Frontend struct {
	Enabled            bool   `mapstructure:"enabled"`
	CSRFSecret         string `mapstructure:"csrf_secret" validate:"omitempty,len=32,alphanumunicode,excludesall= "`
	CookieStoreAuthKey string `mapstructure:"cookie_store_auth_key" validate:"omitempty,len=32,alphanumunicode,excludesall= "`
	CookieStoreEncKey  string `mapstructure:"cookie_store_encryption_key" validate:"omitempty,alphanumunicode,excludesall= ,validateCookieStoreEncKey"`
}

func validateCookieStoreEncKey(fl validator.FieldLevel) bool {
	length := len(fl.Field().String())

	return length == 16 || length == 24 || length == 32
}

// PrometheusTimer is a configuration structure for enabling and setting labels for Prometheus metrics timers.
type PrometheusTimer struct {
	Enabled bool     `mapstructure:"enabled"`
	Labels  []string `mapstructure:"labels" validate:"omitempty,dive,oneof=action account backend brute_force feature filter post_action request store_totp dns"`
}

// IsEnabled indicates whether the Prometheus timer is enabled based on the Enabled property of PrometheusTimer.
func (p *PrometheusTimer) IsEnabled() bool {
	return p.Enabled
}

// GetLabels returns the list of labels configured for the PrometheusTimer.
func (p *PrometheusTimer) GetLabels() []string {
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
}

// GetUsername retrieves the username value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetUsername() string {
	return d.Username
}

// GetPassword retrieves the password value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetPassword() string {
	return d.Password
}

// GetPasswordEncoded retrieves the encoded password value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetPasswordEncoded() string {
	return d.PasswordEncoded
}

// GetProtocol retrieves the protocol value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetProtocol() string {
	return d.Protocol
}

// GetLoginAttempt retrieves the login attempt value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetLoginAttempt() string {
	return d.LoginAttempt
}

// GetAuthMethod retrieves the authentication method value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetAuthMethod() string {
	return d.AuthMethod
}

// GetLocalIP retrieves the local IP address from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetLocalIP() string {
	return d.LocalIP
}

// GetLocalPort retrieves the local port value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetLocalPort() string {
	return d.LocalPort
}

// GetClientIP retrieves the client's IP address from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetClientIP() string {
	return d.ClientIP
}

// GetClientPort retrieves the client port value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetClientPort() string {
	return d.ClientPort
}

// GetClientHost retrieves the client host value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetClientHost() string {
	return d.ClientHost
}

// GetClientID retrieves the client identifier from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetClientID() string {
	return d.ClientID
}

// GetSSL retrieves the SSL value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSL() string {
	return d.SSL
}

// GetSSLSessionID retrieves the SSL session ID from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLSessionID() string {
	return d.SSLSessionID
}

// GetSSLVerify retrieves the SSL verification setting from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLVerify() string {
	return d.SSLVerify
}

// GetSSLSubject retrieves the SSL subject value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLSubject() string {
	return d.SSLSubject
}

// GetSSLClientCN retrieves the Common Name (CN) from the SSL client certificate in the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLClientCN() string {
	return d.SSLClientCN
}

// GetSSLIssuer retrieves the SSL issuer value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLIssuer() string {
	return d.SSLIssuer
}

// GetSSLClientNotBefore retrieves the SSL client certificate start date from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLClientNotBefore() string {
	return d.SSLClientNotBefore
}

// GetSSLClientNotAfter retrieves the SSL client certificate expiration date from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLClientNotAfter() string {
	return d.SSLClientNotAfter
}

// GetSSLSubjectDN retrieves the SSL subject distinguished name (DN) from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLSubjectDN() string {
	return d.SSLSubjectDN
}

// GetSSLIssuerDN retrieves the SSL issuer distinguished name (DN) from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLIssuerDN() string {
	return d.SSLIssuerDN
}

// GetSSLClientSubjectDN retrieves the SSL client subject distinguished name (DN) from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLClientSubjectDN() string {
	return d.SSLClientSubjectDN
}

// GetSSLClientIssuerDN retrieves the SSL client issuer distinguished name (DN) from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLClientIssuerDN() string {
	return d.SSLClientIssuerDN
}

// GetSSLCipher retrieves the SSL cipher value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLCipher() string {
	return d.SSLCipher
}

// GetSSLProtocol retrieves the SSL protocol value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLProtocol() string {
	return d.SSLProtocol
}

// GetSSLSerial retrieves the SSL serial number from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLSerial() string {
	return d.SSLSerial
}

// GetSSLFingerprint retrieves the SSL fingerprint value from the DefaultHTTPRequestHeader struct.
func (d *DefaultHTTPRequestHeader) GetSSLFingerprint() string {
	return d.SSLFingerprint
}
