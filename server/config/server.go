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

// Endpoint defines a structure for configuring various types of authentication and custom hooks.
type Endpoint struct {
	AuthHeader    bool `mapstructure:"auth_header"`
	AuthJSON      bool `mapstructure:"auth_json"`
	AuthBasic     bool `mapstructure:"auth_basic"`
	AuthNginx     bool `mapstructure:"auth_nginx"`
	AuthSASLAuthd bool `mapstructure:"auth_saslauthd"`
	CustomHooks   bool `mapstructure:"custom_hooks"`
}

// TLS represents the configuration for enabling TLS and managing certificates.
type TLS struct {
	Enabled              bool   `mapstructure:"enabled"`
	Cert                 string `mapstructure:"cert" validate:"omitempty,file"`
	Key                  string `mapstructure:"key" validate:"omitempty,file"`
	HTTPClientSkipVerify bool   `mapstructure:"http_client_skip_verify"`
}

type HTTPClient struct {
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host" validate:"omitempty,gte=1"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections" validate:"omitempty,gte=1"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host" validate:"omitempty,gte=0"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout" validate:"omitempty,gte=0"`
	Proxy               string        `mapstructure:"proxy"`
}

// BasicAuth represents the configuration for basic HTTP authentication.
type BasicAuth struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password string `mapstructure:"password" validate:"omitempty,min=16,alphanumunicode,excludesall= "`
}

// Log represents the configuration for logging.
type Log struct {
	JSON       bool         `mapstructure:"json"`
	Color      bool         `mapstructure:"color"`
	Level      Verbosity    `mapstructure:"level"`
	DbgModules []*DbgModule `mapstructure:"debug_modules" validate:"omitempty,dive"`
}

// Insights is a configuration structure for enabling profiling and block profiling capabilities.
type Insights struct {
	EnablePprof        bool `mapstructure:"enable_pprof"`
	EnableBlockProfile bool `mapstructure:"enable_block_profile"`
}

// DNS represents the Domain Name System configuration settings, including resolver, timeout, and client IP resolution options.
type DNS struct {
	Resolver        string        `mapstructure:"resolver" validate:"omitempty,tcp_addr"`
	Timeout         time.Duration `mapstructure:"timeout" validate:"omitempty,gt=0,max=30s"`
	ResolveClientIP bool          `mapstructure:"resolve_client_ip"`
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

// Master represents the configuration for the master Redis instance.
// Includes fields for address, username, and password for the master instance.
type Master struct {
	Address  string `mapstructure:"address" validate:"omitempty,hostname_port"`
	Username string `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password string `mapstructure:"password" validate:"omitempty,excludesall= "`
}

// Replica represents the configuration for a Redis replica instance.
type Replica struct {
	Address string `mapstructure:"address" validate:"omitempty,hostname_port"`
}

// Sentinels represents the configuration for Redis Sentinel.
type Sentinels struct {
	Master    string   `mapstructure:"master" validate:"required,printascii,excludesall= "`
	Addresses []string `mapstructure:"addresses" validate:"required,dive,hostname_port"`
	Username  string   `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password  string   `mapstructure:"password" validate:"omitempty,excludesall= "`
}

// Cluster represents the configuration for a Redis cluster setup.
type Cluster struct {
	Addresses []string `mapstructure:"addresses" validate:"required,dive,hostname_port"`
	Username  string   `mapstructure:"username" validate:"omitempty,excludesall= "`
	Password  string   `mapstructure:"password" validate:"omitempty,excludesall= "`
}

// MasterUser represents a user configuration with flags for enabling and setting delimiters.
type MasterUser struct {
	Enabled   bool   `mapstructure:"enabled"`
	Delimiter string `mapstructure:"delimiter" validate:"omitempty,len=1,printascii"`
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
