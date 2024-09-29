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
)

// ServerSection represents the configuration for a server, including network settings, TLS, logging, backends, features,
// protocol handling, and integrations with other systems such as Redis and Prometheus.
type ServerSection struct {
	Address                   string                   `mapstructure:"address"`
	MaxConcurrentRequests     int32                    `mapstructure:"max_concurrent_requests"`
	MaxPasswordHistoryEntries int32                    `mapstructure:"max_password_history_entries"`
	HTTP3                     bool                     `mapstructure:"http3"`
	HAproxyV2                 bool                     `mapstructure:"haproxy_v2"`
	TLS                       TLS                      `mapstructure:"tls"`
	BasicAuth                 BasicAuth                `mapstructure:"basic_auth"`
	InstanceName              string                   `mapstructure:"instance_name"`
	Log                       Log                      `maptostructure:"log"`
	Backends                  []*Backend               `mapstructure:"backends"`
	Features                  []*Feature               `mapstructure:"features"`
	BruteForceProtocols       []*Protocol              `mapstructure:"brute_force_protocols"`
	HydraAdminUrl             string                   `mapstructure:"ory_hydra_admin_url"`
	DNS                       DNS                      `mapstructure:"dns"`
	Insights                  Insights                 `mapstructure:"insights"`
	Redis                     Redis                    `mapstructure:"redis"`
	MasterUser                MasterUser               `mapstructure:"master_user"`
	Frontend                  Frontend                 `mapstructure:"frontend"`
	PrometheusTimer           PrometheusTimer          `mapstructure:"prometheus_timer"`
	DefaultHTTPRequestHeader  DefaultHTTPRequestHeader `mapstructure:"default_http_request_header"`
}

// TLS represents the configuration for enabling TLS and managing certificates.
type TLS struct {
	Enabled              bool   `mapstructure:"enabled"`
	Cert                 string `mapstructure:"cert"`
	Key                  string `mapstructure:"key"`
	HTTPClientSkipVerify bool   `mapstructure:"http_client_skip_verify"`
}

// BasicAuth represents the configuration for basic HTTP authentication.
type BasicAuth struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// Log represents the configuration for logging.
type Log struct {
	JSON       bool         `mapstructure:"json"`
	Color      bool         `mapstructure:"color"`
	Level      Verbosity    `mapstructure:"level"`
	DbgModules []*DbgModule `mapstructure:"debug_modules"`
}

// Insights is a configuration structure for enabling profiling and block profiling capabilities.
type Insights struct {
	EnablePprof        bool `mapstructure:"enable_pprof"`
	EnableBlockProfile bool `mapstructure:"enable_block_profile"`
}

// DNS represents the Domain Name System configuration settings, including resolver, timeout, and client IP resolution options.
type DNS struct {
	Resolver        string        `mapstructure:"resolver"`
	Timeout         time.Duration `mapstructure:"timeout"`
	ResolveClientIP bool          `mapstructure:"resolve_client_ip"`
}

// Redis represents the configuration settings for a Redis instance, including master, replica, sentinel, and cluster setups.
type Redis struct {
	DatabaseNmuber int       `mapstructure:"database_number"`
	Prefix         string    `mapstructure:"prefix"`
	PasswordNonce  string    `mapstructure:"password_nonce"`
	PoolSize       int       `mapstructure:"pool_size"`
	IdlePoolSize   int       `mapstructure:"idle_pool_size"`
	TLS            TLS       `mapstructure:"tls"`
	PosCacheTTL    uint      `mapstructure:"positive_cache_ttl"`
	NegCacheTTL    uint      `mapstructure:"negative_cache_ttl"`
	Master         Master    `mapstructure:"master"`
	Replica        Replica   `mapstructure:"replica"`
	Sentinels      Sentinels `mapstructure:"sentinels"`
	Cluster        Cluster   `mapstructure:"cluster"`
}

// Master represents the configuration for the master Redis instance.
// Includes fields for address, username, and password for the master instance.
type Master struct {
	Address  string `mapstructure:"address"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// Replica represents the configuration for a Redis replica instance.
type Replica struct {
	Address string `mapstructure:"address"`
}

// Sentinels represents the configuration for Redis Sentinel.
type Sentinels struct {
	Master    string   `mapstructure:"master"`
	Addresses []string `mapstructure:"addresses"`
	Username  string   `mapstructure:"username"`
	Password  string   `mapstructure:"password"`
}

// Cluster represents the configuration for a Redis cluster setup.
type Cluster struct {
	Addresses []string `mapstructure:"addresses"`
	Username  string   `mapstructure:"username"`
	Password  string   `mapstructure:"password"`
}

// MasterUser represents a user configuration with flags for enabling and setting delimiters.
type MasterUser struct {
	Enabled   bool   `mapstructure:"enabled"`
	Delimiter string `mapstructure:"delimiter"`
}

// Frontend represents configuration options for the frontend of the application.
type Frontend struct {
	Enabled            bool   `mapstructure:"enabled"`
	CSRFSecret         string `mapstructure:"csrf_secret"`
	CookieStoreAuthKey string `mapstructure:"cookie_store_auth_key"`
	CookieStoreEncKey  string `mapstructure:"cookie_store_encryption_key"`
}

// PrometheusTimer is a configuration structure for enabling and setting labels for Prometheus metrics timers.
type PrometheusTimer struct {
	Enabled bool     `mapstructure:"enabled"`
	Labels  []string `mapstructure:"labels"`
}

// DefaultHTTPRequestHeader represents the default headers to include in every HTTP request.
// This struct includes fields for authentication, SSL/TLS, and client/server metadata.
type DefaultHTTPRequestHeader struct {
	Username           string `mapstructure:"username"`
	Password           string `mapstructure:"password"`
	PasswordEncoded    string `mapstructure:"password_encoded"`
	Protocol           string `mapstructure:"protocol"`
	LoginAttempt       string `mapstructure:"login_attempt"`
	AuthMethod         string `mapstructure:"auth_method"`
	LocalIP            string `mapstructure:"local_ip"`
	LocalPort          string `mapstructure:"local_port"`
	ClientIP           string `mapstructure:"client_ip"`
	ClientPort         string `mapstructure:"client_port"`
	ClientHost         string `mapstructure:"client_host"`
	ClientID           string `mapstructure:"client_id"`
	SSL                string `mapstructure:"ssl"`
	SSLSessionID       string `mapstructure:"ssl_session_id"`
	SSLVerify          string `mapstructure:"ssl_verify"`
	SSLSubject         string `mapstructure:"ssl_subject"`
	SSLClientCN        string `mapstructure:"ssl_client_cn"`
	SSLIssuer          string `mapstructure:"ssl_issuer"`
	SSLClientNotBefore string `mapstructure:"ssl_client_not_before"`
	SSLClientNotAfter  string `mapstructure:"ssl_client_not_after"`
	SSLSubjectDN       string `mapstructure:"ssl_subject_dn"`
	SSLIssuerDN        string `mapstructure:"ssl_issuer_dn"`
	SSLClientSubjectDN string `mapstructure:"ssl_client_subject_dn"`
	SSLClientIssuerDN  string `mapstructure:"ssl_client_issuer_dn"`
	SSLCipher          string `mapstructure:"ssl_cipher"`
	SSLProtocol        string `mapstructure:"ssl_protocol"`
	SSLSerial          string `mapstructure:"ssl_serial"`
	SSLFingerprint     string `mapstructure:"ssl_fingerprint"`
}
