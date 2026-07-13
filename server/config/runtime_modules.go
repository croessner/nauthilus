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
	"fmt"
	"strings"
	"time"
)

const (
	defaultBackendHealthCheckTimeout           = 5 * time.Second
	defaultBackendHealthCheckInterval          = 10 * time.Second
	defaultBackendHealthCheckFailureThreshold  = 1
	defaultBackendHealthCheckRecoveryThreshold = 1
)

const (
	// BackendAuthMechanismAuto lets backend health checks select an advertised executable mechanism.
	BackendAuthMechanismAuto = "auto"
	// BackendAuthMechanismPlain selects SASL PLAIN.
	BackendAuthMechanismPlain = "PLAIN"
	// BackendAuthMechanismLogin selects SASL LOGIN.
	BackendAuthMechanismLogin = "LOGIN"
	// BackendAuthMechanismUserPass selects POP3 USER/PASS.
	BackendAuthMechanismUserPass = "USERPASS"
	// BackendAuthMechanismBasic selects HTTP Basic authentication.
	BackendAuthMechanismBasic = "BASIC"
)

// BackendTLSMode selects how a backend health-check target establishes TLS.
type BackendTLSMode string

const (
	// BackendTLSModePlain keeps the backend connection unencrypted.
	BackendTLSModePlain BackendTLSMode = "plain"
	// BackendTLSModeImplicit starts TLS immediately after the optional PROXY preface.
	BackendTLSModeImplicit BackendTLSMode = "implicit"
	// BackendTLSModeStartTLS upgrades the application protocol before authentication.
	BackendTLSModeStartTLS BackendTLSMode = "starttls"
)

// RelayDomainsSection describes the exported RelayDomainsSection type.
type RelayDomainsSection struct {
	SoftWhitelist SoftWhitelist `mapstructure:"allowlist"`
	StaticDomains []string      `mapstructure:"static" validate:"required,dive,hostname_rfc1123_with_opt_trailing_dot"`
}

func (r *RelayDomainsSection) String() string {
	if r == nil {
		return "RelayDomainsSection: <nil>"
	}

	return fmt.Sprintf("RelayDomainsSection: {Static[%+v]}", r.StaticDomains)
}

// GetStaticDomains retrieves the list of static domains from the RelayDomainsSection.
// Returns an empty slice if the RelayDomainsSection is nil.
func (r *RelayDomainsSection) GetStaticDomains() []string {
	if r == nil {
		return []string{}
	}

	return r.StaticDomains
}

// GetSoftWhitelist retrieves the SoftWhitelist from the RelayDomainsSection.
// Returns an empty map if the RelayDomainsSection is nil.
func (r *RelayDomainsSection) GetSoftWhitelist() SoftWhitelist {
	if r == nil {
		return map[string][]string{}
	}

	return r.SoftWhitelist
}

// BackendServer describes the exported BackendServer type.
type BackendServer struct {
	Protocol      string         `mapstructure:"protocol" validate:"required,oneof=imap pop3 lmtp smtp sieve http"`
	Host          string         `mapstructure:"host" validate:"required,hostname_rfc1123_with_opt_trailing_dot|ip"`
	AuthMechanism string         `mapstructure:"auth_mechanism" validate:"omitempty,oneof=auto PLAIN LOGIN USERPASS BASIC"`
	TLSMode       BackendTLSMode `mapstructure:"tls_mode" validate:"omitempty,oneof=plain implicit starttls"`

	RequestURI   string `mapstructure:"request_uri" validate:"omitempty,url_encoded"`
	TestUsername string `mapstructure:"test_username" validate:"omitempty,excludesall= "`
	TestPassword string `mapstructure:"test_password" validate:"omitempty,excludesall= "`

	ConnectTimeout time.Duration `mapstructure:"connect_timeout" validate:"omitempty,gt=0,max=1m"`
	TLSTimeout     time.Duration `mapstructure:"tls_timeout" validate:"omitempty,gt=0,max=1m"`
	DeepTimeout    time.Duration `mapstructure:"deep_timeout" validate:"omitempty,gt=0,max=5m"`

	Port          int  `mapstructure:"port" validate:"omitempty,min=1,max=65535"`
	DeepCheck     bool `mapstructure:"deep_check"`
	TLS           bool `mapstructure:"tls"`
	TLSSkipVerify bool `mapstructure:"tls_skip_verify"`
	HAProxyV2     bool `mapstructure:"haproxy_v2"`
}

func (n *BackendServer) String() string {
	if n == nil {
		return "BackendServer: <nil>"
	}

	return fmt.Sprintf("BackendServer: {Protocol: %s, Host: %s, AuthMechanism: %s, TLSMode: %s, RequestURI: %s, TestUsername: %s, TestPassword: <hidden>, Port: %d, TLS: %t, TLSSkipVerify: %t, HAProxyV2: %t}",
		n.Protocol, n.Host, n.GetAuthMechanism(), n.GetTLSMode(), n.RequestURI, n.TestUsername, n.Port, n.TLS, n.TLSSkipVerify, n.HAProxyV2)
}

// GetProtocol retrieves the protocol value from the BackendServer.
// Returns an empty string if the BackendServer is nil.
func (n *BackendServer) GetProtocol() string {
	if n == nil {
		return ""
	}

	return n.Protocol
}

// GetHost retrieves the host value from the BackendServer.
// Returns an empty string if the BackendServer is nil.
func (n *BackendServer) GetHost() string {
	if n == nil {
		return ""
	}

	return n.Host
}

// GetAuthMechanism returns the normalized target-local backend health-check authentication mechanism.
func (n *BackendServer) GetAuthMechanism() string {
	if n == nil {
		return BackendAuthMechanismAuto
	}

	return NormalizeBackendAuthMechanism(n.AuthMechanism)
}

// NormalizeBackendAuthMechanism normalizes backend health-check authentication mechanism names.
func NormalizeBackendAuthMechanism(mechanism string) string {
	normalized := strings.TrimSpace(mechanism)
	if normalized == "" || strings.EqualFold(normalized, BackendAuthMechanismAuto) {
		return BackendAuthMechanismAuto
	}

	return strings.ToUpper(normalized)
}

// normalizeAuthMechanism stores the canonical target-local auth mechanism back into the server config.
func (n *BackendServer) normalizeAuthMechanism() {
	if n == nil {
		return
	}

	n.AuthMechanism = n.GetAuthMechanism()
}

// GetTLSMode resolves the explicit mode and compatible legacy defaults.
func (n *BackendServer) GetTLSMode() BackendTLSMode {
	if n == nil {
		return BackendTLSModePlain
	}

	if n.TLSMode != "" {
		return NormalizeBackendTLSMode(n.TLSMode)
	}

	if n.TLS {
		return BackendTLSModeImplicit
	}

	if strings.EqualFold(n.Protocol, "sieve") {
		return BackendTLSModeStartTLS
	}

	return BackendTLSModePlain
}

// NormalizeBackendTLSMode canonicalizes backend health-check TLS modes.
func NormalizeBackendTLSMode(mode BackendTLSMode) BackendTLSMode {
	return BackendTLSMode(strings.ToLower(strings.TrimSpace(string(mode))))
}

// normalizeTLSMode stores a canonical explicit TLS mode without materializing legacy defaults.
func (n *BackendServer) normalizeTLSMode() {
	if n == nil || n.TLSMode == "" {
		return
	}

	n.TLSMode = NormalizeBackendTLSMode(n.TLSMode)
}

// validateTLSMode enforces protocol and legacy compatibility for one target.
func (n *BackendServer) validateTLSMode() error {
	if n == nil {
		return nil
	}

	mode := n.GetTLSMode()
	if n.TLS && n.TLSMode != "" && mode != BackendTLSModeImplicit {
		return fmt.Errorf("tls: true conflicts with tls_mode %q", mode)
	}

	if mode != BackendTLSModeStartTLS {
		return nil
	}

	if strings.EqualFold(n.Protocol, "http") {
		return fmt.Errorf("protocol http does not support tls_mode %q", mode)
	}

	if !n.DeepCheck {
		return fmt.Errorf("tls_mode %q requires deep_check: true", mode)
	}

	return nil
}

// IsDeepCheck checks if deep checking is enabled for the BackendServer.
// Returns false if the BackendServer is nil.
func (n *BackendServer) IsDeepCheck() bool {
	if n == nil {
		return false
	}

	return n.DeepCheck
}

// GetRequestURI retrieves the request URI from the BackendServer.
// Returns an empty string if the BackendServer is nil.
func (n *BackendServer) GetRequestURI() string {
	if n == nil {
		return ""
	}

	return n.RequestURI
}

// GetTestUsername retrieves the test username from the BackendServer.
// Returns an empty string if the BackendServer is nil.
func (n *BackendServer) GetTestUsername() string {
	if n == nil {
		return ""
	}

	return n.TestUsername
}

// GetTestPassword retrieves the test password from the BackendServer.
// Returns an empty string if the BackendServer is nil.
func (n *BackendServer) GetTestPassword() string {
	if n == nil {
		return ""
	}

	return n.TestPassword
}

// GetPort retrieves the port number from the BackendServer.
// Returns 0 if the BackendServer is nil.
func (n *BackendServer) GetPort() int {
	if n == nil {
		return 0
	}

	return n.Port
}

// IsTLS checks if TLS is enabled for the BackendServer.
// Returns false if the BackendServer is nil.
func (n *BackendServer) IsTLS() bool {
	if n == nil {
		return false
	}

	return n.TLS
}

// IsTLSSkipVerify checks if TLS verification should be skipped for the BackendServer.
// Returns false if the BackendServer is nil.
func (n *BackendServer) IsTLSSkipVerify() bool {
	if n == nil {
		return false
	}

	return n.TLSSkipVerify
}

// IsHAProxyV2 checks if HAProxy protocol version 2 is enabled for the BackendServer.
// Returns false if the BackendServer is nil.
func (n *BackendServer) IsHAProxyV2() bool {
	if n == nil {
		return false
	}

	return n.HAProxyV2
}

// BackendServerMonitoring describes the exported BackendServerMonitoring type.
type BackendServerMonitoring struct {
	BackendServers []*BackendServer `mapstructure:"backend_servers" validate:"required,dive"`

	ConnectTimeout  time.Duration `mapstructure:"connect_timeout" validate:"omitempty,gt=0,max=1m"`
	TLSTimeout      time.Duration `mapstructure:"tls_timeout" validate:"omitempty,gt=0,max=1m"`
	DeepTimeout     time.Duration `mapstructure:"deep_timeout" validate:"omitempty,gt=0,max=5m"`
	ConnectInterval time.Duration `mapstructure:"connect_interval" validate:"omitempty,gt=0,max=24h"`
	DeepInterval    time.Duration `mapstructure:"deep_interval" validate:"omitempty,gt=0,max=24h"`

	FailureThreshold  int `mapstructure:"failure_threshold" validate:"omitempty,min=1,max=100"`
	RecoveryThreshold int `mapstructure:"recovery_threshold" validate:"omitempty,min=1,max=100"`
}

func (n *BackendServerMonitoring) String() string {
	if n == nil {
		return "BackendServerMonitoring: <nil>"
	}

	return fmt.Sprintf("BackendServerMonitoring: [%v]", n.BackendServers)
}

// GetBackendServers retrieves the list of backend servers from the BackendServerMonitoring.
// Returns an empty slice if the BackendServerMonitoring is nil.
func (n *BackendServerMonitoring) GetBackendServers() []*BackendServer {
	if n == nil {
		return []*BackendServer{}
	}

	return n.BackendServers
}

// GetConnectTimeout returns the TCP connect timeout used by backend health checks.
func (n *BackendServerMonitoring) GetConnectTimeout() time.Duration {
	if n == nil || n.ConnectTimeout <= 0 {
		return defaultBackendHealthCheckTimeout
	}

	return n.ConnectTimeout
}

// GetTLSTimeout returns the TLS handshake timeout used by backend health checks.
func (n *BackendServerMonitoring) GetTLSTimeout() time.Duration {
	if n == nil || n.TLSTimeout <= 0 {
		return defaultBackendHealthCheckTimeout
	}

	return n.TLSTimeout
}

// GetDeepTimeout returns the protocol-level deep check timeout.
func (n *BackendServerMonitoring) GetDeepTimeout() time.Duration {
	if n == nil || n.DeepTimeout <= 0 {
		return defaultBackendHealthCheckTimeout
	}

	return n.DeepTimeout
}

// GetConnectInterval returns the interval for connect-only backend probes.
func (n *BackendServerMonitoring) GetConnectInterval(fallback time.Duration) time.Duration {
	if n != nil && n.ConnectInterval > 0 {
		return n.ConnectInterval
	}

	if fallback > 0 {
		return fallback
	}

	return defaultBackendHealthCheckInterval
}

// GetDeepInterval returns the interval for protocol-level deep backend probes.
func (n *BackendServerMonitoring) GetDeepInterval(fallback time.Duration) time.Duration {
	if n != nil && n.DeepInterval > 0 {
		return n.DeepInterval
	}

	if fallback > 0 {
		return fallback
	}

	return n.GetConnectInterval(0)
}

// GetFailureThreshold returns how many consecutive probe failures are required before a server is marked unhealthy.
func (n *BackendServerMonitoring) GetFailureThreshold() int {
	if n == nil || n.FailureThreshold <= 0 {
		return defaultBackendHealthCheckFailureThreshold
	}

	return n.FailureThreshold
}

// GetRecoveryThreshold returns how many consecutive probe successes are required before a server recovers.
func (n *BackendServerMonitoring) GetRecoveryThreshold() int {
	if n == nil || n.RecoveryThreshold <= 0 {
		return defaultBackendHealthCheckRecoveryThreshold
	}

	return n.RecoveryThreshold
}

// GetServerConnectTimeout returns the target-specific connect timeout or the monitoring default.
func (n *BackendServerMonitoring) GetServerConnectTimeout(server *BackendServer) time.Duration {
	if server != nil && server.ConnectTimeout > 0 {
		return server.ConnectTimeout
	}

	return n.GetConnectTimeout()
}

// GetServerTLSTimeout returns the target-specific TLS timeout or the monitoring default.
func (n *BackendServerMonitoring) GetServerTLSTimeout(server *BackendServer) time.Duration {
	if server != nil && server.TLSTimeout > 0 {
		return server.TLSTimeout
	}

	return n.GetTLSTimeout()
}

// GetServerDeepTimeout returns the target-specific deep-check timeout or the monitoring default.
func (n *BackendServerMonitoring) GetServerDeepTimeout(server *BackendServer) time.Duration {
	if server != nil && server.DeepTimeout > 0 {
		return server.DeepTimeout
	}

	return n.GetDeepTimeout()
}
