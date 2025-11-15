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

import "fmt"

type RelayDomainsSection struct {
	SoftWhitelist `mapstructure:"soft_whitelist"`
	StaticDomains []string `mapstructure:"static" validate:"required,dive,hostname_rfc1123_with_opt_trailing_dot"`
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

type BackendServer struct {
	Protocol      string `mapstructure:"protocol" validate:"required,oneof=imap pop3 lmtp smtp sieve http"`
	Host          string `mapstructure:"host" validate:"required,hostname_rfc1123_with_opt_trailing_dot|ip"`
	DeepCheck     bool   `mapstructure:"deep_check"`
	RequestURI    string `mapstructure:"request_uri" validate:"omitempty,url_encoded"`
	TestUsername  string `mapstructure:"test_username" validate:"omitempty,excludesall= "`
	TestPassword  string `mapstructure:"test_password" validate:"omitempty,excludesall= "`
	Port          int    `mapstructure:"port" validate:"omitempty,min=1,max=65535"`
	TLS           bool   `mapstructure:"tls"`
	TLSSkipVerify bool   `mapstructure:"tls_skip_verify"`
	HAProxyV2     bool   `mapstructure:"haproxy_v2"`
}

func (n *BackendServer) String() string {
	if n == nil {
		return "BackendServer: <nil>"
	}

	return fmt.Sprintf("BackendServer: {Protocol: %s, Host: %s, RequestURI: %s, TestUsername: %s, TestPassword: <hidden>, Port: %d, TLS: %t, TLSSkipVerify: %t, HAProxyV2: %t}",
		n.Protocol, n.Host, n.RequestURI, n.TestUsername, n.Port, n.TLS, n.TLSSkipVerify, n.HAProxyV2)
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

type BackendServerMonitoring struct {
	BackendServers []*BackendServer `mapstructure:"backend_servers" validate:"required,dive"`
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
