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
	StaticDomains []string `mapstructure:"static" validate:"required,dive,hostname"`
}

func (r *RelayDomainsSection) String() string {
	if r == nil {
		return "RelayDomainsSection: <nil>"
	}

	return fmt.Sprintf("RelayDomainsSection: {Static[%+v]}", r.StaticDomains)
}

type BackendServer struct {
	Protocol      string `mapstructure:"protocol" validate:"required,oneof=imap pop3 lmtp smtp sieve http"`
	Host          string `mapstructure:"host" validate:"required,hostname|ip"`
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

type BackendServerMonitoring struct {
	BackendServers []*BackendServer `mapstructure:"backend_servers" validate:"required,dive"`
}

func (n *BackendServerMonitoring) String() string {
	if n == nil {
		return "BackendServerMonitoring: <nil>"
	}

	return fmt.Sprintf("BackendServerMonitoring: [%v]", n.BackendServers)
}
