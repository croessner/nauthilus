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
	StaticDomains []string `mapstructure:"static"`
}

func (r *RelayDomainsSection) String() string {
	if r == nil {
		return "RelayDomainsSection: <nil>"
	}

	return fmt.Sprintf("RelayDomainsSection: {Static[%+v]}", r.StaticDomains)
}

type BackendServer struct {
	Protocol  string `mapstructure:"protocol"`
	IP        string `mapstructure:"ip"`
	Port      int    `mapstructure:"port"`
	TLS       bool   `mapstructure:"tls"`
	HAProxyV2 bool   `mapstructure:"haproxy_v2"`
}

func (n *BackendServer) String() string {
	if n == nil {
		return "BackendServer: <nil>"
	}

	return fmt.Sprintf("BackendServers: {Protocol: %s, IP: %s, Port: %d}", n.Protocol, n.IP, n.Port)
}

type BackendServerMonitoring struct {
	BackendServers []*BackendServer `mapstructure:"backend_servers"`
}

func (n *BackendServerMonitoring) String() string {
	if n == nil {
		return "BackendServerMonitoring: <nil>"
	}

	return fmt.Sprintf("BackendServerMonitoring: [%v]", n.BackendServers)
}
