// Copyright (C) 2025 Christian Rößner
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

package util

import (
	"net"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/server/config"
)

// DNSResolverPeerFromAddress normalizes a DNS resolver address (optionally including scheme and port)
// and returns host/port information suitable for tracing attributes.
//
// If the address points to loopback (e.g. 127.0.0.1, ::1, localhost), ok is false.
func DNSResolverPeerFromAddress(addr string) (host string, port int, ok bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, false
	}

	host = addr
	port = 53

	if h, p, err := net.SplitHostPort(addr); err == nil {
		host = h

		if p != "" {
			// Use ParseInt with bitSize 16 to avoid integer overflow; ports are 0-65535
			if pn, convErr := strconv.ParseInt(p, 10, 16); convErr == nil && pn >= 0 && pn <= 65535 {
				port = int(pn)
			}
		}
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimSpace(host)
	if host == "" {
		return "", 0, false
	}

	if strings.EqualFold(host, "localhost") {
		return "", 0, false
	}

	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "", 0, false
	}

	return host, port, true
}

// DNSResolverPeer returns the configured resolver peer (host/port) for tracing.
// For loopback/localhost resolvers ok is false to avoid creating a misleading remote node
// in downstream service graphs.
func DNSResolverPeer(cfg config.File) (host string, port int, ok bool) {
	return DNSResolverPeerFromAddress(cfg.GetServer().GetDNS().GetResolver())
}
