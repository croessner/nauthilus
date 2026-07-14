// Copyright (C) 2026 Christian Roessner
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

// Package helpers contains deterministic, non-secret helpers for native plugins.
package helpers

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"

	"github.com/biter777/countries"
)

const (
	defaultAccountHashTagPrefix = "acm-"
	unknownCountryName          = "Unknown"
)

// AccountTagOptions controls Redis Cluster hash-tag generation for account keys.
type AccountTagOptions struct {
	HashTagPrefix string
	UseHashTags   bool
}

// IPScopingOptions controls deterministic IP network scoping.
type IPScopingOptions struct {
	IPv4CIDR int
	IPv6CIDR int
}

// DefaultAccountTagOptions returns the Lua-compatible account hash-tag defaults.
func DefaultAccountTagOptions() AccountTagOptions {
	return AccountTagOptions{
		HashTagPrefix: defaultAccountHashTagPrefix,
		UseHashTags:   true,
	}
}

// AccountTag returns a Redis Cluster hash-tag for account-scoped keys.
func AccountTag(username string, options AccountTagOptions) string {
	if username == "" || !options.UseHashTags {
		return ""
	}

	prefix := options.HashTagPrefix
	if prefix == "" {
		prefix = defaultAccountHashTagPrefix
	}

	sum := md5.Sum([]byte(username))

	return "{" + prefix + hex.EncodeToString(sum[:]) + "}"
}

// CountryName returns the Lua-compatible display name for a country code.
func CountryName(countryCode string) string {
	country := countries.ByName(countryCode)
	if country == countries.Unknown {
		return unknownCountryName
	}

	return country.String()
}

// ScopedIP returns ip or a configured network identifier for stable cache and Redis keys.
func ScopedIP(ip string, options IPScopingOptions) string {
	if ip == "" {
		return ip
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}

	if parsed.To4() != nil {
		return scopedNetwork(ip, options.IPv4CIDR, 32)
	}

	return scopedNetwork(ip, options.IPv6CIDR, 128)
}

// IsRoutableIP reports whether ip is suitable for public internet routing decisions.
func IsRoutableIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsPrivate() {
		return false
	}

	for _, prefix := range nonRoutablePrefixes() {
		if prefix.Contains(addr) {
			return false
		}
	}

	return true
}

// scopedNetwork applies cidr when it is inside the address family's valid mask range.
func scopedNetwork(ip string, cidr int, maxCIDR int) string {
	if cidr <= 0 || cidr > maxCIDR {
		return ip
	}

	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, cidr))
	if err != nil || network == nil {
		return ip
	}

	return network.String()
}

// nonRoutablePrefixes lists routability exclusions not covered by netip helpers.
func nonRoutablePrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("fc00::/7"),
	}
}
