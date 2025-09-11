// Copyright (C) 2020-2025
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

package bruteforce

import (
	"fmt"
	"net"
	"strings"

	"github.com/croessner/nauthilus/server/config"
)

// ScopeContext identifies the feature/context in which IP scoping is applied.
// It allows reusing the same mechanism for multiple features (e.g., repeating-wrong-password, tolerations).
// Keep values stable as they may be used in logs.
type ScopeContext string

const (
	// ScopeRepeatingWrongPassword is used when operating on password-history keys and totals.
	ScopeRepeatingWrongPassword ScopeContext = "repeating_wrong_password"
)

// IPScoper abstracts normalization of IP addresses into a stable identifier for storage/lookup.
// Different contexts may apply different scoping rules.
type IPScoper interface {
	// Scope returns the identifier to use for the given context. The return value can be the plain IP
	// or a network string (e.g., 2001:db8::/64) depending on configuration and IP version.
	Scope(ctx ScopeContext, ip string) string
}

// configurableIPScoper implements IPScoper based on configuration values.
// Currently supports IPv6 CIDR scoping for the repeating-wrong-password context.
type configurableIPScoper struct {
	bf *config.BruteForceSection
}

func newIPScoper() IPScoper {
	return &configurableIPScoper{bf: config.GetFile().GetBruteForce()}
}

// Scope processes the given IP based on the context and configuration, applying scoping rules like IPv6 CIDR, if applicable.
func (s *configurableIPScoper) Scope(ctx ScopeContext, ip string) string {
	if ip == "" {
		return ip
	}

	isIPv6 := strings.Contains(ip, ":") && net.ParseIP(ip) != nil && net.ParseIP(ip).To4() == nil

	switch ctx {
	case ScopeRepeatingWrongPassword:
		if isIPv6 && s != nil && s.bf != nil {
			if cidr := s.bf.GetRWPIPv6CIDR(); cidr > 0 && cidr <= 128 {
				if _, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, cidr)); err == nil && network != nil {
					return network.String()
				}
			}
		}
	}

	// Default: return the exact IP
	return ip
}
