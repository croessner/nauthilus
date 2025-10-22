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

package ipscoper

import (
	"fmt"
	"net"

	"github.com/croessner/nauthilus/server/config"
)

// ScopeContext identifies the feature/context in which IP scoping is applied.
// It allows reusing the same mechanism for multiple features (e.g., repeating-wrong-password, tolerations).
// Keep values stable as they may be used in logs.
type ScopeContext string

const (
	// ScopeRepeatingWrongPassword is used when operating on password-history keys and totals.
	ScopeRepeatingWrongPassword ScopeContext = "repeating_wrong_password"
	// ScopeTolerations is used when operating on tolerations keys.
	ScopeTolerations ScopeContext = "tolerations"
	// ScopeLuaGeneric is used for generic Lua-driven features (metrics, dedup) outside brute-force.
	ScopeLuaGeneric ScopeContext = "lua_generic"
)

// IPScoper abstracts normalization of IP addresses into a stable identifier for storage/lookup.
// Different contexts may apply different scoping rules.
type IPScoper interface {
	// Scope returns the identifier to use for the given context. The return value can be the plain IP
	// or a network string (e.g., 2001:db8::/64) depending on configuration and IP version.
	Scope(ctx ScopeContext, ip string) string
}

// configurableIPScoper implements IPScoper based on configuration values.
// Currently supports IPv6 CIDR scoping for multiple contexts.
type configurableIPScoper struct{}

// NewIPScoper returns a new IPScoper instance without touching configuration at init time.
// Configuration is consulted lazily during Scope calls to avoid early GetFile() usage in package init.
func NewIPScoper() IPScoper {
	return &configurableIPScoper{}
}

// cidrFor returns the configured IPv6 CIDR for the given context.
// This removes the need for duplicated switch-case logic in Scope and avoids early config access.
func (s *configurableIPScoper) cidrFor(ctx ScopeContext) uint {
	bf := config.GetFile().GetBruteForce()
	luaSection := config.GetFile().GetLua()

	var luaConf *config.LuaConf

	if luaSection != nil {
		if c, ok := luaSection.GetConfig().(*config.LuaConf); ok {
			luaConf = c
		}
	}

	switch ctx {
	case ScopeRepeatingWrongPassword:
		if bf != nil {
			return bf.GetRWPIPv6CIDR()
		}
	case ScopeTolerations:
		if bf != nil {
			return bf.GetTolerationsIPv6CIDR()
		}

	case ScopeLuaGeneric:
		if luaConf != nil {
			return luaConf.GetLuaIPv6CIDR()
		}
	}

	return 0
}

// v4cidrFor returns the configured IPv4 CIDR for the given context (currently only Lua generic).
func (s *configurableIPScoper) v4cidrFor(ctx ScopeContext) uint {
	luaSection := config.GetFile().GetLua()
	if luaSection == nil {
		return 0
	}

	if c, ok := luaSection.GetConfig().(*config.LuaConf); ok && c != nil {
		if ctx == ScopeLuaGeneric {
			return c.GetLuaIPv4CIDR()
		}
	}

	return 0
}

// Scope processes the given IP based on the context and configuration, applying scoping rules like IPv6/IPv4 CIDR, if applicable.
func (s *configurableIPScoper) Scope(ctx ScopeContext, ip string) string {
	if ip == "" {
		return ip
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}

	isIPv4 := parsed.To4() != nil
	isIPv6 := !isIPv4

	if isIPv6 {
		if cidr := s.cidrFor(ctx); cidr > 0 && cidr <= 128 {
			if _, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, cidr)); err == nil && network != nil {
				return network.String()
			}
		}
	} else {
		if v4cidr := s.v4cidrFor(ctx); v4cidr > 0 && v4cidr <= 32 {
			if _, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, v4cidr)); err == nil && network != nil {
				return network.String()
			}
		}
	}

	// Default: return the exact IP
	return ip
}
