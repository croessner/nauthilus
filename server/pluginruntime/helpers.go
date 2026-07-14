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

package pluginruntime

import (
	"os"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/helpers"
	"github.com/croessner/nauthilus/v3/server/config"
)

var _ pluginapi.DeterministicHelpers = (*deterministicHelperFacade)(nil)

// HelperOptions configures deterministic helper behavior for one host.
type HelperOptions struct {
	AccountTag          helpers.AccountTagOptions
	LuaIPv4CIDR         int
	LuaIPv6CIDR         int
	RWPIPv6CIDR         int
	TolerationsIPv6CIDR int
}

type deterministicHelperFacade struct {
	options HelperOptions
}

// HelperOptionsFromConfig derives helper options from the loaded server configuration and Lua-compatible environment knobs.
func HelperOptionsFromConfig(cfg config.File) HelperOptions {
	options := HelperOptions{
		AccountTag: helpers.AccountTagOptions{
			UseHashTags:   envBool("USE_KEY_HASHTAGS", true),
			HashTagPrefix: envString("KEY_HASHTAG_PREFIX", "acm-"),
		},
	}

	if cfg == nil {
		return options
	}

	if bruteForce := cfg.GetBruteForce(); bruteForce != nil {
		options.RWPIPv6CIDR = int(bruteForce.GetRWPIPv6CIDR())
		options.TolerationsIPv6CIDR = int(bruteForce.GetTolerationsIPv6CIDR())
	}

	if luaSection := cfg.GetLua(); luaSection != nil {
		if luaConf, ok := luaSection.GetConfig().(*config.LuaConf); ok && luaConf != nil {
			options.LuaIPv4CIDR = int(luaConf.GetLuaIPv4CIDR())
			options.LuaIPv6CIDR = int(luaConf.GetLuaIPv6CIDR())
		}
	}

	return options
}

// NewDeterministicHelperFacade creates a helper facade for native plugin ports.
func NewDeterministicHelperFacade(options HelperOptions) pluginapi.DeterministicHelpers {
	if options.AccountTag == (helpers.AccountTagOptions{}) {
		options.AccountTag = helpers.DefaultAccountTagOptions()
	}

	return &deterministicHelperFacade{options: options}
}

// AccountTag returns a Redis Cluster hash tag for account-scoped keys.
func (h *deterministicHelperFacade) AccountTag(username string) string {
	if h == nil {
		return helpers.AccountTag(username, helpers.DefaultAccountTagOptions())
	}

	return helpers.AccountTag(username, h.options.AccountTag)
}

// CountryName returns the Lua-compatible display name for a country code.
func (h *deterministicHelperFacade) CountryName(countryCode string) string {
	return helpers.CountryName(countryCode)
}

// ScopedIP returns a stable address or network identifier for a helper context.
func (h *deterministicHelperFacade) ScopedIP(contextName string, ip string) string {
	if h == nil {
		return helpers.ScopedIP(ip, helpers.IPScopingOptions{})
	}

	return helpers.ScopedIP(ip, h.scopingOptions(contextName))
}

// IsRoutableIP reports whether ip is suitable for public routing decisions.
func (h *deterministicHelperFacade) IsRoutableIP(ip string) bool {
	return helpers.IsRoutableIP(ip)
}

// scopingOptions maps Lua/native helper contexts to configured scoping rules.
func (h *deterministicHelperFacade) scopingOptions(contextName string) helpers.IPScopingOptions {
	switch contextName {
	case "rwp", "repeating_wrong_password":
		return helpers.IPScopingOptions{IPv6CIDR: h.options.RWPIPv6CIDR}
	case "tolerations":
		return helpers.IPScopingOptions{IPv6CIDR: h.options.TolerationsIPv6CIDR}
	default:
		return helpers.IPScopingOptions{
			IPv4CIDR: h.options.LuaIPv4CIDR,
			IPv6CIDR: h.options.LuaIPv6CIDR,
		}
	}
}

// envBool reads a Lua-compatible truthy/falsey environment knob.
func envBool(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}

	switch strings.ToLower(value) {
	case "", "0", "false":
		return false
	default:
		return true
	}
}

// envString returns the environment value or fallback when unset.
func envString(name string, fallback string) string {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return fallback
	}

	return value
}
