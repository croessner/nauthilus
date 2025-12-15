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

package lualib

import (
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// softWhitelistSet manages soft whitelist entries by adding a network for a username based on a specified feature category.
// It initializes the soft whitelist if it does not exist for the given feature and returns nil upon success.
func softWhitelistSet(L *lua.LState) int {
	var provider config.SoftWhitelistProvider

	username := L.CheckString(1)
	network := L.CheckString(2)
	feature := L.CheckString(3)

	switch feature {
	case definitions.FeatureBruteForce:
		if !config.GetFile().GetBruteForce().HasSoftWhitelist() {
			config.GetFile().GetBruteForce().SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = config.GetFile().GetBruteForce()
	case definitions.FeatureRelayDomains:
		if !config.GetFile().GetRelayDomains().HasSoftWhitelist() {
			config.GetFile().GetRelayDomains().SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = config.GetFile().GetRelayDomains()
	case definitions.FeatureRBL:
		if !config.GetFile().GetRBLs().HasSoftWhitelist() {
			config.GetFile().GetRBLs().SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = config.GetFile().GetRBLs()
	default:
		L.Push(lua.LString("invalid feature category"))

		return 1
	}

	provider.Set(username, network)

	L.Push(lua.LNil)

	return 1
}

// getNetworks retrieves a list of networks associated with a username for a specific feature using a soft whitelist provider.
// It supports features like brute force protection, relay domains, and RBL.
// The function returns nil if no networks are found or if the feature is undefined.
func getNetworks(username, feature string) []string {
	var provider config.SoftWhitelistProvider

	switch feature {
	case definitions.FeatureBruteForce:
		provider = config.GetFile().GetBruteForce()
	case definitions.FeatureRelayDomains:
		provider = config.GetFile().GetRelayDomains()
	case definitions.FeatureRBL:
		provider = config.GetFile().GetRBLs()
	default:
		return nil
	}

	if provider.HasSoftWhitelist() {
		return provider.Get(username)
	}

	return nil
}

// softWhitelistGet retrieves networks associated with a user's soft whitelist for a given feature and returns their count.
func softWhitelistGet(L *lua.LState) int {
	username := L.CheckString(1)
	feature := L.CheckString(2)
	networks := getNetworks(username, feature)

	resultTable := L.NewTable()

	for i, network := range networks {
		L.RawSetInt(resultTable, i+1, lua.LString(network))
	}

	L.Push(resultTable)

	return 1
}

// softWhitelistDelete removes a network from a user's soft whitelist for a specified feature, given username and network.
// It applies to features such as brute force protection, relay domains, or RBLs by accessing appropriate configurations.
func softWhitelistDelete(L *lua.LState) int {
	var provider config.SoftWhitelistProvider

	username := L.CheckString(1)
	network := L.CheckString(2)
	feature := L.CheckString(3)

	switch feature {
	case definitions.FeatureBruteForce:
		provider = config.GetFile().GetBruteForce()
	case definitions.FeatureRelayDomains:
		provider = config.GetFile().GetRelayDomains()
	case definitions.FeatureRBL:
		provider = config.GetFile().GetRBLs()
	default:
		return 0
	}

	if provider.HasSoftWhitelist() {
		provider.Delete(username, network)
	}

	return 0
}

// exportModSoftWhitelist is a mapping of Lua function names related to soft whitelisting to their corresponding Go implementations.
var exportModSoftWhitelist = map[string]lua.LGFunction{
	definitions.LuaFnSoftWhitelistSet:    softWhitelistSet,
	definitions.LuaFnSoftWhitelistGet:    softWhitelistGet,
	definitions.LuaFnSoftWhitelistDelete: softWhitelistDelete,
}

// LoaderModSoftWhitelist registers and exposes the soft whitelist module functions to the provided Lua state.
func LoaderModSoftWhitelist(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportModSoftWhitelist)

	L.Push(mod)

	return 1
}
