package lualib

import (
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/yuin/gopher-lua"
)

func softWhitelistSet(L *lua.LState) int {
	var provider config.SoftWhitelistProvider

	username := L.CheckString(1)
	network := L.CheckString(2)
	feature := L.CheckString(3)

	switch feature {
	case definitions.FeatureBruteForce:
		if !config.GetFile().BruteForce.HasSoftWhitelist() {
			config.GetFile().BruteForce.SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = config.GetFile().BruteForce
	case definitions.FeatureRelayDomains:
		if !config.GetFile().RelayDomains.HasSoftWhitelist() {
			config.GetFile().RelayDomains.SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = config.GetFile().RelayDomains
	case definitions.FeatureRBL:
		if !config.GetFile().RBLs.HasSoftWhitelist() {
			config.GetFile().RBLs.SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = config.GetFile().RBLs
	default:
		L.Push(lua.LString("invalid feature category"))

		return 1
	}

	provider.Set(username, network)

	L.Push(lua.LNil)

	return 1
}

// getNetworks retrieves a list of networks associated with a username for a specified feature if a soft whitelist exists.
// The feature can be one of "brute_force", "relay_domains", or "rbl". Returns nil if the feature is not recognized or no whitelist exists.
func getNetworks(username, feature string) []string {
	var provider config.SoftWhitelistProvider

	switch feature {
	case definitions.FeatureBruteForce:
		provider = config.GetFile().BruteForce
	case definitions.FeatureRelayDomains:
		provider = config.GetFile().RelayDomains
	case definitions.FeatureRBL:
		provider = config.GetFile().RBLs
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
		provider = config.GetFile().BruteForce
	case definitions.FeatureRelayDomains:
		provider = config.GetFile().RelayDomains
	case definitions.FeatureRBL:
		provider = config.GetFile().RBLs
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
