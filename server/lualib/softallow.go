package lualib

import (
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/yuin/gopher-lua"
)

// SoftWhitelistProvider defines the methods for managing a soft whitelist of networks associated with usernames.
// The interface allows checking the existence of a whitelist, retrieving, setting, and deleting networks.
type SoftWhitelistProvider interface {
	// HasSoftWhitelist checks if there is at least one entry in the soft whitelist, returning true if it exists, otherwise false.
	HasSoftWhitelist() bool

	// Get retrieves the list of networks associated with the given username from the soft whitelist.
	Get(username string) []string

	// Set adds a specified network to a user's whitelist if the network is valid and the username is not empty.
	Set(username, network string)

	// Delete removes a specified network from the user's soft whitelist identified by the provided username.
	Delete(username, network string)
}

// softWhitelistSet sets a network for a user in the soft whitelist based on the specified feature category.
func softWhitelistSet(L *lua.LState) int {
	var provider SoftWhitelistProvider

	username := L.CheckString(1)
	network := L.CheckString(2)
	feature := L.CheckString(3)

	switch feature {
	case definitions.FeatureBruteForce:
		provider = config.LoadableConfig.BruteForce
	case definitions.FeatureRelayDomains:
		provider = config.LoadableConfig.RelayDomains
	case definitions.FeatureRBL:
		provider = config.LoadableConfig.RBLs
	default:
		return 0
	}

	if !provider.HasSoftWhitelist() {
		provider = config.NewSoftWhitelist()
	}

	provider.Set(username, network)

	return 0
}

// getNetworks retrieves a list of networks associated with a username for a specified feature if a soft whitelist exists.
// The feature can be one of "brute_force", "relay_domains", or "rbl". Returns nil if the feature is not recognized or no whitelist exists.
func getNetworks(username, feature string) []string {
	var provider SoftWhitelistProvider

	switch feature {
	case definitions.FeatureBruteForce:
		provider = config.LoadableConfig.BruteForce
	case definitions.FeatureRelayDomains:
		provider = config.LoadableConfig.RelayDomains
	case definitions.FeatureRBL:
		provider = config.LoadableConfig.RBLs
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

	for _, network := range networks {
		L.Push(lua.LString(network))
	}

	return len(networks)
}

// softWhitelistDelete removes a network from a user's soft whitelist for a specified feature, given username and network.
// It applies to features such as brute force protection, relay domains, or RBLs by accessing appropriate configurations.
func softWhitelistDelete(L *lua.LState) int {
	var provider SoftWhitelistProvider

	username := L.CheckString(1)
	network := L.CheckString(2)
	feature := L.CheckString(3)

	switch feature {
	case definitions.FeatureBruteForce:
		provider = config.LoadableConfig.BruteForce
	case definitions.FeatureRelayDomains:
		provider = config.LoadableConfig.RelayDomains
	case definitions.FeatureRBL:
		provider = config.LoadableConfig.RBLs
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
