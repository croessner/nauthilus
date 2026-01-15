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
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	lua "github.com/yuin/gopher-lua"
)

// SoftAllowManager manages soft whitelist operations for Lua.
type SoftAllowManager struct {
	*BaseManager
}

// NewSoftAllowManager creates a new SoftAllowManager.
func NewSoftAllowManager(ctx context.Context, cfg config.File, logger *slog.Logger) *SoftAllowManager {
	return &SoftAllowManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
	}
}

// SoftWhitelistSet sets a soft whitelist entry.
func (m *SoftAllowManager) SoftWhitelistSet(L *lua.LState) int {
	stack := luastack.NewManager(L)

	var provider config.SoftWhitelistProvider

	username := stack.CheckString(1)
	network := stack.CheckString(2)
	feature := stack.CheckString(3)

	switch feature {
	case definitions.FeatureBruteForce:
		if !m.Cfg.GetBruteForce().HasSoftWhitelist() {
			m.Cfg.GetBruteForce().SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = m.Cfg.GetBruteForce()
	case definitions.FeatureRelayDomains:
		if !m.Cfg.GetRelayDomains().HasSoftWhitelist() {
			m.Cfg.GetRelayDomains().SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = m.Cfg.GetRelayDomains()
	case definitions.FeatureRBL:
		if !m.Cfg.GetRBLs().HasSoftWhitelist() {
			m.Cfg.GetRBLs().SoftWhitelist = config.NewSoftWhitelist()
		}

		provider = m.Cfg.GetRBLs()
	default:
		return stack.PushResult(lua.LString("invalid feature category"))
	}

	provider.Set(username, network)

	return stack.PushResults(lua.LString("OK"), lua.LNil)
}

// SoftWhitelistGet retrieves soft whitelist entries.
func (m *SoftAllowManager) SoftWhitelistGet(L *lua.LState) int {
	stack := luastack.NewManager(L)
	username := stack.CheckString(1)
	feature := stack.CheckString(2)

	var provider config.SoftWhitelistProvider

	switch feature {
	case definitions.FeatureBruteForce:
		provider = m.Cfg.GetBruteForce()
	case definitions.FeatureRelayDomains:
		provider = m.Cfg.GetRelayDomains()
	case definitions.FeatureRBL:
		provider = m.Cfg.GetRBLs()
	default:
		return stack.PushResults(L.NewTable(), lua.LNil)
	}

	var networks []string
	if provider.HasSoftWhitelist() {
		networks = provider.Get(username)
	}

	resultTable := L.NewTable()

	for i, network := range networks {
		L.RawSetInt(resultTable, i+1, lua.LString(network))
	}

	return stack.PushResults(resultTable, lua.LNil)
}

// SoftWhitelistDelete removes a soft whitelist entry.
func (m *SoftAllowManager) SoftWhitelistDelete(L *lua.LState) int {
	stack := luastack.NewManager(L)

	var provider config.SoftWhitelistProvider

	username := stack.CheckString(1)
	network := stack.CheckString(2)
	feature := stack.CheckString(3)

	switch feature {
	case definitions.FeatureBruteForce:
		provider = m.Cfg.GetBruteForce()
	case definitions.FeatureRelayDomains:
		provider = m.Cfg.GetRelayDomains()
	case definitions.FeatureRBL:
		provider = m.Cfg.GetRBLs()
	default:
		return 0
	}

	if provider.HasSoftWhitelist() {
		provider.Delete(username, network)
	}

	return stack.PushResults(lua.LString("OK"), lua.LNil)
}

// LoaderModSoftAllow initializes and loads the soft allow module for Lua.
func LoaderModSoftAllow(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewSoftAllowManager(ctx, cfg, logger)

		// Register the module functions
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnSoftWhitelistSet:    manager.SoftWhitelistSet,
			definitions.LuaFnSoftWhitelistGet:    manager.SoftWhitelistGet,
			definitions.LuaFnSoftWhitelistDelete: manager.SoftWhitelistDelete,
		})

		return stack.PushResult(mod)
	}
}
