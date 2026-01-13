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

func LoaderModSoftAllow(cfg config.File) lua.LGFunction {
	return func(L *lua.LState) int {
		// Register the module functions
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnSoftWhitelistSet: func(L *lua.LState) int {
				var provider config.SoftWhitelistProvider

				username := L.CheckString(1)
				network := L.CheckString(2)
				feature := L.CheckString(3)

				switch feature {
				case definitions.FeatureBruteForce:
					if !cfg.GetBruteForce().HasSoftWhitelist() {
						cfg.GetBruteForce().SoftWhitelist = config.NewSoftWhitelist()
					}

					provider = cfg.GetBruteForce()
				case definitions.FeatureRelayDomains:
					if !cfg.GetRelayDomains().HasSoftWhitelist() {
						cfg.GetRelayDomains().SoftWhitelist = config.NewSoftWhitelist()
					}

					provider = cfg.GetRelayDomains()
				case definitions.FeatureRBL:
					if !cfg.GetRBLs().HasSoftWhitelist() {
						cfg.GetRBLs().SoftWhitelist = config.NewSoftWhitelist()
					}

					provider = cfg.GetRBLs()
				default:
					L.Push(lua.LString("invalid feature category"))

					return 1
				}

				provider.Set(username, network)

				L.Push(lua.LNil)

				return 1
			},
			definitions.LuaFnSoftWhitelistGet: func(L *lua.LState) int {
				username := L.CheckString(1)
				feature := L.CheckString(2)

				var provider config.SoftWhitelistProvider

				switch feature {
				case definitions.FeatureBruteForce:
					provider = cfg.GetBruteForce()
				case definitions.FeatureRelayDomains:
					provider = cfg.GetRelayDomains()
				case definitions.FeatureRBL:
					provider = cfg.GetRBLs()
				default:
					L.Push(L.NewTable())

					return 1
				}

				var networks []string
				if provider.HasSoftWhitelist() {
					networks = provider.Get(username)
				}

				resultTable := L.NewTable()

				for i, network := range networks {
					L.RawSetInt(resultTable, i+1, lua.LString(network))
				}

				L.Push(resultTable)

				return 1
			},
			definitions.LuaFnSoftWhitelistDelete: func(L *lua.LState) int {
				var provider config.SoftWhitelistProvider

				username := L.CheckString(1)
				network := L.CheckString(2)
				feature := L.CheckString(3)

				switch feature {
				case definitions.FeatureBruteForce:
					provider = cfg.GetBruteForce()
				case definitions.FeatureRelayDomains:
					provider = cfg.GetRelayDomains()
				case definitions.FeatureRBL:
					provider = cfg.GetRBLs()
				default:
					return 0
				}

				if provider.HasSoftWhitelist() {
					provider.Delete(username, network)
				}

				return 0
			},
		})

		L.Push(mod)

		return 1
	}
}
