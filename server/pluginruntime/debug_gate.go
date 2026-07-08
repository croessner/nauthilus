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
	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

// pluginDebugGate evaluates native plugin debug selectors against the active config.
type pluginDebugGate struct {
	cfg      config.File
	registry debugSelectorLookup
}

type debugSelectorLookup interface {
	HasDebugSelector(string) bool
}

// enabled reports whether a plugin debug record should be emitted and which selector describes it.
func (g pluginDebugGate) enabled(moduleName string, localName string) (string, bool) {
	if g.cfg == nil || moduleName == "" {
		return "", false
	}

	logCfg := g.cfg.GetServer().GetLog()
	if logCfg.GetLogLevel() < definitions.LogLevelDebug {
		return "", false
	}

	moduleSelector, err := pluginapi.PluginDebugModuleSelector(moduleName)
	if err != nil {
		return "", false
	}

	localSelector := g.registeredLocalSelector(moduleName, localName)
	recordSelector := moduleSelector

	if localSelector != "" {
		recordSelector = localSelector
	}

	for _, module := range logCfg.GetDebugModules() {
		switch module.Get() {
		case definitions.DbgAllName, extensionPointPlugin, moduleSelector:
			return recordSelector, true
		case localSelector:
			if localSelector != "" {
				return recordSelector, true
			}
		}

		if module.GetModule() == definitions.DbgAll {
			return recordSelector, true
		}
	}

	return "", false
}

// registeredLocalSelector returns a local selector only when the registry declared it.
func (g pluginDebugGate) registeredLocalSelector(moduleName string, localName string) string {
	if localName == "" || g.registry == nil {
		return ""
	}

	selector, err := pluginapi.PluginDebugSubmoduleSelector(moduleName, localName)
	if err != nil {
		return ""
	}

	if !g.registry.HasDebugSelector(selector) {
		return ""
	}

	return selector
}

// setRegistry updates the selector lookup used by existing module-bound hosts.
func (g *pluginDebugGate) setRegistry(registry *pluginregistry.Registry) {
	if g == nil {
		return
	}

	g.registry = registry
}
