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

package pluginloader

import (
	"errors"
	"fmt"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
)

var (
	// ErrPluginDebugSelectorMissing reports an exact debug selector without a registered module.
	ErrPluginDebugSelectorMissing = errors.New("plugin debug selector is not registered")
)

// ValidatePluginDebugSelectors verifies exact plugin debug selectors after module registration.
func ValidatePluginDebugSelectors(cfg config.File, state *State) error {
	if cfg == nil || cfg.GetServer() == nil {
		return nil
	}

	registry := stateRegistry(state)

	for _, module := range cfg.GetServer().GetLog().GetDebugModules() {
		selector := module.Get()
		if !pluginapi.IsPluginDebugSelector(selector) || selector == "plugin" {
			continue
		}

		if !registry.HasDebugSelector(selector) {
			return fmt.Errorf("%w: %s", ErrPluginDebugSelectorMissing, selector)
		}
	}

	return nil
}

// stateRegistry returns the loaded registry or an empty registry for nil state.
func stateRegistry(state *State) debugSelectorRegistry {
	if state == nil {
		return emptyDebugSelectorRegistry{}
	}

	return state.Registry()
}

type debugSelectorRegistry interface {
	HasDebugSelector(string) bool
}

type emptyDebugSelectorRegistry struct{}

// HasDebugSelector reports false for every selector in the empty registry.
func (emptyDebugSelectorRegistry) HasDebugSelector(string) bool {
	return false
}
