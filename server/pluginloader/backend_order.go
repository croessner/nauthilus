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

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/pluginregistry"
)

var (
	// ErrOrderedPluginBackendMissing reports an auth.backends.order plugin selector
	// that did not resolve to a registered backend component.
	ErrOrderedPluginBackendMissing = errors.New("ordered plugin backend is not registered")
)

// ValidateOrderedPluginBackends verifies that auth.backends.order plugin entries
// refer to registered backend components after native plugin registration.
func ValidateOrderedPluginBackends(cfg config.File, state *State) error {
	if cfg == nil || cfg.GetServer() == nil {
		return nil
	}

	registry := pluginregistry.NewRegistry()
	if state != nil {
		registry = state.Registry()
	}

	for _, backend := range cfg.GetServer().GetBackends() {
		if backend.Get() != definitions.BackendPlugin {
			continue
		}

		if err := validateOrderedPluginBackend(backend.GetName(), registry); err != nil {
			return err
		}
	}

	return nil
}

// validateOrderedPluginBackend checks one fully qualified plugin backend name.
func validateOrderedPluginBackend(qualifiedName string, registry *pluginregistry.Registry) error {
	if err := pluginapi.ValidateQualifiedComponentName(qualifiedName); err != nil {
		return fmt.Errorf("%w: %q is not a fully qualified backend name", ErrOrderedPluginBackendMissing, qualifiedName)
	}

	component, found := registry.Lookup(qualifiedName)
	if !found {
		return fmt.Errorf("%w: %s", ErrOrderedPluginBackendMissing, qualifiedName)
	}

	if component.Kind != pluginregistry.ComponentKindBackend {
		return fmt.Errorf("%w: %s registered as %s", ErrOrderedPluginBackendMissing, qualifiedName, component.Kind)
	}

	return nil
}
