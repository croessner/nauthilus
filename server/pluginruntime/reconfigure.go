// Copyright (C) 2026 Christian Roessner
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

// Reconfigure applies config-only plugin reloads and rejects restart-only loader changes.
func (r *Runner) Reconfigure(ctx context.Context, file config.File) error {
	if r == nil {
		return nil
	}

	next := pluginSectionFromFile(file)

	r.mu.Lock()
	defer r.mu.Unlock()

	if restartOnlyPluginChange(r.pluginConfig, next) {
		return ErrRestartRequired
	}

	nextModules := modulesByName(next.Modules)

	reconfigured, err := r.reconfigureModules(ctx, nextModules)
	if err != nil {
		return err
	}

	r.commitReconfiguredModules(reconfigured)
	r.pluginConfig = next

	return nil
}

// pluginSectionFromFile returns the cloned plugin section from a config file.
func pluginSectionFromFile(file config.File) *config.PluginsSection {
	if file == nil {
		return clonePluginSection(nil)
	}

	return clonePluginSection(file.GetPlugins())
}

// reconfigureModules calls ReloadablePlugin instances and records successful config swaps.
func (r *Runner) reconfigureModules(
	ctx context.Context,
	nextModules map[string]config.PluginModule,
) (map[string]config.PluginModule, error) {
	reconfigured := make(map[string]config.PluginModule, len(r.modules))

	var errs []error

	for index := range r.modules {
		instance := r.modules[index].instance
		nextModule := nextModules[instance.ModuleName]

		reconfiguredModule, err := r.reconfigureModule(ctx, instance, nextModule)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		if reconfiguredModule {
			reconfigured[instance.ModuleName] = nextModule
		}
	}

	return reconfigured, errors.Join(errs...)
}

// reconfigureModule invokes one reloadable plugin module.
func (r *Runner) reconfigureModule(
	ctx context.Context,
	instance pluginloader.ModuleInstance,
	nextModule config.PluginModule,
) (bool, error) {
	reloadable, ok := instance.Plugin.(pluginapi.ReloadablePlugin)
	if !ok {
		return false, nil
	}

	view := pluginregistry.NewConfigView(nextModule.Config)

	spec := invokeSpec{
		moduleName:     instance.ModuleName,
		componentName:  instance.ModuleName,
		extensionPoint: extensionPointPlugin,
		method:         "Reconfigure",
	}
	if err := r.invoke(ctx, spec, func(callCtx context.Context) error {
		return reloadable.Reconfigure(callCtx, view)
	}); err != nil {
		return false, fmt.Errorf("plugin module %q Reconfigure failed: %w", instance.ModuleName, err)
	}

	return true, nil
}

// commitReconfiguredModules swaps host-owned config views after all reloadable modules succeeded.
func (r *Runner) commitReconfiguredModules(reconfigured map[string]config.PluginModule) {
	for index := range r.modules {
		instance := &r.modules[index].instance

		nextModule, ok := reconfigured[instance.ModuleName]
		if ok {
			instance.Module.Config = cloneConfigMap(nextModule.Config)
		}
	}
}

// restartOnlyPluginChange reports whether reload input changed non-plugin-owned configuration.
func restartOnlyPluginChange(current *config.PluginsSection, next *config.PluginsSection) bool {
	current = clonePluginSection(current)
	next = clonePluginSection(next)

	if current.VerificationPolicy != next.VerificationPolicy {
		return true
	}

	if !slices.Equal(current.AllowedDirs, next.AllowedDirs) {
		return true
	}

	if !sameSigners(current.Trust.Signers, next.Trust.Signers) {
		return true
	}

	if len(current.Modules) != len(next.Modules) {
		return true
	}

	for index := range current.Modules {
		if restartOnlyModuleChange(current.Modules[index], next.Modules[index]) {
			return true
		}
	}

	return false
}

// restartOnlyModuleChange compares all module fields except plugin-owned config.
func restartOnlyModuleChange(current config.PluginModule, next config.PluginModule) bool {
	if current.Name != next.Name {
		return true
	}

	if current.Type != next.Type ||
		current.Path != next.Path ||
		current.Checksum != next.Checksum ||
		current.Signature != next.Signature ||
		current.Signer != next.Signer ||
		current.StopTimeout != next.StopTimeout ||
		current.Optional != next.Optional {
		return true
	}

	return !sameCapabilities(current.AllowCapabilities, next.AllowCapabilities)
}

// sameSigners reports whether trust signer configuration is unchanged.
func sameSigners(left []config.PluginTrustSigner, right []config.PluginTrustSigner) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}

// modulesByName returns configured modules keyed by instance name.
func modulesByName(modules []config.PluginModule) map[string]config.PluginModule {
	byName := make(map[string]config.PluginModule, len(modules))
	for _, module := range modules {
		byName[module.Name] = clonePluginModule(module)
	}

	return byName
}
