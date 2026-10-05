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
	"errors"
	"fmt"
	"reflect"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
)

// ReloadResult is the bounded outcome of one module in one configuration reload.
type ReloadResult string

const (
	// ReloadResultReloaded reports a module whose changed config was applied by Reconfigure.
	ReloadResultReloaded ReloadResult = "reloaded"

	// ReloadResultUnchanged reports a module whose plugin-owned config did not change.
	ReloadResultUnchanged ReloadResult = "unchanged"

	// ReloadResultRestartRequired reports a change that only a process restart can apply.
	ReloadResultRestartRequired ReloadResult = "restart_required"

	// ReloadResultRejected reports a candidate config the module refused during validation.
	ReloadResultRejected ReloadResult = "rejected"

	// ReloadResultFailed reports a Reconfigure call that failed after the generation was committed.
	ReloadResultFailed ReloadResult = "failed"

	// ReloadResultAborted reports a valid change that was not applied because the reload was rejected elsewhere.
	ReloadResultAborted ReloadResult = "aborted"
)

// reloadResultPending marks a validated change that waits for commit.
const reloadResultPending ReloadResult = ""

// ReloadRecord describes one module outcome of one reload without config values.
//
// ModuleName is empty when a change outside the modules, such as the trust settings, made the
// whole plugin section restart-bound.
type ReloadRecord struct {
	ModuleName string
	Result     ReloadResult
}

// ReloadObserver receives one record per module and reload.
type ReloadObserver interface {
	ObservePluginReload(ReloadRecord)
}

// ReloadClassifier decides which plugin section changes a running process can apply.
//
// Only the plugin-owned config of registered modules whose plugin implements
// pluginapi.ReloadablePlugin is reloadable. Every other field of the plugins section is bound
// to the process lifetime.
type ReloadClassifier struct {
	reloadable map[string]struct{}
}

// moduleChange is the classified reload state of one configured module.
type moduleChange struct {
	next   config.PluginModule
	name   string
	result ReloadResult
}

// NewReloadClassifier captures which registered module instances accept config-only reloads.
func NewReloadClassifier(instances []pluginloader.ModuleInstance) ReloadClassifier {
	reloadable := make(map[string]struct{}, len(instances))

	for _, instance := range instances {
		if !instance.IsRegistered() {
			continue
		}

		if _, ok := instance.Plugin.(pluginapi.ReloadablePlugin); !ok {
			continue
		}

		name := instance.ModuleName
		if name == "" {
			name = instance.Module.Name
		}

		reloadable[name] = struct{}{}
	}

	return ReloadClassifier{reloadable: reloadable}
}

// Reloadable reports whether the named module accepts config-only reloads.
func (c ReloadClassifier) Reloadable(moduleName string) bool {
	_, ok := c.reloadable[moduleName]

	return ok
}

// RestartBound returns the plugin section without the plugin-owned config of reloadable modules.
//
// The result is the part of the plugins section that must stay identical until the next restart.
// It shares every other value with plugins and must not be modified.
func (c ReloadClassifier) RestartBound(plugins *config.PluginsSection) *config.PluginsSection {
	if plugins == nil {
		return nil
	}

	projected := *plugins
	projected.Modules = slices.Clone(plugins.Modules)

	for index := range projected.Modules {
		if c.Reloadable(projected.Modules[index].Name) {
			projected.Modules[index].Config = nil
		}
	}

	return &projected
}

// Validate rejects every change between two plugin sections that needs a process restart.
func (c ReloadClassifier) Validate(current *config.PluginsSection, next *config.PluginsSection) error {
	_, err := c.classify(current, next)

	return err
}

// classify returns the per-module outcome and the joined restart-bound causes.
//
// Section-level changes return no module outcomes because they concern the loader as a whole.
func (c ReloadClassifier) classify(current *config.PluginsSection, next *config.PluginsSection) ([]moduleChange, error) {
	current = clonePluginSection(current)
	next = clonePluginSection(next)

	if reason := restartOnlySectionChange(current, next); reason != "" {
		return nil, fmt.Errorf("%w: plugin %s changed", ErrRestartRequired, reason)
	}

	changes := make([]moduleChange, 0, len(next.Modules))

	var errs []error

	for index := range next.Modules {
		change, err := c.classifyModule(current.Modules[index], next.Modules[index])
		if err != nil {
			errs = append(errs, err)
		}

		changes = append(changes, change)
	}

	return changes, errors.Join(errs...)
}

// classifyModule compares one module declaration with its candidate at the same position.
func (c ReloadClassifier) classifyModule(current config.PluginModule, next config.PluginModule) (moduleChange, error) {
	change := moduleChange{name: next.Name, next: next, result: ReloadResultUnchanged}

	if restartOnlyModuleChange(current, next) {
		change.result = ReloadResultRestartRequired

		return change, fmt.Errorf("%w: plugin module %q loader settings changed", ErrRestartRequired, next.Name)
	}

	if reflect.DeepEqual(current.Config, next.Config) {
		return change, nil
	}

	if !c.Reloadable(next.Name) {
		change.result = ReloadResultRestartRequired

		return change, fmt.Errorf("%w: plugin module %q does not support config reload", ErrRestartRequired, next.Name)
	}

	change.result = reloadResultPending

	return change, nil
}

// restartOnlySectionChange names the first changed section-level loader field, or returns an empty string.
func restartOnlySectionChange(current *config.PluginsSection, next *config.PluginsSection) string {
	switch {
	case !reflect.DeepEqual(current.OpaqueIdentifierTagger, next.OpaqueIdentifierTagger):
		return "opaque identifier tagger"
	case current.VerificationPolicy != next.VerificationPolicy:
		return "verification policy"
	case !slices.Equal(current.AllowedDirs, next.AllowedDirs):
		return "allowed directories"
	case !sameSigners(current.Trust.Signers, next.Trust.Signers):
		return "trust signers"
	case len(current.Modules) != len(next.Modules):
		return "module list"
	}

	return ""
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
		current.PositivePasswordCache != next.PositivePasswordCache ||
		current.Optional != next.Optional {
		return true
	}

	if !sameHookAuthorizations(current.Hooks, next.Hooks) {
		return true
	}

	if !samePluginCompatibility(current.Compatibility, next.Compatibility) {
		return true
	}

	return !sameCapabilities(current.AllowCapabilities, next.AllowCapabilities)
}

// samePluginCompatibility compares restart-only exact observability allowlists in declaration order.
func samePluginCompatibility(left config.PluginCompatibility, right config.PluginCompatibility) bool {
	if !slices.Equal(left.TraceScopes, right.TraceScopes) || len(left.Metrics) != len(right.Metrics) {
		return false
	}

	for index := range left.Metrics {
		leftMetric := left.Metrics[index]

		rightMetric := right.Metrics[index]

		if leftMetric.Type != rightMetric.Type ||
			leftMetric.Name != rightMetric.Name ||
			leftMetric.Help != rightMetric.Help ||
			!slices.Equal(leftMetric.Labels, rightMetric.Labels) ||
			!slices.Equal(leftMetric.Buckets, rightMetric.Buckets) {
			return false
		}
	}

	return true
}

// sameHookAuthorizations compares host-owned hook scopes independently of declaration order.
func sameHookAuthorizations(left []config.PluginHookAuthorization, right []config.PluginHookAuthorization) bool {
	if len(left) != len(right) {
		return false
	}

	rightByName := make(map[string][]string, len(right))
	for _, authorization := range right {
		rightByName[authorization.Name] = authorization.RequiredScopes
	}

	for _, authorization := range left {
		rightScopes, exists := rightByName[authorization.Name]
		if !exists || !slices.Equal(authorization.RequiredScopes, rightScopes) {
			return false
		}
	}

	return true
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
