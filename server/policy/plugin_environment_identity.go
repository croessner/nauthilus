// Copyright (C) 2026 Christian Rößner
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

package policy

import "strings"

const (
	pluginEnvironmentAttributePrefix = "auth.plugin.environment."
	pluginEnvironmentCheckPrefix     = "plugin_environment_"
	pluginEnvironmentRefSuffix       = ".environment"
)

// PluginEnvironmentModuleNameFromConfigRef returns the module selected by a native environment check.
func PluginEnvironmentModuleNameFromConfigRef(configRef string) string {
	moduleName, _ := pluginModuleNameFromConfigRef(configRef, pluginEnvironmentRefSuffix)

	return moduleName
}

// PluginEnvironmentCheckName returns the scheduler-visible check name for one module.
func PluginEnvironmentCheckName(moduleName string) string {
	moduleName = strings.TrimSpace(moduleName)
	if moduleName == "" {
		return ""
	}

	return pluginEnvironmentCheckPrefix + moduleName
}

// PluginEnvironmentConfigRef returns the module config reference for native environment checks.
func PluginEnvironmentConfigRef(moduleName string) string {
	moduleName = strings.TrimSpace(moduleName)
	if moduleName == "" {
		return ""
	}

	return pluginConfigRefPrefix + moduleName + pluginEnvironmentRefSuffix
}

// PluginEnvironmentAttributeID returns a generated native environment execution fact ID.
func PluginEnvironmentAttributeID(moduleName string, componentName string, suffix string) string {
	moduleName = strings.TrimSpace(moduleName)
	componentName = strings.TrimSpace(componentName)
	suffix = strings.TrimSpace(suffix)

	if moduleName == "" || componentName == "" || suffix == "" {
		return ""
	}

	return pluginEnvironmentAttributePrefix + moduleName + "." + componentName + "." + suffix
}
