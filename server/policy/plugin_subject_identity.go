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
	pluginSubjectAttributePrefix = "auth.plugin.subject."
	pluginSubjectCheckPrefix     = "plugin_subject_"
)

// PluginSubjectIdentity returns the canonical module-local identity for native subject sources.
func PluginSubjectIdentity(moduleName string, localName string) string {
	moduleName = strings.TrimSpace(moduleName)
	localName = strings.TrimSpace(localName)

	if moduleName == "" || localName == "" {
		return ""
	}

	return moduleName + "." + localName
}

// PluginSubjectCheckName returns the scheduler-visible check name for one native subject source.
func PluginSubjectCheckName(moduleName string, localName string) string {
	identity := PluginSubjectIdentity(moduleName, localName)
	if identity == "" {
		return ""
	}

	return pluginSubjectCheckPrefix + strings.ReplaceAll(identity, ".", "_")
}

// PluginSubjectAttributeID returns the generated native subject attribute ID for one suffix.
func PluginSubjectAttributeID(moduleName string, localName string, suffix string) string {
	identity := PluginSubjectIdentity(moduleName, localName)
	suffix = strings.TrimSpace(suffix)

	if identity == "" || suffix == "" {
		return ""
	}

	return pluginSubjectAttributePrefix + identity + "." + suffix
}
