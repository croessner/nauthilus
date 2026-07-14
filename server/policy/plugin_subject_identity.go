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
	pluginSubjectRefSuffix       = ".subject"
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

// PluginSubjectIdentityFromCheck derives the canonical subject identity from a compiled check.
func PluginSubjectIdentityFromCheck(configRef string, checkName string) string {
	moduleName, ok := pluginModuleNameFromConfigRef(configRef, pluginSubjectRefSuffix)
	if !ok {
		return ""
	}

	localName, ok := pluginSubjectLocalNameFromCheckName(moduleName, checkName)
	if !ok {
		return ""
	}

	return PluginSubjectIdentity(moduleName, localName)
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

// pluginSubjectLocalNameFromCheckName parses the runtime-generated subject check name for one module.
func pluginSubjectLocalNameFromCheckName(moduleName string, checkName string) (string, bool) {
	checkName = strings.TrimSpace(checkName)
	checkPrefix := pluginSubjectCheckPrefix + strings.ReplaceAll(moduleName, ".", "_") + "_"

	localName, ok := strings.CutPrefix(checkName, checkPrefix)
	if !ok {
		return "", false
	}

	localName = strings.TrimSpace(localName)
	if localName == "" {
		return "", false
	}

	return localName, true
}
