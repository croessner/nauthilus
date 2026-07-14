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

const pluginConfigRefPrefix = "plugins.modules."

// pluginModuleNameFromConfigRef parses a module-level native extension config reference.
func pluginModuleNameFromConfigRef(configRef string, suffix string) (string, bool) {
	configRef = strings.TrimSpace(configRef)

	trimmed, ok := strings.CutPrefix(configRef, pluginConfigRefPrefix)
	if !ok {
		return "", false
	}

	moduleName, ok := strings.CutSuffix(trimmed, suffix)
	if !ok {
		return "", false
	}

	moduleName = strings.TrimSpace(moduleName)
	if moduleName == "" {
		return "", false
	}

	return moduleName, true
}
