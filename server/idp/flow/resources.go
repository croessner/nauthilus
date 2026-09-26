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

package flow

import "strings"

// resourceSeparator separates resource indicators in flow metadata. Validated resources never contain whitespace.
const resourceSeparator = " "

// JoinResources renders validated RFC 8707 resource indicators for the FlowMetadataResource value.
func JoinResources(resources []string) string {
	return strings.Join(resources, resourceSeparator)
}

// SplitResources parses a FlowMetadataResource value; an empty value yields no resources.
func SplitResources(value string) []string {
	resources := strings.Fields(value)
	if len(resources) == 0 {
		return nil
	}

	return resources
}
