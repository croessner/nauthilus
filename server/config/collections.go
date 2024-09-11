// Copyright (C) 2024 Christian Rößner
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

package config

var void struct{}

// StringSet is a storage container that ensures unique keys.
type StringSet map[string]any

// GetStringSlice returns all values for a StringSet as a slice of strings.
func (s *StringSet) GetStringSlice() (result []string) {
	for key := range *s {
		result = append(result, key)
	}

	return
}

// Set adds an element to the StringSet
func (s *StringSet) Set(value string) {
	(*s)[value] = void
}

// NewStringSet constructs a new StringSet
func NewStringSet() StringSet {
	return make(StringSet, 1)
}
