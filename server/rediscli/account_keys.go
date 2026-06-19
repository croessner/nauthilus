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

// Package rediscli contains Redis client helpers and key builders.
package rediscli

import "github.com/croessner/nauthilus/v3/server/definitions"

// BuildKey applies the configured Redis prefix without changing the key body.
func BuildKey(prefix string, key string) string {
	return prefix + key
}

// BuildKeys applies the configured Redis prefix to each key.
func BuildKeys(prefix string, keys []string) []string {
	if len(keys) == 0 {
		return nil
	}

	built := make([]string, len(keys))
	for index, key := range keys {
		built[index] = BuildKey(prefix, key)
	}

	return built
}

// GetAffectedAccountsIndexKey returns the sorted index key for affected accounts.
func GetAffectedAccountsIndexKey(prefix string) string {
	return prefix + definitions.RedisAffectedAccountsIndexKey
}
