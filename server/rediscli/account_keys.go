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

import (
	"errors"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// affectedAccountsRetentionSuffix names the retention-deadline sibling of the affected-account set.
const affectedAccountsRetentionSuffix = "retention"

// ErrNoSlotSibling reports a key whose braces prevent building a sibling key in the same cluster slot.
var ErrNoSlotSibling = errors.New("key braces prevent a same-slot sibling key")

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

// GetAffectedAccountsKey returns the affected-account set key.
func GetAffectedAccountsKey(prefix string) string {
	return prefix + definitions.RedisAffectedAccountsKey
}

// GetAffectedAccountsRetentionKey returns the retention-deadline ZSET that shares the cluster slot of the
// affected-account set, so scripts can update both keys atomically.
func GetAffectedAccountsRetentionKey(prefix string) (string, error) {
	return SlotSiblingKey(prefix, GetAffectedAccountsKey(prefix), affectedAccountsRetentionSuffix)
}

// SlotSiblingKey returns a key that Redis Cluster maps to the same hash slot as key and that still starts with
// prefix whenever possible, so prefix-scoped ACLs and tooling cover it.
//
// It follows the cluster specification: the hash tag is the text between the first "{" and the first "}" after
// it, and an empty tag does not count. A key with a valid tag keeps it by appending the suffix. A key without a
// valid tag is wrapped as "<prefix>{key}:suffix", which hashes the complete original key. If the prefix itself
// contains a brace, the wrapping tag must come first ("{key}:suffix"). A key containing "}" without a valid tag
// cannot be wrapped exactly and is rejected with ErrNoSlotSibling.
func SlotSiblingKey(prefix string, key string, suffix string) (string, error) {
	if hasClusterHashTag(key) {
		return key + ":" + suffix, nil
	}

	if strings.Contains(key, "}") {
		return "", ErrNoSlotSibling
	}

	if strings.Contains(prefix, "{") {
		return "{" + key + "}:" + suffix, nil
	}

	return prefix + "{" + key + "}:" + suffix, nil
}

// hasClusterHashTag reports whether key carries a non-empty hash tag under the Redis Cluster rule.
func hasClusterHashTag(key string) bool {
	start := strings.IndexByte(key, '{')
	if start < 0 {
		return false
	}

	end := strings.IndexByte(key[start+1:], '}')

	return end > 0
}

// StringsToArgs converts strings into variadic go-redis arguments.
func StringsToArgs(values []string) []any {
	args := make([]any, len(values))
	for index, value := range values {
		args[index] = value
	}

	return args
}
