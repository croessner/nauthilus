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

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
)

var mu = &sync.RWMutex{}

// SoftWhitelistProvider defines the methods for managing a soft whitelist of networks associated with usernames.
// The interface allows checking the existence of a whitelist, retrieving, setting, and deleting networks.
type SoftWhitelistProvider interface {
	// HasSoftWhitelist checks if there is at least one entry in the soft whitelist, returning true if it exists, otherwise false.
	HasSoftWhitelist() bool

	// Get retrieves the list of networks associated with the given username from the soft whitelist.
	Get(username string) []string

	// Set adds a specified network to a user's whitelist if the network is valid and the username is not empty.
	Set(username, network string)

	// Delete removes a specified network from the user's soft whitelist identified by the provided username.
	Delete(username, network string)
}

// SoftWhitelist is a type that represents a map linking a string key to a slice of string values.
// Typically used to associate users with a list of CIDR networks.
type SoftWhitelist map[string][]string

// decodeSoftWhitelist restores dotted usernames that Viper expands into nested maps.
func decodeSoftWhitelist(data any) (SoftWhitelist, error) {
	allowlist := NewSoftWhitelist()

	if err := collectSoftWhitelistEntries(allowlist, nil, data); err != nil {
		return nil, err
	}

	return allowlist, nil
}

// collectSoftWhitelistEntries flattens one Viper map branch into a username and its networks.
func collectSoftWhitelistEntries(allowlist SoftWhitelist, path []string, data any) error {
	switch value := data.(type) {
	case nil:
		return nil
	case SoftWhitelist:
		copySoftWhitelistEntries(allowlist, value)
		return nil
	case map[string][]string:
		copySoftWhitelistEntries(allowlist, value)
		return nil
	case map[string]any:
		return collectSoftWhitelistMapEntries(allowlist, path, value)
	case []string:
		return storeSoftWhitelistNetworks(allowlist, path, value)
	case []any:
		return storeSoftWhitelistAnyNetworks(allowlist, path, value)
	default:
		return fmt.Errorf("allowlist %q expects network list, got %T", strings.Join(path, "."), data)
	}
}

// copySoftWhitelistEntries copies typed allowlist entries without sharing network slices.
func copySoftWhitelistEntries(allowlist SoftWhitelist, entries map[string][]string) {
	for username, networks := range entries {
		allowlist[username] = append([]string(nil), networks...)
	}
}

// collectSoftWhitelistMapEntries walks map keys in deterministic order.
func collectSoftWhitelistMapEntries(allowlist SoftWhitelist, path []string, entries map[string]any) error {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		if err := collectSoftWhitelistEntries(allowlist, append(path, key), entries[key]); err != nil {
			return err
		}
	}

	return nil
}

// storeSoftWhitelistNetworks stores one username entry after validating its path.
func storeSoftWhitelistNetworks(allowlist SoftWhitelist, path []string, networks []string) error {
	if len(path) == 0 {
		return fmt.Errorf("allowlist networks require a username")
	}

	allowlist[strings.Join(path, ".")] = append([]string(nil), networks...)

	return nil
}

// storeSoftWhitelistAnyNetworks converts Viper list values into strings before storing them.
func storeSoftWhitelistAnyNetworks(allowlist SoftWhitelist, path []string, values []any) error {
	networks := make([]string, 0, len(values))
	for index, network := range values {
		networkString, ok := network.(string)
		if !ok {
			return fmt.Errorf("allowlist %q network %d expects string, got %T", strings.Join(path, "."), index, network)
		}

		networks = append(networks, networkString)
	}

	return storeSoftWhitelistNetworks(allowlist, path, networks)
}

// NewSoftWhitelist creates and returns a new instance of SoftWhitelist initialized as an empty map of string slices.
func NewSoftWhitelist() SoftWhitelist {
	return make(SoftWhitelist)
}

func (s SoftWhitelist) String() string {
	if s == nil {
		return "SoftWhitelist: <nil>"
	}

	for k, v := range s {
		var sb strings.Builder

		sb.WriteString("SoftWhitelist: {SoftWhitelist[")
		sb.WriteString(k)
		sb.WriteString("]: ")
		sb.WriteString(strings.Join(v, ", "))
		sb.WriteByte('}')

		return sb.String()
	}

	return "SoftWhitelist: {SoftWhitelist: <empty>}"
}

// HasSoftWhitelist checks if the SoftWhitelist is non-nil and contains at least one entry.
func (s SoftWhitelist) HasSoftWhitelist() bool {
	if s == nil {
		return false
	}

	mu.RLock()

	defer mu.RUnlock()

	return len(s) > 0
}

// isValidNetwork checks if the provided network string is a valid CIDR notation.
// It returns true if the network is valid, otherwise false.
func (s SoftWhitelist) isValidNetwork(network string) bool {
	_, ok := canonicalSoftWhitelistNetwork(network)

	return ok
}

// Set adds a specified network to a user's whitelist if the network is valid and the username is not empty.
func (s SoftWhitelist) Set(username, network string) {
	if s == nil {
		return
	}

	mu.Lock()

	defer mu.Unlock()

	if len(username) == 0 {
		return
	}

	if canonical, ok := canonicalSoftWhitelistNetwork(network); ok {
		if s[username] == nil {
			s[username] = make([]string, 0)
		}

		if !slices.Contains(s[username], canonical) {
			s[username] = append(s[username], canonical)
		}
	}
}

// Get retrieves the list of networks associated with the specified username from the SoftWhitelist.
// If the SoftWhitelist is nil or the username does not exist, it returns nil.
func (s SoftWhitelist) Get(username string) []string {
	if s == nil {
		return nil
	}

	mu.RLock()

	defer mu.RUnlock()

	return append([]string(nil), s[username]...)
}

// normalize canonicalizes networks and removes duplicate entries during config loading.
func (s SoftWhitelist) normalize() {
	for username, networks := range s {
		normalized := make([]string, 0, len(networks))

		seen := make(map[string]struct{}, len(networks))

		for _, network := range networks {
			canonical, ok := canonicalSoftWhitelistNetwork(network)
			if !ok {
				canonical = strings.TrimSpace(network)
			}

			if _, exists := seen[canonical]; exists {
				continue
			}

			seen[canonical] = struct{}{}
			normalized = append(normalized, canonical)
		}

		s[username] = normalized
	}
}

// validate checks usernames and CIDR entries using deterministic paths.
func (s SoftWhitelist) validate(path string) error {
	usernames := make([]string, 0, len(s))
	for username := range s {
		usernames = append(usernames, username)
	}

	sort.Strings(usernames)

	for _, username := range usernames {
		if strings.TrimSpace(username) == "" {
			return NewValidationProblem(path, "username must not be blank")
		}

		for index, network := range s[username] {
			if !s.isValidNetwork(network) {
				return NewValidationProblem(fmt.Sprintf("%s.%s[%d]", path, username, index), "must be a valid CIDR network")
			}
		}
	}

	return nil
}

// canonicalSoftWhitelistNetwork returns a normalized CIDR representation.
func canonicalSoftWhitelistNetwork(network string) (string, bool) {
	_, parsed, err := net.ParseCIDR(strings.TrimSpace(network))
	if err != nil {
		return "", false
	}

	return parsed.String(), true
}

// Delete removes the specified network from the user's whitelist in the SoftWhitelist. If the network is the only entry,
// the user is removed from the whitelist. The function does nothing if the whitelist is nil or if the user does not exist.
func (s SoftWhitelist) Delete(username, network string) {
	if s == nil {
		return
	}

	mu.Lock()

	defer mu.Unlock()

	if canonical, ok := canonicalSoftWhitelistNetwork(network); ok {
		network = canonical
	}

	networks, exists := s[username]
	if !exists {
		return
	}

	if len(networks) > 1 {
		for i, n := range networks {
			if n == network {
				networks = append(networks[:i], networks[i+1:]...)

				break
			}
		}

		s[username] = networks
	} else {
		if s[username][0] == network {
			delete(s, username)
		}
	}
}

var _ SoftWhitelistProvider = (*SoftWhitelist)(nil)
