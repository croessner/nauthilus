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
	"net"
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
	_, _, err := net.ParseCIDR(network)

	return err == nil
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

	if s.isValidNetwork(network) {
		if s[username] == nil {
			s[username] = make([]string, 0)
		}

		s[username] = append(s[username], network)
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

	for k, v := range s {
		if k == username {
			return v
		}
	}

	return nil
}

// Delete removes the specified network from the user's whitelist in the SoftWhitelist. If the network is the only entry,
// the user is removed from the whitelist. The function does nothing if the whitelist is nil or if the user does not exist.
func (s SoftWhitelist) Delete(username, network string) {
	if s == nil {
		return
	}

	mu.Lock()

	defer mu.Unlock()

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
