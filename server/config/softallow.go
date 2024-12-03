package config

import (
	"net"
	"strings"
)

// SoftWhitelist is a type that represents a map linking a string key to a slice of string values.
// Typically used to associate users with a list of CIDR networks.
type SoftWhitelist map[string][]string

// NewSoftWhitelist creates and returns a new instance of SoftWhitelist initialized as an empty map of string slices.
func NewSoftWhitelist() SoftWhitelist {
	return make(map[string][]string)
}

func (s SoftWhitelist) String() string {
	if s == nil {
		return "SoftWhitelist: <nil>"
	}

	for k, v := range s {
		return "SoftWhitelist: {SoftWhitelist[" + k + "]: " + strings.Join(v, ", ") + "}"
	}

	return "SoftWhitelist: {SoftWhitelist: <empty>}"
}

// HasSoftWhitelist checks if the SoftWhitelist is non-nil and contains at least one entry.
func (s SoftWhitelist) HasSoftWhitelist() bool {
	if s == nil {
		return false
	}

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

	networks := s.Get(username)
	if networks == nil {
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
