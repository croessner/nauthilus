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

// HasSoftWhitelist reports whether brute-force allowlist entries are configured.
func (b *BruteForceSection) HasSoftWhitelist() bool {
	if b == nil {
		return false
	}

	return b.SoftWhitelist.HasSoftWhitelist()
}

// Get returns allowlist networks for the given brute-force username.
func (b *BruteForceSection) Get(username string) []string {
	if b == nil {
		return nil
	}

	return b.SoftWhitelist.Get(username)
}

// Set stores an allowlist network for the given brute-force username.
func (b *BruteForceSection) Set(username, network string) {
	if b == nil {
		return
	}

	b.SoftWhitelist.Set(username, network)
}

// Delete removes an allowlist network for the given brute-force username.
func (b *BruteForceSection) Delete(username, network string) {
	if b == nil {
		return
	}

	b.SoftWhitelist.Delete(username, network)
}

// HasSoftWhitelist reports whether relay-domain allowlist entries are configured.
func (r *RelayDomainsSection) HasSoftWhitelist() bool {
	if r == nil {
		return false
	}

	return r.SoftWhitelist.HasSoftWhitelist()
}

// Get returns allowlist networks for the given relay-domain username.
func (r *RelayDomainsSection) Get(username string) []string {
	if r == nil {
		return nil
	}

	return r.SoftWhitelist.Get(username)
}

// Set stores an allowlist network for the given relay-domain username.
func (r *RelayDomainsSection) Set(username, network string) {
	if r == nil {
		return
	}

	r.SoftWhitelist.Set(username, network)
}

// Delete removes an allowlist network for the given relay-domain username.
func (r *RelayDomainsSection) Delete(username, network string) {
	if r == nil {
		return
	}

	r.SoftWhitelist.Delete(username, network)
}

// HasSoftWhitelist reports whether RBL allowlist entries are configured.
func (r *RBLSection) HasSoftWhitelist() bool {
	if r == nil {
		return false
	}

	return r.SoftWhitelist.HasSoftWhitelist()
}

// Get returns allowlist networks for the given RBL username.
func (r *RBLSection) Get(username string) []string {
	if r == nil {
		return nil
	}

	return r.SoftWhitelist.Get(username)
}

// Set stores an allowlist network for the given RBL username.
func (r *RBLSection) Set(username, network string) {
	if r == nil {
		return
	}

	r.SoftWhitelist.Set(username, network)
}

// Delete removes an allowlist network for the given RBL username.
func (r *RBLSection) Delete(username, network string) {
	if r == nil {
		return
	}

	r.SoftWhitelist.Delete(username, network)
}

var _ SoftWhitelistProvider = (*BruteForceSection)(nil)
var _ SoftWhitelistProvider = (*RelayDomainsSection)(nil)
var _ SoftWhitelistProvider = (*RBLSection)(nil)
