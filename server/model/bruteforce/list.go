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

package bruteforce

import "time"

// BanEntry represents a single active brute force ban with all derived information.
type BanEntry struct {
	// Network is the banned IP network (e.g. "192.168.1.0/24").
	Network string `json:"network"`

	// Bucket is the name of the brute force rule that triggered the ban.
	Bucket string `json:"bucket"`

	// BanTime is the configured ban duration from the rule.
	BanTime time.Duration `json:"ban_time,omitzero"`

	// TTL is the remaining time until the ban expires (from Redis TTL).
	TTL time.Duration `json:"ttl,omitzero"`

	// BannedAt is the calculated timestamp when the ban was created.
	BannedAt time.Time `json:"banned_at,omitzero"`
}

// BlockedIPAddresses represents the response for the brute force listing API.
type BlockedIPAddresses struct {
	// Entries contains all active ban entries.
	Entries []BanEntry `json:"entries"`

	// Error holds any error encountered during the retrieval process.
	Error *string `json:"error,omitempty"`
}

// BlockedAccounts represents a list of blocked user accounts and potential error information.
type BlockedAccounts struct {
	// Accounts represents a list of user accounts.
	Accounts map[string][]string `json:"accounts"`

	// Error represents the error message, if any, encountered during the account retrieval process.
	Error *string `json:"error"`
}

// FilterCmd defines a struct for command filters with optional fields for Accounts and IP Address.
type FilterCmd struct {
	// Accounts represents an optional filter criterion for user accounts in the FilterCmd struct.
	Accounts []string `json:"accounts,omitempty"`

	// IPAddress represents an optional filter criterion for IP addresses in the FilterCmd struct.
	IPAddress []string `json:"ip_addresses,omitempty"`
}
