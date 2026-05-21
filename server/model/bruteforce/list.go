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

	// Page contains optional pagination metadata for the current entries slice.
	Page *PageInfo `json:"page,omitempty"`

	// Error holds any error encountered during the retrieval process.
	Error *string `json:"error,omitempty"`
}

// BlockedAccounts represents a list of blocked user accounts and potential error information.
type BlockedAccounts struct {
	// Accounts represents a list of user accounts.
	Accounts map[string][]string `json:"accounts"`

	// Page contains optional pagination metadata for the current account slice.
	Page *PageInfo `json:"page,omitempty"`

	// Error represents the error message, if any, encountered during the account retrieval process.
	Error *string `json:"error"`
}

// PageInfo describes a server-side page returned by a list endpoint.
type PageInfo struct {
	// Limit is the maximum number of records requested for this page.
	Limit int `json:"limit"`

	// Offset is the zero-based offset used for this page.
	Offset int `json:"offset"`

	// NextOffset is the offset a client can use for the following page.
	NextOffset int `json:"next_offset"`

	// HasMore reports whether the current section has more records after this page.
	HasMore bool `json:"has_more"`
}

// FilterCmd defines a struct for command filters with optional fields for Accounts and IP Address.
type FilterCmd struct {
	// Accounts represents an optional filter criterion for user accounts in the FilterCmd struct.
	Accounts []string `json:"accounts,omitempty"`

	// IPAddress represents an optional filter criterion for IP addresses in the FilterCmd struct.
	IPAddress []string `json:"ip_addresses,omitempty"`
}
