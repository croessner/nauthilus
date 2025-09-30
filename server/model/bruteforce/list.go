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

// BlockedIPAddresses represents a structure to hold blocked IP addresses retrieved from Redis.
// IPAddresses maps IP addresses to their corresponding rules/buckets.
// Error holds any error encountered during the retrieval process.
type BlockedIPAddresses struct {
	// IPAddresses maps IP addresses to their respective buckets/rules that triggered blocking.
	IPAddresses map[string]string `json:"ip_addresses"`

	// Error holds any error encountered during the retrieval process.
	Error *string `json:"error"`
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
