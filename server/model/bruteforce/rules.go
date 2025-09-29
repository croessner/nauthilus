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

// FlushRuleCmdStatus is a structure representing the status of a Flush Rule command
type FlushRuleCmdStatus struct {
	// IPAddress is the IP address that the rule was applied to
	IPAddress string `json:"ip_address"`

	// RuleName is the name of the rule that was flushed
	RuleName string `json:"rule_name"`

	// Protocol is the protocol associated with the rule that was flushed
	Protocol string `json:"protocol,omitempty"`

	// OIDCCID is the OIDC Client ID associated with the rule that was flushed
	OIDCCID string `json:"oidc_cid,omitempty"`

	// RemovedKeys contains a list of Redis keys that were successfully removed during the flush operation.
	RemovedKeys []string `json:"removed_keys"`

	// Status is the current status of the rule following the Flush Command
	Status string `json:"status"`
}

// FlushRuleCmd represents a command to flush a specific rule.
// It contains the necessary information needed to identify the rule to be flushed.
type FlushRuleCmd struct {
	// IPAddress is the IP address associated with the rule to be flushed.
	// It must be in a format valid for an IP address.
	IPAddress string `json:"ip_address" binding:"required,ip"`

	// RuleName is the name of the rule to be flushed.
	// This value should reference an existing rule.
	RuleName string `json:"rule_name" binding:"required"`

	// Protocol is the optional protocol associated with the rule to be flushed.
	// If specified, only rules with matching protocol will be flushed.
	Protocol string `json:"protocol,omitempty"`

	// OIDCCID is the optional OIDC Client ID associated with the rule to be flushed.
	// If specified, only rules with matching OIDC Client ID will be flushed.
	OIDCCID string `json:"oidc_cid,omitempty"`
}
