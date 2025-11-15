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

import "fmt"

type RBLSection struct {
	SoftWhitelist `mapstructure:"soft_whitelist"`
	Lists         []RBL    `mapstructure:"lists" validate:"required,dive"`
	Threshold     int      `mapstructure:"threshold" validate:"omitempty,min=0,max=100"`
	IPWhiteList   []string `mapstructure:"ip_whitelist" validate:"omitempty,dive,ip_addr|cidr"`
}

func (r *RBLSection) String() string {
	if r == nil {
		return "RBLSection: <nil>"
	}

	return fmt.Sprintf("RBLSection: {Lists[%+v] Threshold[%+v] Whitelist[%+v]}", r.Lists, r.Threshold, r.IPWhiteList)
}

// GetLists retrieves the list of RBL configurations from the RBLSection.
// Returns an empty slice if the RBLSection is nil.
func (r *RBLSection) GetLists() []RBL {
	if r == nil {
		return []RBL{}
	}

	return r.Lists
}

// GetThreshold retrieves the threshold value from the RBLSection.
// Returns 0 as a default value if the RBLSection is nil.
func (r *RBLSection) GetThreshold() int {
	if r == nil {
		return 0
	}

	return r.Threshold
}

// GetIPWhiteList retrieves the IP whitelist from the RBLSection.
// Returns an empty slice if the RBLSection is nil.
func (r *RBLSection) GetIPWhiteList() []string {
	if r == nil {
		return []string{}
	}

	return r.IPWhiteList
}

// GetSoftWhitelist retrieves the SoftWhitelist from the RBLSection.
// Returns nil if the RBLSection is nil.
func (r *RBLSection) GetSoftWhitelist() SoftWhitelist {
	if r == nil {
		return nil
	}

	return r.SoftWhitelist
}

type RBL struct {
	Name         string `mapstructure:"name" validate:"required"`
	RBL          string `mapstructure:"rbl" validate:"required,hostname_rfc1123_with_opt_trailing_dot"`
	IPv4         bool
	IPv6         bool
	AllowFailure bool     `mapstructure:"allow_failure"`
	ReturnCode   string   `mapstructure:"return_code" validate:"omitempty,ip4_addr"`
	ReturnCodes  []string `mapstructure:"return_codes" validate:"required,dive,ip4_addr"`
	Weight       int      `mapstructure:"weight" validate:"omitempty,min=-100,max=100"`
}

// GetName retrieves the name of the RBL.
// Returns an empty string if the RBL is nil.
func (r *RBL) GetName() string {
	if r == nil {
		return ""
	}

	return r.Name
}

// GetRBL retrieves the RBL hostname.
// Returns an empty string if the RBL is nil.
func (r *RBL) GetRBL() string {
	if r == nil {
		return ""
	}

	return r.RBL
}

// IsIPv4 checks if the RBL is configured for IPv4.
// Returns false if the RBL is nil.
func (r *RBL) IsIPv4() bool {
	if r == nil {
		return false
	}

	return r.IPv4
}

// IsIPv6 checks if the RBL is configured for IPv6.
// Returns false if the RBL is nil.
func (r *RBL) IsIPv6() bool {
	if r == nil {
		return false
	}

	return r.IPv6
}

// IsAllowFailure checks if failures are allowed for this RBL.
// Returns false if the RBL is nil.
func (r *RBL) IsAllowFailure() bool {
	if r == nil {
		return false
	}

	return r.AllowFailure
}

// GetReturnCode retrieves the return code for the RBL.
// Returns an empty string if the RBL is nil.
// Deprecated: Use GetReturnCodes() instead
func (r *RBL) GetReturnCode() string {
	if r == nil {
		return ""
	}

	return r.ReturnCode
}

// GetReturnCodes retrieves the list of return codes for the RBL.
// Returns an empty slice if the RBL is nil.
func (r *RBL) GetReturnCodes() []string {
	if r == nil {
		return []string{}
	}

	return r.ReturnCodes
}

// GetWeight retrieves the weight value for the RBL.
// Returns 0 if the RBL is nil.
func (r *RBL) GetWeight() int {
	if r == nil {
		return 0
	}

	return r.Weight
}
