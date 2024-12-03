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
	Lists         []RBL
	Threshold     int
	IPWhiteList   []string `mapstructure:"ip_whitelist"`
}

func (r *RBLSection) String() string {
	if r == nil {
		return "RBLSection: <nil>"
	}

	return fmt.Sprintf("RBLSection: {Lists[%+v] Threshold[%+v] Whitelist[%+v]}", r.Lists, r.Threshold, r.IPWhiteList)
}

type RBL struct {
	Name         string
	RBL          string
	IPv4         bool
	IPv6         bool
	AllowFailure bool   `mapstructure:"allow_failure"`
	ReturnCode   string `mapstructure:"return_code"`
	Weight       int
}
