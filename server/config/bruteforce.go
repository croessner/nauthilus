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
	"time"
)

type BruteForceSection struct {
	SoftWhitelist `mapstructure:"soft_whitelist"`
	IPWhitelist   []string         `mapstructure:"ip_whitelist" validate:"omitempty,dive,ip_addr|cidr"`
	Buckets       []BruteForceRule `mapstructure:"buckets" validate:"required,dive"`
	Learning      []*Feature       `mapstructure:"learning" validate:"omitempty,dive"`
}

func (b *BruteForceSection) String() string {
	if b == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Buckets: %+v, IP-Whitelist: %+v", b.Buckets, b.IPWhitelist)
}

// LearnFromFeature checks if the given feature is present in the Learning slice of the BruteForceSection.
// It returns true if the feature is found, otherwise false.
func (b *BruteForceSection) LearnFromFeature(input string) bool {
	if b == nil {
		return false
	}

	if b.Learning == nil {
		return false
	}

	if len(b.Learning) == 0 {
		return false
	}

	for _, feature := range b.Learning {
		if input == feature.Get() {
			return true
		}
	}

	return false
}

// BruteForceRule is the definition of a brute force rule as defined in the configuration file. See the markdown
// documentation for a description of the field names.
type BruteForceRule struct {
	Name           string        `mapstructure:"name" validate:"required"`
	Period         time.Duration `mapstructure:"period" validate:"required,gt=0,max=8760h"`
	CIDR           uint          `mapstructure:"cidr" validate:"required,min=1,max=128"`
	IPv4           bool
	IPv6           bool
	FailedRequests uint `mapstructure:"failed_requests" validate:"required,min=1"`
}

func (b *BruteForceRule) String() string {
	if b == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Name: %s, Period: %s, CIDR: %d, IPv4: %t, IPv6: %t, FailedRequests: %d", b.Name, b.Period, b.CIDR, b.IPv4, b.IPv6, b.FailedRequests)
}
