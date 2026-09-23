// Copyright (C) 2026 Christian Rößner
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

package registry

import (
	"net/netip"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// NetworkReferencePrefix identifies source-owned network condition-set references.
const NetworkReferencePrefix = "@network."

// NetworkSet is one immutable precompiled collection of cidr_contains operands.
type NetworkSet struct {
	prefixes  []netip.Prefix
	addresses []netip.Addr
}

// NewNetworkSet parses string operands once and skips values that are neither a prefix nor an address.
func NewNetworkSet(values []decision.Value) NetworkSet {
	var set NetworkSet

	for _, value := range values {
		network, ok := value.StringValue()
		if !ok {
			continue
		}

		if prefix, err := netip.ParsePrefix(network); err == nil {
			set.prefixes = append(set.prefixes, prefix)

			continue
		}

		// Exact addresses stay addresses so zoned IPv6 operands keep exact-equality semantics.
		if address, err := netip.ParseAddr(network); err == nil {
			set.addresses = append(set.addresses, address)
		}
	}

	return set
}

// Len returns the number of admitted prefix and exact-address operands.
func (s NetworkSet) Len() int {
	return len(s.prefixes) + len(s.addresses)
}

// Contains reports whether address lies in one prefix or equals one exact address.
func (s NetworkSet) Contains(address netip.Addr) bool {
	for _, prefix := range s.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}

	for _, exact := range s.addresses {
		if exact == address {
			return true
		}
	}

	return false
}
