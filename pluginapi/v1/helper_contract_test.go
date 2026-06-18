// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"testing"

	"github.com/croessner/nauthilus/pluginapi/v1/helpers"
)

func TestDeterministicHelpersMatchLuaContracts(t *testing.T) {
	tag := helpers.AccountTag("alice", helpers.DefaultAccountTagOptions())
	if tag != "{acm-6384e2b2184bcbf58eccf10ca7a6563c}" {
		t.Fatalf("AccountTag() = %q, want Lua-compatible hash tag", tag)
	}

	disabled := helpers.AccountTag("alice", helpers.AccountTagOptions{UseHashTags: false})
	if disabled != "" {
		t.Fatalf("AccountTag() with disabled hash tags = %q, want empty", disabled)
	}

	scopedIPv4 := helpers.ScopedIP("203.0.113.42", helpers.IPScopingOptions{IPv4CIDR: 24})
	if scopedIPv4 != "203.0.113.0/24" {
		t.Fatalf("ScopedIP() IPv4 = %q, want /24 network", scopedIPv4)
	}

	scopedIPv6 := helpers.ScopedIP("2001:db8:abcd:1234::1", helpers.IPScopingOptions{IPv6CIDR: 64})
	if scopedIPv6 != "2001:db8:abcd:1234::/64" {
		t.Fatalf("ScopedIP() IPv6 = %q, want /64 network", scopedIPv6)
	}

	if helpers.IsRoutableIP("10.0.0.1") {
		t.Fatal("IsRoutableIP() returned true for private IPv4")
	}

	if helpers.IsRoutableIP("0.1.2.3") {
		t.Fatal("IsRoutableIP() returned true for current-network IPv4")
	}

	if helpers.IsRoutableIP("203.0.113.9") {
		t.Fatal("IsRoutableIP() returned true for documentation IPv4")
	}

	if !helpers.IsRoutableIP("8.8.8.8") {
		t.Fatal("IsRoutableIP() returned false for public IPv4")
	}

	if helpers.IsRoutableIP("fc00::1") {
		t.Fatal("IsRoutableIP() returned true for unique-local IPv6")
	}

	if !helpers.IsRoutableIP("2001:4860:4860::8888") {
		t.Fatal("IsRoutableIP() returned false for public IPv6")
	}
}
