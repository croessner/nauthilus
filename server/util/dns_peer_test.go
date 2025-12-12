// Copyright (C) 2025 Christian Rößner
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

package util

import "testing"

func TestDNSResolverPeerFromAddressLoopback(t *testing.T) {
	t.Parallel()

	tests := []string{
		"127.0.0.1",
		"127.0.0.1:53",
		"[::1]:53",
		"::1",
		"localhost",
		"localhost:53",
	}

	for _, tc := range tests {
		_, _, ok := DNSResolverPeerFromAddress(tc)
		if ok {
			t.Fatalf("expected loopback/localhost resolver %q to be suppressed", tc)
		}
	}
}

func TestDNSResolverPeerFromAddressParsesHostPort(t *testing.T) {
	t.Parallel()

	h, p, ok := DNSResolverPeerFromAddress("10.0.0.10:5353")
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if h != "10.0.0.10" || p != 5353 {
		t.Fatalf("expected 10.0.0.10:5353, got %q:%d", h, p)
	}
}

func TestDNSResolverPeerFromAddressDefaultsPort53(t *testing.T) {
	t.Parallel()

	h, p, ok := DNSResolverPeerFromAddress("dns.example")
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if h != "dns.example" || p != 53 {
		t.Fatalf("expected dns.example:53, got %q:%d", h, p)
	}
}
