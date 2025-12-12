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

package monitoring

import "testing"

func TestResolveServiceNamePrefersConfiguredNonIP(t *testing.T) {
	t.Parallel()

	got := ResolveServiceName("custom-service", "127.0.0.1", "nauthilus-server")
	if got != "custom-service" {
		t.Fatalf("expected custom-service, got %q", got)
	}
}

func TestResolveServiceNameSkipsIPInstanceName(t *testing.T) {
	t.Parallel()

	got := ResolveServiceName("", "127.0.0.1", "nauthilus-server")
	if got == "127.0.0.1" {
		t.Fatalf("expected service name not to be an IP, got %q", got)
	}
}

func TestResolveServiceNameSkipsIPTracingServiceName(t *testing.T) {
	t.Parallel()

	got := ResolveServiceName("127.0.0.1", "instance", "nauthilus-server")
	if got != "instance" {
		t.Fatalf("expected instance, got %q", got)
	}
}
