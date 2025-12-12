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

import (
	"net"
	"os"
	"strings"
)

// ResolveServiceName determines the OpenTelemetry service name.
//
// Priority:
//  1. explicit tracing service name (if set and not an IP)
//  2. configured instance name (if set and not an IP)
//  3. hostname (if available and not an IP)
//  4. fallbackName
func ResolveServiceName(tracingServiceName string, instanceName string, fallbackName string) string {
	if s := strings.TrimSpace(tracingServiceName); s != "" && !looksLikeIP(s) {
		return s
	}

	if s := strings.TrimSpace(instanceName); s != "" && !looksLikeIP(s) {
		return s
	}

	h, err := os.Hostname()
	if err == nil {
		if s := strings.TrimSpace(h); s != "" && !looksLikeIP(s) {
			return s
		}
	}

	if s := strings.TrimSpace(fallbackName); s != "" {
		return s
	}

	return "nauthilus-server"
}

func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}

	host := strings.TrimSpace(s)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	return net.ParseIP(host) != nil
}
