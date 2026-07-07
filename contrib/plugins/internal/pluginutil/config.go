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

// Package pluginutil contains narrow helpers shared by bundled native plugins.
package pluginutil

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// ParseDefaultedDuration parses a non-negative duration with a fallback for empty input.
func ParseDefaultedDuration(name string, value string, fallback time.Duration) (time.Duration, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return fallback, nil
	}

	duration, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", name, err)
	}

	if duration < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}

	return duration, nil
}

// ParsePositiveDefaultedDuration parses a positive duration with a fallback for empty input.
func ParsePositiveDefaultedDuration(name string, value string, fallback time.Duration) (time.Duration, error) {
	duration, err := ParseDefaultedDuration(name, value, fallback)
	if err != nil {
		return 0, err
	}

	if duration <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return duration, nil
}

// ParsePositiveDefaultedInt parses a positive integer with a fallback for zero input.
func ParsePositiveDefaultedInt(name string, value int, fallback int) (int, error) {
	if value == 0 {
		value = fallback
	}

	if value <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return value, nil
}

// ParsePositiveDefaultedInt64 parses a positive int64 with a fallback for zero input.
func ParsePositiveDefaultedInt64(name string, value int64, fallback int64) (int64, error) {
	if value == 0 {
		value = fallback
	}

	if value <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return value, nil
}

// ValidateOptionalHTTPURL returns a normalized HTTP(S) URL or an empty string.
func ValidateOptionalHTTPURL(name string, value string) (string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", nil
	}

	parsed, err := url.Parse(text)
	if err != nil {
		return "", fmt.Errorf("%s must be a valid URL: %w", name, err)
	}

	if parsed.Scheme != schemeHTTP && parsed.Scheme != schemeHTTPS {
		return "", fmt.Errorf("%s must use http or https", name)
	}

	if strings.TrimSpace(parsed.Hostname()) == "" {
		return "", fmt.Errorf("%s host must not be empty", name)
	}

	return parsed.String(), nil
}

// RemoteAddressFromURL extracts a host:port target suitable for connection observability.
func RemoteAddressFromURL(value string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Hostname() == "" {
		return "", false
	}

	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case schemeHTTP:
			port = "80"
		case schemeHTTPS:
			port = "443"
		default:
			return "", false
		}
	}

	if number, err := strconv.Atoi(port); err != nil || number <= 0 || number > 65535 {
		return "", false
	}

	return net.JoinHostPort(parsed.Hostname(), port), true
}
