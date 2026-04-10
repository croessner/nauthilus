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

package idp

import (
	"net/url"
	"regexp"
	"strings"
)

var loopbackRedirectHosts = map[string]struct{}{
	"localhost": {},
	"127.0.0.1": {},
	"::1":       {},
}

// any access to parent folder /../ is unsafe with or without encoding
var unsafeRedirectPathPattern = regexp.MustCompile(`(?i)(/|%2f|%5c|\\)(%2e|\.){2}(/|%2f|%5c|\\)|(/|%2f|%5c|\\)(%2e|\.){2}$`)

// validateRedirectURIAgainstAllowList validates an incoming redirect URI against
// the configured allow-list with wildcard and loopback rules.
func validateRedirectURIAgainstAllowList(allowedURIs []string, redirectURI string) bool {
	if len(allowedURIs) == 0 {
		return false
	}

	requestURI, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	allowWildcards := areRedirectWildcardsAllowed(requestURI)
	requestScheme := requestURI.Scheme

	if matchesRedirectURIList(allowedURIs, redirectURI, requestScheme, allowWildcards) {
		return true
	}

	// Native-app compatibility:
	// allow dynamic loopback ports for HTTP redirects by comparing again
	// with the default HTTP port stripped from the incoming redirect URI.
	if strings.EqualFold(requestScheme, "http") && isLoopbackRedirectHost(requestURI.Hostname()) {
		redirectWithDefaultPort := normalizeRedirectURIWithoutPort(requestURI)

		if matchesRedirectURIList(allowedURIs, redirectWithDefaultPort, requestScheme, allowWildcards) {
			return true
		}
	}

	return false
}

// matchesRedirectURIList checks whether any configured allowed URI matches the
// incoming redirect URI and if the scheme constraints are satisfied.
func matchesRedirectURIList(allowedURIs []string, redirectURI string, requestScheme string, allowWildcards bool) bool {
	for _, allowedURI := range allowedURIs {
		if !matchesAllowedRedirectURI(allowedURI, redirectURI, allowWildcards) {
			continue
		}

		if !isRedirectSchemeAllowed(allowedURI, requestScheme) {
			continue
		}

		return true
	}

	return false
}

// matchesAllowedRedirectURI performs exact matching plus end-wildcard prefix
// matching when wildcard checks are allowed for the incoming redirect URI.
func matchesAllowedRedirectURI(allowedURI string, redirectURI string, allowWildcards bool) bool {
	if allowedURI == "*" {
		return true
	}

	if strings.HasSuffix(allowedURI, "*") && !strings.Contains(allowedURI, "?") && allowWildcards {
		redirectWithoutQueryOrFragment := stripRedirectURIQueryAndFragment(redirectURI)
		allowedURIPrefix := strings.TrimSuffix(allowedURI, "*")

		if strings.HasPrefix(redirectWithoutQueryOrFragment, allowedURIPrefix) {
			return true
		}

		if strings.HasSuffix(allowedURIPrefix, "/") && strings.TrimSuffix(allowedURIPrefix, "/") == redirectWithoutQueryOrFragment {
			return true
		}
	}

	return allowedURI == redirectURI
}

// isRedirectSchemeAllowed enforces scheme compatibility for wildcard patterns
// and preserves the special handling of the full wildcard for http/https.
func isRedirectSchemeAllowed(matchedAllowedURI string, requestScheme string) bool {
	if requestScheme == "" {
		return true
	}

	if strings.HasPrefix(matchedAllowedURI, requestScheme+":") {
		return true
	}

	return strings.EqualFold(requestScheme, "http") || strings.EqualFold(requestScheme, "https")
}

// stripRedirectURIQueryAndFragment removes query and fragment parts for
// wildcard prefix matching.
func stripRedirectURIQueryAndFragment(redirectURI string) string {
	index := strings.IndexAny(redirectURI, "?#")
	if index == -1 {
		return redirectURI
	}

	return redirectURI[:index]
}

// areRedirectWildcardsAllowed disables wildcard matching for redirect URIs with
// user-info or unsafe parent traversal path segments.
func areRedirectWildcardsAllowed(redirectURI *url.URL) bool {
	if redirectURI.User != nil {
		return false
	}

	escapedPath := redirectURI.EscapedPath()
	if escapedPath == "" {
		return true
	}

	return !unsafeRedirectPathPattern.MatchString(escapedPath)
}

// isLoopbackRedirectHost reports whether the host is a loopback host supported
// for dynamic native-app callback ports.
func isLoopbackRedirectHost(host string) bool {
	if host == "" {
		return false
	}

	_, found := loopbackRedirectHosts[strings.ToLower(host)]

	return found
}

// normalizeRedirectURIWithoutPort removes the explicit port from the URI while
// preserving scheme, path, query, and fragment.
func normalizeRedirectURIWithoutPort(redirectURI *url.URL) string {
	if redirectURI == nil {
		return ""
	}

	clone := *redirectURI
	hostname := redirectURI.Hostname()
	if hostname == "" {
		return ""
	}

	clone.Host = hostname
	if strings.Contains(hostname, ":") {
		clone.Host = "[" + hostname + "]"
	}

	return clone.String()
}
