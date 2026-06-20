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

package util

import (
	"regexp"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
)

const (
	macroCaptureGroupCapacity = 3
	emailAddressPartCount     = 2
)

var macroPattern = regexp.MustCompile(`%([LURT]*)?\{([^\}]*)\}`)

// MacroSource holds all values that might be used in macros.
type MacroSource struct {
	Username    string
	UserDN      string
	Account     string
	XLocalIP    string
	XPort       string
	ClientIP    string
	XClientPort string
	TOTPSecret  string
	Protocol    config.Protocol
}

type macroReplacement struct {
	source    string
	modifier  string
	variable  string
	lowerCase bool
	upperCase bool
	replaced  bool
}

/*
ReplaceMacros replaces several macros with values found in the Authentication object.

%Modifiers{long variables}

Modifiers: (Optional):
L - Lower
U - Upper

R - Reverse the string
T - Trim the string

Long variavles:
user - full username, i.e. localpart@domain.tld
username - the local part of {user}, if user has a domain part, else user and username are the same
domain - the domain part of {user}. Empty string, if {user} did not contain a domain part
service - The service name, i.e. imap, pop3, lmtp
local_ip - local IP address
local_port - local port
remote_ip - remote client IP address
remote_port - remote client port.
account - authenticated account name
user_dn - LDAP distinguished name of the current user
*/
func (m *MacroSource) ReplaceMacros(source string) (dest string) {
	replacement, ok := newMacroReplacement(source)
	if !ok {
		return source
	}

	value, shouldReplace := m.macroValue(replacement)
	if shouldReplace {
		dest = replacement.replaceFirst(value)
	}

	return m.ReplaceMacros(dest)
}

// newMacroReplacement parses the first macro occurrence in source.
func newMacroReplacement(source string) (macroReplacement, bool) {
	searchResult := macroPattern.FindSubmatch([]byte(source))
	if searchResult == nil {
		return macroReplacement{}, false
	}

	macroResult := make([]string, 0, macroCaptureGroupCapacity)
	for _, findings := range searchResult {
		macroResult = append(macroResult, string(findings))
	}

	if macroResult[2] == "" {
		return macroReplacement{}, false
	}

	result := macroReplacement{
		source:   source,
		modifier: macroResult[1],
		variable: macroResult[2],
	}
	result.applyModifiers()

	return result, true
}

// applyModifiers records the effective case modifiers for a macro.
func (r *macroReplacement) applyModifiers() {
	for _, modifier := range r.modifier {
		switch string(modifier) {
		case "L":
			r.lowerCase = !r.upperCase
		case "U":
			r.upperCase = !r.lowerCase
		}
	}
}

// macroValue resolves the configured long variable to its escaped value.
func (m *MacroSource) macroValue(replacement macroReplacement) (string, bool) {
	switch replacement.variable {
	case "user":
		return replacement.applyCaseAndEscape(m.Username), true
	case "username":
		return replacement.applyCaseAndEscape(m.localUsername()), true
	case "domain":
		return replacement.applyCaseAndEscape(m.usernameDomain()), true
	case "service":
		return replacement.applyCaseAndEscape(m.Protocol.Get()), true
	case "local_ip":
		return replacement.applyCaseAndEscape(m.XLocalIP), true
	case "local_port":
		return EscapeLDAPFilter(m.XPort), true
	case "remote_ip":
		return replacement.applyCaseAndEscape(m.ClientIP), true
	case "remote_port":
		return EscapeLDAPFilter(m.XClientPort), true
	case "totp_secret":
		return EscapeLDAPFilter(m.TOTPSecret), true
	case "account":
		return replacement.applyCaseAndEscape(m.Account), true
	case "user_dn":
		return replacement.applyCaseAndEscape(m.UserDN), true
	}

	return "", false
}

// localUsername returns the username part used by the legacy macro implementation.
func (m *MacroSource) localUsername() string {
	split := m.splitUsername()
	if len(split) == emailAddressPartCount {
		return split[0]
	}

	return m.Username
}

// usernameDomain returns the domain part used by the legacy macro implementation.
func (m *MacroSource) usernameDomain() string {
	split := m.splitUsername()
	if len(split) == emailAddressPartCount {
		return split[1]
	}

	return ""
}

// splitUsername returns at most two address parts to match the legacy macro behavior.
func (m *MacroSource) splitUsername() []string {
	if strings.Contains(m.Username, "@") {
		split := strings.Split(m.Username, "@")
		if len(split) <= emailAddressPartCount {
			return split
		}
	}

	return []string{}
}

// applyCaseAndEscape applies supported case modifiers and LDAP escaping.
func (r macroReplacement) applyCaseAndEscape(value string) string {
	if r.lowerCase {
		value = strings.ToLower(value)
	} else if r.upperCase {
		value = strings.ToUpper(value)
	}

	return EscapeLDAPFilter(value)
}

// replaceFirst substitutes only the first macro occurrence in the original source.
func (r *macroReplacement) replaceFirst(value string) string {
	return macroPattern.ReplaceAllStringFunc(r.source, func(val string) string {
		if r.replaced {
			return val
		}

		r.replaced = true

		return macroPattern.ReplaceAllString(val, value)
	})
}

// ExpandLDAPFilter replaces legacy placeholders and macros using LDAP-safe escaping.
// It supports both `%s` and `%{...}` syntax.
func ExpandLDAPFilter(filter string, macroSource *MacroSource) string {
	if macroSource == nil {
		return filter
	}

	expanded := strings.ReplaceAll(filter, "%s", EscapeLDAPFilter(macroSource.Username))

	return macroSource.ReplaceMacros(expanded)
}
