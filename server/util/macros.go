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

	"github.com/croessner/nauthilus/server/config"
)

// MacroSource holds all values that might be used in macros.
type MacroSource struct {
	Username    string
	XLocalIP    string
	XPort       string
	ClientIP    string
	XClientPort string
	TOTPSecret  *string
	Protocol    config.Protocol
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
*/
//nolint:gocognit,gocyclo // Ignore
func (m *MacroSource) ReplaceMacros(source string) (dest string) {
	var (
		flag      bool
		lowerCase bool
		upperCase bool

		user     string
		username string
		domain   string

		service  string
		localIP  string
		remoteIP string
	)

	macroResult := make([]string, 0, 3) //nolint:gomnd // Preallocate three
	pattern := `%([LURT]*)?\{([^\}]*)\}`
	regObj := regexp.MustCompile(pattern)

	searchResult := regObj.FindSubmatch([]byte(source))
	if searchResult == nil {
		return source
	}

	for _, findings := range searchResult {
		macroResult = append(macroResult, string(findings))
	}

	if macroResult[2] == "" {
		return source
	}

	// Modifiers
	for _, modifier := range macroResult[1] {
		switch string(modifier) {
		case "L":
			lowerCase = !upperCase
		case "U":
			upperCase = !lowerCase
		}
	}

	splitUsername := func() []string {
		if strings.Contains(m.Username, "@") {
			split := strings.Split(m.Username, "@")
			//nolint:gomnd // E-mail address format
			if len(split) <= 2 {
				return split
			}
		}

		return []string{}
	}

	// Long variables
	switch macroResult[2] {
	case "user":
		switch {
		case lowerCase:
			user = strings.ToLower(m.Username)
		case upperCase:
			user = strings.ToUpper(m.Username)
		default:
			user = m.Username
		}

		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, user)
		})
	case "username":
		split := splitUsername()
		//nolint:gomnd // E-mail address format
		if len(split) == 2 {
			username = split[0]
		} else {
			username = m.Username
		}

		if lowerCase {
			username = strings.ToLower(username)
		} else if upperCase {
			username = strings.ToUpper(username)
		}

		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, username)
		})
	case "domain":
		split := splitUsername()
		//nolint:gomnd // E-mail address format
		if len(split) == 2 {
			domain = split[1]
		}

		if lowerCase {
			domain = strings.ToLower(domain)
		} else if upperCase {
			domain = strings.ToUpper(domain)
		}

		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, domain)
		})
	case "service":
		switch {
		case lowerCase:
			service = strings.ToLower(m.Protocol.Get())
		case upperCase:
			service = strings.ToUpper(m.Protocol.Get())
		default:
			service = m.Protocol.Get()
		}

		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, service)
		})
	case "local_ip":
		switch {
		case lowerCase:
			localIP = strings.ToLower(m.XLocalIP)
		case upperCase:
			localIP = strings.ToUpper(m.XLocalIP)
		default:
			localIP = m.XLocalIP
		}

		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, localIP)
		})
	case "local_port":
		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, m.XPort)
		})
	case "remote_ip":
		switch {
		case lowerCase:
			remoteIP = strings.ToLower(m.ClientIP)
		case upperCase:
			remoteIP = strings.ToUpper(m.ClientIP)
		default:
			remoteIP = m.ClientIP
		}

		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, remoteIP)
		})
	case "remote_port":
		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, m.XClientPort)
		})
	case "totp_secret":
		dest = regObj.ReplaceAllStringFunc(source, func(val string) string {
			if flag {
				return val
			}

			flag = true

			return regObj.ReplaceAllString(val, *m.TOTPSecret)
		})
	}

	return m.ReplaceMacros(dest)
}
