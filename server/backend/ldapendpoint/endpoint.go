// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package ldapendpoint parses LDAP URIs into secret-free endpoint metadata.
package ldapendpoint

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var errInvalidEndpoint = errors.New("invalid LDAP endpoint")

const (
	schemeLDAP  = "ldap"
	schemeLDAPS = "ldaps"
	schemeLDAPI = "ldapi"
)

// Endpoint contains only trace-safe LDAP endpoint metadata.
type Endpoint struct {
	Scheme string
	Host   string
	Port   int
}

// Parse strips credentials and URI details while deriving the endpoint port.
func Parse(raw string) (Endpoint, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Endpoint{}, errInvalidEndpoint
	}

	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case schemeLDAP, schemeLDAPS:
		return parseTCPEndpoint(parsed, scheme)
	case schemeLDAPI:
		if parsed.Host != "" || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
			return Endpoint{}, errInvalidEndpoint
		}

		return Endpoint{Scheme: scheme, Host: parsed.Path}, nil
	default:
		return Endpoint{}, fmt.Errorf("%w: unsupported scheme %q", errInvalidEndpoint, scheme)
	}
}

// parseTCPEndpoint derives a host and port without retaining URI userinfo or paths.
func parseTCPEndpoint(parsed *url.URL, scheme string) (Endpoint, error) {
	host := parsed.Hostname()
	if host == "" {
		return Endpoint{}, errInvalidEndpoint
	}

	port := defaultPort(scheme)

	if rawPort := parsed.Port(); rawPort != "" {
		value, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || value == 0 {
			return Endpoint{}, errInvalidEndpoint
		}

		port = int(value)
	}

	return Endpoint{Scheme: scheme, Host: host, Port: port}, nil
}

// defaultPort returns the standard TCP port for an LDAP URI scheme.
func defaultPort(scheme string) int {
	if scheme == schemeLDAPS {
		return 636
	}

	return 389
}
