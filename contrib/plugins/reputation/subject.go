package main

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var errSubject = errors.New("invalid reputation subject")

// canonicalSubject normalizes one admitted kind without leaking values in diagnostics.
func (c *configuration) canonicalSubject(kind, value string) (string, error) {
	if !boundedText(value, 512, false) {
		return "", errSubject
	}

	switch kind {
	case kindIP:
		return canonicalIP(value)
	case kindNetwork:
		return canonicalNetwork(value)
	case kindASN:
		return canonicalASN(value)
	case kindDomain:
		return canonicalDomain(value)
	case kindAccount:
		if c.raw.AccountNormalization == normalizeLowercase {
			return strings.ToLower(value), nil
		}

		return value, nil
	case kindService:
		normalized := strings.ToLower(value)
		if slices.Contains(c.raw.Services, normalized) {
			return normalized, nil
		}
	}

	return "", errSubject
}

// canonicalNetwork collapses host bits and equivalent mapped IPv4 prefixes.
func canonicalNetwork(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", errSubject
	}

	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return "", errSubject
		}

		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}

	return prefix.Masked().String(), nil
}

// canonicalASN normalizes a positive 32-bit autonomous system number.
func canonicalASN(value string) (string, error) {
	text := strings.TrimPrefix(strings.ToUpper(value), "AS")

	number, err := strconv.ParseUint(text, 10, 32)
	if err != nil || number == 0 || strings.HasPrefix(text, "+") {
		return "", errSubject
	}

	return strconv.FormatUint(number, 10), nil
}

// canonicalDomain validates IDNA DNS labels and normalizes one optional root dot.
func canonicalDomain(value string) (string, error) {
	text, err := idna.Lookup.ToASCII(strings.TrimSuffix(value, "."))
	if err != nil || len(text) == 0 || len(text) > 253 {
		return "", errSubject
	}

	text = strings.ToLower(text)
	for _, label := range strings.Split(text, ".") {
		if !validDomainLabel(label) {
			return "", errSubject
		}
	}

	return text, nil
}

// canonicalIP removes mapped aliases and rejects interface-local zone identifiers.
func canonicalIP(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return "", errSubject
	}

	return address.Unmap().String(), nil
}

// validDomainLabel checks the DNS A-label syntax after IDNA conversion.
func validDomainLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}

	return true
}

// networkSubject derives the configured prefix from an already validated canonical IP.
func (c *configuration) networkSubject(canonical string) string {
	address := netip.MustParseAddr(canonical)

	bits := c.raw.NetworkSubjects.IPv6Prefix
	if address.Is4() {
		bits = c.raw.NetworkSubjects.IPv4Prefix
	}

	return netip.PrefixFrom(address, bits).Masked().String()
}
