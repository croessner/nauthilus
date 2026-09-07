package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

type geographicEvidence struct {
	state, country, org, prefix string
	age, asn                    int64
	hasASN                      bool
}

// decodeGeographic consumes only exact-address provider evidence and retains no raw peer address in the output view.
func decodeGeographic(values map[string]pluginapi.DecisionValue, peer netip.Addr) (geographicEvidence, error) {
	result := geographicEvidence{state: valueUnavailable}
	if len(values) == 0 {
		return result, nil
	}

	address, ok := values[valueIP].StringValue()
	if !ok || address != peer.String() {
		return result, errCorrelation
	}

	result.state, ok = values[valueLookupState].StringValue()
	if !ok {
		return result, errCorrelation
	}

	switch result.state {
	case valueFresh, valueStale:
		if err := result.decodeEvaluated(values, peer); err != nil {
			return geographicEvidence{}, err
		}
	case valueNotFound, valueUnavailable:
		for _, name := range []string{valueCountryIso, valueAsn, valueAsnOrg, valueAsnPrefix} {
			if _, present := values[name]; present {
				return geographicEvidence{}, errCorrelation
			}
		}
	default:
		return geographicEvidence{}, errCorrelation
	}

	return result, nil
}

// decodeEvaluated requires bounded source age before validating optional geographic detail.
func (g *geographicEvidence) decodeEvaluated(values map[string]pluginapi.DecisionValue, peer netip.Addr) error {
	age, valid := values[valueDataAgeSeconds].Integer()
	if !valid || age < 0 || age > 31536000 {
		return errCorrelation
	}

	g.age = age

	return g.decodeDetails(values, peer)
}

// decodeDetails validates optional country, ASN, organization and prefix as independent evidence.
func (g *geographicEvidence) decodeDetails(values map[string]pluginapi.DecisionValue, peer netip.Addr) error {
	if value, present := values[valueCountryIso]; present {
		country, valid := value.StringValue()
		if !valid || !validCountry(country) {
			return errCorrelation
		}

		g.country = country
	}

	if value, present := values[valueAsn]; present {
		number, valid := value.Integer()
		if !valid || number < 1 || number > 4294967295 {
			return errCorrelation
		}

		g.asn, g.hasASN = number, true
	}

	return g.decodeASNDetails(values, peer)
}

// decodeASNDetails rejects unsanitized organization text and prefixes unrelated to the exact peer.
func (g *geographicEvidence) decodeASNDetails(values map[string]pluginapi.DecisionValue, peer netip.Addr) error {
	if value, present := values[valueAsnOrg]; present {
		org, valid := value.StringValue()
		if !valid || !validOrganization(org) {
			return errCorrelation
		}

		g.org = org
	}

	if value, present := values[valueAsnPrefix]; present {
		prefix, valid := value.StringValue()
		if !valid || !g.hasASN || !validPeerPrefix(prefix, peer) {
			return errCorrelation
		}

		g.prefix = prefix
	}

	return nil
}

// validCountry recognizes an exact uppercase ISO country-code shape.
func validCountry(value string) bool {
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

// validOrganization requires bounded UTF-8 text without control characters.
func validOrganization(value string) bool {
	return len(value) <= 128 && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

// validPeerPrefix requires canonical network evidence containing the current peer.
func validPeerPrefix(value string, peer netip.Addr) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && len(value) <= 43 && prefix.String() == value && prefix == prefix.Masked() && prefix.Contains(peer)
}
