package main

import "net/netip"

type identityResult struct{ state, strength string }

// matchIdentity never attributes the current SMTP peer's network evidence to a historical signer.
func (c *configuration) matchIdentity(domain string, target bool, ip netip.Addr, asn int64, asnAvailable bool) identityResult {
	contract, exists := c.contracts[domain]
	if !exists {
		return identityResult{valueMissing, valueNone}
	}

	if !target {
		return identityResult{valueDomainOnly, valueDomainOnly}
	}

	for _, prefix := range contract.prefixes {
		if prefix.Contains(ip) {
			return identityResult{valueMatched, valueCidr}
		}
	}

	if _, matched := contract.asns[asn]; asnAvailable && matched {
		return identityResult{valueMatched, valueAsn}
	}

	if len(contract.asns) > 0 && !asnAvailable {
		return identityResult{valueUnavailable, valueNone}
	}

	if len(contract.asns) == 0 && len(contract.prefixes) == 0 {
		return identityResult{valueMissing, valueNone}
	}

	return identityResult{valueMismatch, valueNone}
}
