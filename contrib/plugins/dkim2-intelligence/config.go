package main

import (
	"errors"
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"net/netip"
	"strings"
)

var errConfig = errors.New("invalid DKIM2 intelligence configuration")

type rawConfig struct {
	SignerSets         map[string][]string   `mapstructure:"signer_sets"`
	IdentityContracts  []rawIdentityContract `mapstructure:"identity_contracts"`
	ReputationProvider string                `mapstructure:"reputation_provider"`
	ReputationFact     string                `mapstructure:"reputation_fact"`
	GeoIPProvider      string                `mapstructure:"geoip_provider"`
	DecisionProfile    string                `mapstructure:"decision_profile"`
}

type rawIdentityContract struct {
	SignerDomains    []string `mapstructure:"signer_domains"`
	SignerSets       []string `mapstructure:"signer_sets"`
	CurrentPeerCIDRs []string `mapstructure:"current_peer_cidrs"`
	CurrentPeerASNs  []int64  `mapstructure:"current_peer_asns"`
	Name             string   `mapstructure:"name"`
}

type configuration struct {
	contracts map[string]identityContract
	raw       rawConfig
}

type identityContract struct {
	prefixes []netip.Prefix
	asns     map[int64]struct{}
}

// decodeConfig compiles bounded operator identities and exact upstream owners without inferred provider trust.
func decodeConfig(input pluginapi.ConfigView) (*configuration, error) {
	var raw rawConfig
	if input == nil || input.IsZero() || input.Decode(&raw) != nil {
		return nil, errConfig
	}

	if !view.ValidProfile(raw.DecisionProfile) || !validProvider(raw.ReputationProvider) || !validProvider(raw.GeoIPProvider) {
		return nil, errConfig
	}

	module, _, _ := strings.Cut(strings.TrimPrefix(strings.Split(raw.ReputationProvider, "/")[1], valuePlugin), ".")
	if !strings.HasPrefix(raw.ReputationFact, valuePlugin+module+".") || len(raw.ReputationFact) > 128 {
		return nil, errConfig
	}

	if len(raw.IdentityContracts) > 256 || len(raw.SignerSets) > 64 {
		return nil, errConfig
	}

	cfg := &configuration{raw: raw, contracts: make(map[string]identityContract)}
	if err := cfg.compileContracts(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validProvider restricts each input owner to one exact native component in the DKIM2 namespace.
func validProvider(value string) bool {
	return strings.HasPrefix(value, "dkim2/") && pluginapi.ValidateDecisionProviderReference(value) == nil
}

// compileContracts rejects ambiguous domain ownership and malformed unused signer sets as well as active ones.
func (c *configuration) compileContracts() error {
	if err := c.validateSignerSets(); err != nil {
		return err
	}

	names := make(map[string]bool)
	for _, raw := range c.raw.IdentityContracts {
		if !validContractName(raw.Name) || names[raw.Name] {
			return errConfig
		}

		names[raw.Name] = true

		domains := append([]string(nil), raw.SignerDomains...)
		for _, name := range raw.SignerSets {
			members, exists := c.raw.SignerSets[name]
			if !exists {
				return errConfig
			}

			domains = append(domains, members...)
		}

		if validateDomains(domains) != nil {
			return errConfig
		}

		contract, err := compileIdentityNetworks(raw)
		if err != nil {
			return err
		}

		for _, domain := range domains {
			if _, exists := c.contracts[domain]; exists {
				return errConfig
			}

			c.contracts[domain] = contract
		}
	}

	return nil
}

// compileIdentityNetworks keeps exact network and broader ASN evidence independently typed.
func compileIdentityNetworks(raw rawIdentityContract) (identityContract, error) {
	result := identityContract{asns: make(map[int64]struct{})}
	if len(raw.CurrentPeerCIDRs) > 128 || len(raw.CurrentPeerASNs) > 128 {
		return result, errConfig
	}

	seen := make(map[netip.Prefix]bool)

	for _, text := range raw.CurrentPeerCIDRs {
		prefix, err := parseContractPrefix(text)
		if err != nil || seen[prefix] {
			return result, errConfig
		}

		seen[prefix] = true
		result.prefixes = append(result.prefixes, prefix)
	}

	for _, asn := range raw.CurrentPeerASNs {
		if _, exists := result.asns[asn]; exists || asn < 1 || asn > 4294967295 {
			return result, errConfig
		}

		result.asns[asn] = struct{}{}
	}

	return result, nil
}

// validateDomains requires a nonempty unique set of canonical signer identities.
func validateDomains(domains []string) error {
	if len(domains) == 0 || len(domains) > 256 {
		return errConfig
	}

	seen := make(map[string]bool)
	for _, domain := range domains {
		if !projection.CanonicalDomain(domain) || seen[domain] {
			return errConfig
		}

		seen[domain] = true
	}

	return nil
}

// validContractName accepts bounded operator labels without dynamic selectors.
func validContractName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}

	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}

	return true
}

// validateSignerSets validates operator sets even when no current contract references them.
func (c *configuration) validateSignerSets() error {
	for name, domains := range c.raw.SignerSets {
		if !validContractName(name) || validateDomains(domains) != nil {
			return errConfig
		}
	}

	return nil
}

// parseContractPrefix rejects ambiguous or noncanonical operator network identities.
func parseContractPrefix(text string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil || prefix != prefix.Masked() || prefix.String() != text || prefix.Addr().Is4In6() {
		return netip.Prefix{}, errConfig
	}

	return prefix, nil
}
