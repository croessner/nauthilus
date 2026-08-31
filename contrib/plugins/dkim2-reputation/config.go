// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	reputationTrusted = "trusted"
	reputationNeutral = "neutral"
	reputationBlocked = "blocked"
	reputationUnknown = "unknown"
)

type rawAssessmentConfig struct {
	Domains   []rawDomainReputation  `mapstructure:"domains"`
	Networks  []rawNetworkReputation `mapstructure:"client_networks"`
	Contracts []rawDomainContract    `mapstructure:"contracts"`
}

type rawDomainReputation struct {
	Domain     string `mapstructure:"domain"`
	Reputation string `mapstructure:"reputation"`
}

type rawNetworkReputation struct {
	CIDR       string `mapstructure:"cidr"`
	Reputation string `mapstructure:"reputation"`
}

type rawDomainContract struct {
	Domain                 string   `mapstructure:"signer_domain"`
	AllowedClientCIDRs     []string `mapstructure:"allowed_client_cidrs"`
	PermittedChangeClasses []string `mapstructure:"permitted_change_classes"`
}

type assessmentConfig struct {
	domains   map[string]string
	contracts map[string]domainContract
	networks  []networkReputation
}

type networkReputation struct {
	prefix     netip.Prefix
	reputation string
}

type domainContract struct {
	allowedChanges map[string]struct{}
	allowedPeers   []netip.Prefix
}

// decodeAssessmentConfig parses and validates the complete operator-owned snapshot.
func decodeAssessmentConfig(view pluginapi.ConfigView) (*assessmentConfig, error) {
	var raw rawAssessmentConfig

	if view == nil || view.IsZero() {
		return nil, fmt.Errorf("dkim2 reputation config must not be empty")
	}

	if err := view.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode dkim2 reputation config: %w", err)
	}

	domains, err := parseDomainReputations(raw.Domains)
	if err != nil {
		return nil, err
	}

	networks, err := parseNetworkReputations(raw.Networks)
	if err != nil {
		return nil, err
	}

	contracts, err := parseDomainContracts(raw.Contracts)
	if err != nil {
		return nil, err
	}

	if len(domains) == 0 || len(networks) == 0 || len(contracts) == 0 {
		return nil, fmt.Errorf("domains, client_networks, and contracts must each contain at least one entry")
	}

	return &assessmentConfig{domains: domains, networks: networks, contracts: contracts}, nil
}

// parseDomainReputations validates exact canonical signer-domain classifications.
func parseDomainReputations(input []rawDomainReputation) (map[string]string, error) {
	result := make(map[string]string, len(input))

	for index, entry := range input {
		domain := entry.Domain
		if !canonicalDomain(domain) {
			return nil, fmt.Errorf("domains[%d].domain must be a canonical DNS domain", index)
		}

		if !configuredReputation(entry.Reputation) {
			return nil, fmt.Errorf("domains[%d].reputation must be trusted, neutral, or blocked", index)
		}

		if _, exists := result[domain]; exists {
			return nil, fmt.Errorf("domains[%d].domain duplicates %s", index, domain)
		}

		result[domain] = entry.Reputation
	}

	return result, nil
}

// parseNetworkReputations validates deterministic longest-prefix client classifications.
func parseNetworkReputations(input []rawNetworkReputation) ([]networkReputation, error) {
	result := make([]networkReputation, 0, len(input))
	seen := make(map[netip.Prefix]struct{}, len(input))

	for index, entry := range input {
		prefix, err := parseCanonicalPrefix(entry.CIDR)
		if err != nil {
			return nil, fmt.Errorf("client_networks[%d].cidr: %w", index, err)
		}

		if !configuredReputation(entry.Reputation) {
			return nil, fmt.Errorf("client_networks[%d].reputation must be trusted, neutral, or blocked", index)
		}

		if _, exists := seen[prefix]; exists {
			return nil, fmt.Errorf("client_networks[%d].cidr duplicates %s", index, prefix)
		}

		seen[prefix] = struct{}{}
		result = append(result, networkReputation{prefix: prefix, reputation: entry.Reputation})
	}

	slices.SortStableFunc(result, func(left networkReputation, right networkReputation) int {
		return right.prefix.Bits() - left.prefix.Bits()
	})

	return result, nil
}

// parseDomainContracts validates signer, peer-network, and Recipe authorization bindings.
func parseDomainContracts(input []rawDomainContract) (map[string]domainContract, error) {
	result := make(map[string]domainContract, len(input))

	for index, entry := range input {
		domain := entry.Domain
		if !canonicalDomain(domain) {
			return nil, fmt.Errorf("contracts[%d].signer_domain must be a canonical DNS domain", index)
		}

		if _, exists := result[domain]; exists {
			return nil, fmt.Errorf("contracts[%d].signer_domain duplicates %s", index, domain)
		}

		peers, err := parseContractPrefixes(index, entry.AllowedClientCIDRs)
		if err != nil {
			return nil, err
		}

		changes, err := parseContractChanges(index, entry.PermittedChangeClasses)
		if err != nil {
			return nil, err
		}

		result[domain] = domainContract{allowedPeers: peers, allowedChanges: changes}
	}

	return result, nil
}

// parseContractPrefixes requires a unique non-empty canonical peer allowlist.
func parseContractPrefixes(index int, input []string) ([]netip.Prefix, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("contracts[%d].allowed_client_cidrs must not be empty", index)
	}

	result := make([]netip.Prefix, 0, len(input))
	seen := make(map[netip.Prefix]struct{}, len(input))

	for peerIndex, value := range input {
		prefix, err := parseCanonicalPrefix(value)
		if err != nil {
			return nil, fmt.Errorf("contracts[%d].allowed_client_cidrs[%d]: %w", index, peerIndex, err)
		}

		if _, exists := seen[prefix]; exists {
			return nil, fmt.Errorf("contracts[%d].allowed_client_cidrs[%d] duplicates %s", index, peerIndex, prefix)
		}

		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}

	return result, nil
}

// parseContractChanges requires a sorted unique subset of the projection vocabulary.
func parseContractChanges(index int, input []string) (map[string]struct{}, error) {
	if !sortedUniqueStrings(input) {
		return nil, fmt.Errorf("contracts[%d].permitted_change_classes must be sorted and unique", index)
	}

	result := make(map[string]struct{}, len(input))
	for changeIndex, value := range input {
		if !allowedChangeClass(value) {
			return nil, fmt.Errorf("contracts[%d].permitted_change_classes[%d] is not supported", index, changeIndex)
		}

		result[value] = struct{}{}
	}

	return result, nil
}

// parseCanonicalPrefix rejects host-bit aliases and IPv4-mapped IPv6 prefixes.
func parseCanonicalPrefix(value string) (netip.Prefix, error) {
	text := strings.TrimSpace(value)
	if text != value {
		return netip.Prefix{}, fmt.Errorf("must not contain surrounding whitespace")
	}

	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("must be a valid prefix: %w", err)
	}

	if prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.String() != text {
		return netip.Prefix{}, fmt.Errorf("must be a canonical IPv4 or IPv6 prefix")
	}

	return prefix, nil
}

// configuredReputation reports whether a configuration value belongs to the explicit vocabulary.
func configuredReputation(value string) bool {
	return value == reputationTrusted || value == reputationNeutral || value == reputationBlocked
}
