// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

type privacyClass string

const (
	privacyClassTor          privacyClass = "tor_exit"
	privacyClassKnownVPN     privacyClass = "known_vpn_exit"
	privacyClassPublicProxy  privacyClass = "public_proxy"
	privacyClassRelay        privacyClass = "privacy_relay"
	privacyClassCommunityVPN privacyClass = "community_vpn_exit"
	privacyClassSharedEgress privacyClass = "shared_egress"
	privacyClassHosting      privacyClass = "hosting"
)

var privacyClassOrder = []privacyClass{
	privacyClassTor,
	privacyClassKnownVPN,
	privacyClassPublicProxy,
	privacyClassRelay,
	privacyClassCommunityVPN,
	privacyClassSharedEgress,
	privacyClassHosting,
}

var privacyAuthorityOrder = []privacyAuthority{
	privacyAuthorityOfficial,
	privacyAuthorityOperator,
	privacyAuthorityCommunity,
	privacyAuthorityDerived,
}

type privacySnapshot struct {
	Entries     []privacyEntry    `json:"entries"`
	SourceID    string            `json:"source_id"`
	Kind        privacySourceKind `json:"kind"`
	Authority   privacyAuthority  `json:"authority"`
	GeneratedAt time.Time         `json:"generated_at"`
	ConfirmedAt time.Time         `json:"confirmed_at"`
	LoadedAt    time.Time         `json:"loaded_at"`
	MaxAge      time.Duration     `json:"max_age"`
}

type privacyEntry struct {
	Prefix     netip.Prefix `json:"prefix"`
	Class      privacyClass `json:"class"`
	Provider   string       `json:"provider,omitempty"`
	Confidence int          `json:"confidence"`
}

type privacyEvidence struct {
	GeneratedAt time.Time
	ConfirmedAt time.Time
	Prefix      netip.Prefix
	Class       privacyClass
	Authority   privacyAuthority
	SourceID    string
	Provider    string
	MaxAge      time.Duration
	Confidence  int
}

type privacyLookupResult struct {
	Classes      []privacyClass
	Authorities  []privacyAuthority
	PrimaryClass privacyClass
	State        string
	Confidence   int
	DataAge      time.Duration
	Stale        bool
}

const (
	privacyLookupStateEvaluated   = "evaluated"
	privacyLookupStateInvalidIP   = "invalid_ip"
	privacyLookupStateNoSources   = "no_sources"
	privacyLookupStateUnavailable = "unavailable"
	privacyLookupStateStale       = "stale"
)

type normalizedPrivacyFile struct {
	Source        normalizedPrivacySource  `json:"source"`
	Entries       []normalizedPrivacyEntry `json:"entries"`
	SchemaVersion int                      `json:"schema_version"`
}

type normalizedPrivacySource struct {
	ID          string           `json:"id"`
	Description string           `json:"description"`
	Authority   privacyAuthority `json:"authority"`
	License     string           `json:"license"`
	LicenseURL  string           `json:"license_url"`
	GeneratedAt time.Time        `json:"generated_at"`
	ValidUntil  time.Time        `json:"valid_until"`
}

type normalizedPrivacyEntry struct {
	Network    string         `json:"network"`
	Classes    []privacyClass `json:"classes"`
	Provider   string         `json:"provider"`
	Confidence int            `json:"confidence"`
}

type onionooPrivacyDocument struct {
	Relays []onionooPrivacyRelay `json:"relays"`
}

type onionooPrivacyRelay struct {
	ExitAddresses []string `json:"exit_addresses"`
	Flags         []string `json:"flags"`
	Running       bool     `json:"running"`
}

type privacyLookupIndex struct {
	exact    map[netip.Addr][]privacyEvidence
	prefixes privacyPrefixTrie
}

type privacyPrefixTrie struct {
	root4 *privacyPrefixTrieNode
	root6 *privacyPrefixTrieNode
}

type privacyPrefixTrieNode struct {
	zero     *privacyPrefixTrieNode
	one      *privacyPrefixTrieNode
	evidence []privacyEvidence
}

// parseNormalizedPrivacySnapshot validates one complete versioned normalized candidate.
func parseNormalizedPrivacySnapshot(raw []byte, config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	decoded, err := decodeNormalizedPrivacyFile(raw, config)
	if err != nil {
		return privacySnapshot{}, err
	}

	entries, err := parseNormalizedPrivacyEntries(decoded.Entries, config)
	if err != nil {
		return privacySnapshot{}, err
	}

	return privacySnapshot{Entries: deduplicatePrivacyEntries(entries), SourceID: config.ID, Kind: config.Kind, Authority: config.Authority, GeneratedAt: decoded.Source.GeneratedAt, ConfirmedAt: now, LoadedAt: now, MaxAge: config.MaxAge}, nil
}

// decodeNormalizedPrivacyFile validates schema and source-level metadata.
func decodeNormalizedPrivacyFile(raw []byte, config privacySourceConfig) (normalizedPrivacyFile, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var decoded normalizedPrivacyFile
	if err := decoder.Decode(&decoded); err != nil {
		return normalizedPrivacyFile{}, fmt.Errorf("decode normalized privacy source %q: %w", config.ID, err)
	}

	if err := validateNormalizedPrivacyMetadata(decoded, config); err != nil {
		return normalizedPrivacyFile{}, err
	}

	return decoded, nil
}

// validateNormalizedPrivacyMetadata checks schema, provenance, freshness, and bounds.
func validateNormalizedPrivacyMetadata(decoded normalizedPrivacyFile, config privacySourceConfig) error {
	if decoded.SchemaVersion != 1 {
		return fmt.Errorf("privacy source %q uses unsupported schema version %d", config.ID, decoded.SchemaVersion)
	}

	if decoded.Source.ID != config.ID || decoded.Source.Authority != config.Authority {
		return fmt.Errorf("privacy source %q metadata does not match configuration", config.ID)
	}

	if decoded.Source.GeneratedAt.IsZero() {
		return fmt.Errorf("privacy source %q generated_at is required", config.ID)
	}

	if !decoded.Source.ValidUntil.IsZero() && !decoded.Source.ValidUntil.After(decoded.Source.GeneratedAt) {
		return fmt.Errorf("privacy source %q valid_until must follow generated_at", config.ID)
	}

	if config.Authority == privacyAuthorityCommunity && (decoded.Source.License == "" || decoded.Source.LicenseURL == "") {
		return fmt.Errorf("community privacy source %q lacks license metadata", config.ID)
	}

	if len(decoded.Entries) == 0 || len(decoded.Entries) > config.MaxEntries {
		return fmt.Errorf("privacy source %q entry count is outside configured bounds", config.ID)
	}

	return nil
}

// parseNormalizedPrivacyEntries validates and expands bounded class records.
func parseNormalizedPrivacyEntries(raw []normalizedPrivacyEntry, config privacySourceConfig) ([]privacyEntry, error) {
	entries := make([]privacyEntry, 0, len(raw))

	for index, item := range raw {
		prefix, err := netip.ParsePrefix(item.Network)
		if err != nil {
			return nil, fmt.Errorf("privacy source %q entries[%d].network: %w", config.ID, index, err)
		}

		if err := validatePrivacyFeedPrefix(prefix); err != nil {
			return nil, fmt.Errorf("privacy source %q entries[%d].network: %w", config.ID, index, err)
		}

		classes, err := validatePrivacyClasses(item.Classes)
		if err != nil {
			return nil, fmt.Errorf("privacy source %q entries[%d].classes: %w", config.ID, index, err)
		}

		confidence := item.Confidence
		if confidence == 0 {
			confidence = config.Confidence
		}

		if err := validatePrivacyConfidence(config.Authority, confidence); err != nil {
			return nil, fmt.Errorf("privacy source %q entries[%d]: %w", config.ID, index, err)
		}

		for _, class := range classes {
			entries = append(entries, privacyEntry{Prefix: prefix.Masked(), Class: class, Provider: boundedPrivacyValue(item.Provider), Confidence: confidence})
			if len(entries) > config.MaxEntries {
				return nil, fmt.Errorf("privacy source %q expanded entry count exceeds configured bounds", config.ID)
			}
		}
	}

	return entries, nil
}

// parseTorPrivacySnapshot validates address lines from TorDNSEL, CollecTor, or bulk exit exports.
func parseTorPrivacySnapshot(raw []byte, config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		return parseOnionooPrivacySnapshot(raw, config, now)
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	entries := make([]privacyEntry, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)

		candidate, metadata, err := parseTorLine(fields)
		if err != nil {
			return privacySnapshot{}, fmt.Errorf("tor source %q: %w", config.ID, err)
		}

		if metadata {
			continue
		}

		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			return privacySnapshot{}, fmt.Errorf("tor source %q contains invalid address %q", config.ID, candidate)
		}

		addr = addr.Unmap()
		if err := validatePrivacyFeedPrefix(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
			return privacySnapshot{}, fmt.Errorf("tor source %q contains non-public address %q", config.ID, candidate)
		}

		entries = append(entries, privacyEntry{Prefix: netip.PrefixFrom(addr, addr.BitLen()), Class: privacyClassTor, Confidence: 100})
		if len(entries) > config.MaxEntries {
			return privacySnapshot{}, fmt.Errorf("tor source %q exceeds entry limit", config.ID)
		}
	}

	if err := scanner.Err(); err != nil {
		return privacySnapshot{}, fmt.Errorf("read Tor source %q: %w", config.ID, err)
	}

	if len(entries) == 0 {
		return privacySnapshot{}, fmt.Errorf("tor source %q has no exit addresses", config.ID)
	}

	return privacySnapshot{Entries: deduplicatePrivacyEntries(entries), SourceID: config.ID, Kind: config.Kind, Authority: privacyAuthorityOfficial, GeneratedAt: now, ConfirmedAt: now, LoadedAt: now, MaxAge: config.MaxAge}, nil
}

// parseOnionooPrivacySnapshot validates running Exit relays from one bounded details response.
func parseOnionooPrivacySnapshot(raw []byte, config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	var decoded onionooPrivacyDocument
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return privacySnapshot{}, fmt.Errorf("decode Onionoo Tor source %q: %w", config.ID, err)
	}

	entries := make([]privacyEntry, 0)

	for relayIndex, relay := range decoded.Relays {
		if !relay.Running || !slices.Contains(relay.Flags, "Exit") {
			continue
		}

		for addressIndex, value := range relay.ExitAddresses {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return privacySnapshot{}, fmt.Errorf("onionoo tor source %q relays[%d].exit_addresses[%d]: %w", config.ID, relayIndex, addressIndex, err)
			}

			addr = addr.Unmap()
			if err := validatePrivacyFeedPrefix(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
				return privacySnapshot{}, fmt.Errorf("onionoo tor source %q relays[%d].exit_addresses[%d] is not public", config.ID, relayIndex, addressIndex)
			}

			entries = append(entries, privacyEntry{Prefix: netip.PrefixFrom(addr, addr.BitLen()), Class: privacyClassTor, Confidence: 100})
			if len(entries) > config.MaxEntries {
				return privacySnapshot{}, fmt.Errorf("onionoo tor source %q exceeds entry limit", config.ID)
			}
		}
	}

	if len(entries) == 0 {
		return privacySnapshot{}, fmt.Errorf("onionoo tor source %q has no running exit addresses", config.ID)
	}

	return privacySnapshot{Entries: deduplicatePrivacyEntries(entries), SourceID: config.ID, Kind: config.Kind, Authority: privacyAuthorityOfficial, GeneratedAt: now, ConfirmedAt: now, LoadedAt: now, MaxAge: config.MaxAge}, nil
}

// validatePrivacyFeedPrefix rejects address classes that cannot represent public exits.
func validatePrivacyFeedPrefix(prefix netip.Prefix) error {
	addr := prefix.Addr().Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return fmt.Errorf("prefix %q is not a public unicast network", prefix)
	}

	return nil
}

// parseTorLine validates TorDNSEL and CollecTor metadata or returns one exit address.
func parseTorLine(fields []string) (string, bool, error) { //nolint:gocyclo // The bounded TorDNSEL record grammar is clearer as an explicit dispatch.
	if len(fields) == 0 {
		return "", true, nil
	}

	switch fields[0] {
	case "@type":
		if len(fields) != 3 || fields[1] != "tordnsel" || fields[2] != "1.0" {
			return "", false, fmt.Errorf("unsupported TorDNSEL type declaration")
		}

		return "", true, nil
	case "ExitNode":
		if len(fields) != 2 || len(fields[1]) != 40 || !isASCIIHex(fields[1]) {
			return "", false, fmt.Errorf("invalid ExitNode fingerprint")
		}

		return "", true, nil
	case "Published", "LastStatus":
		if len(fields) != 3 {
			return "", false, fmt.Errorf("invalid %s timestamp", fields[0])
		}

		if _, err := time.Parse("2006-01-02 15:04:05", fields[1]+" "+fields[2]); err != nil {
			return "", false, fmt.Errorf("invalid %s timestamp", fields[0])
		}

		return "", true, nil
	case "ExitAddress":
		if len(fields) != 4 {
			return "", false, fmt.Errorf("invalid ExitAddress record")
		}

		if _, err := time.Parse("2006-01-02 15:04:05", fields[2]+" "+fields[3]); err != nil {
			return "", false, fmt.Errorf("invalid ExitAddress timestamp")
		}

		return fields[1], false, nil
	default:
		if len(fields) != 1 {
			return "", false, fmt.Errorf("unsupported Tor exit-list record %q", fields[0])
		}

		return fields[0], false, nil
	}
}

// isASCIIHex validates bounded Tor relay fingerprints without allocating decoded bytes.
func isASCIIHex(value string) bool {
	for _, char := range value {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') {
			continue
		}

		return false
	}

	return true
}

// newPrivacyLookupIndex builds immutable exact-address and broader-prefix indexes.
func newPrivacyLookupIndex(snapshots []privacySnapshot) *privacyLookupIndex {
	index := &privacyLookupIndex{exact: make(map[netip.Addr][]privacyEvidence)}

	for _, snapshot := range snapshots {
		for _, entry := range snapshot.Entries {
			evidence := privacyEvidence{GeneratedAt: snapshot.GeneratedAt, ConfirmedAt: snapshot.ConfirmedAt, Prefix: entry.Prefix, Class: entry.Class, Authority: snapshot.Authority, SourceID: snapshot.SourceID, Provider: entry.Provider, MaxAge: snapshot.MaxAge, Confidence: entry.Confidence}
			prefix := entry.Prefix.Masked()

			if prefix.Bits() == prefix.Addr().BitLen() {
				address := prefix.Addr().Unmap()
				index.exact[address] = append(index.exact[address], evidence)

				continue
			}

			index.prefixes.Insert(prefix, evidence)
		}
	}

	for address := range index.exact {
		sortPrivacyEvidence(index.exact[address])
	}

	index.prefixes.Sort()

	return index
}

// Lookup returns evidence from every matching prefix without scanning the global entry set.
func (i *privacyLookupIndex) Lookup(addr netip.Addr) []privacyEvidence {
	if i == nil || !addr.IsValid() {
		return nil
	}

	addr = addr.Unmap()
	prefixEvidence := i.prefixes.Lookup(addr)
	exactEvidence := i.exact[addr]

	if len(prefixEvidence) == 0 {
		return exactEvidence[:len(exactEvidence):len(exactEvidence)]
	}

	result := make([]privacyEvidence, 0, len(prefixEvidence)+len(exactEvidence))
	result = append(result, prefixEvidence...)
	result = append(result, exactEvidence...)

	return result
}

// Insert stores broader-prefix evidence at its matching trie node.
func (t *privacyPrefixTrie) Insert(prefix netip.Prefix, evidence privacyEvidence) {
	prefix = prefix.Masked()
	root := t.insertRoot(prefix.Addr())
	node := root

	for bit := 0; bit < prefix.Bits(); bit++ {
		if addrBit(prefix.Addr(), bit) {
			if node.one == nil {
				node.one = &privacyPrefixTrieNode{}
			}

			node = node.one
		} else {
			if node.zero == nil {
				node.zero = &privacyPrefixTrieNode{}
			}

			node = node.zero
		}
	}

	node.evidence = append(node.evidence, evidence)
}

// Lookup collects evidence until the first missing address branch.
func (t privacyPrefixTrie) Lookup(addr netip.Addr) []privacyEvidence {
	node := t.lookupRoot(addr)
	if node == nil {
		return nil
	}

	result := append([]privacyEvidence(nil), node.evidence...)

	for bit := 0; bit < addrBits(addr); bit++ {
		if addrBit(addr, bit) {
			node = node.one
		} else {
			node = node.zero
		}

		if node == nil {
			break
		}

		result = append(result, node.evidence...)
	}

	return result
}

// Sort orders evidence stored at every populated trie node.
func (t privacyPrefixTrie) Sort() {
	sortPrivacyPrefixTrieNode(t.root4)
	sortPrivacyPrefixTrieNode(t.root6)
}

// insertRoot returns the address-family root, creating it when necessary.
func (t *privacyPrefixTrie) insertRoot(addr netip.Addr) *privacyPrefixTrieNode {
	if addr.Unmap().Is4() {
		if t.root4 == nil {
			t.root4 = &privacyPrefixTrieNode{}
		}

		return t.root4
	}

	if t.root6 == nil {
		t.root6 = &privacyPrefixTrieNode{}
	}

	return t.root6
}

// lookupRoot returns the address-family root without allocating it.
func (t privacyPrefixTrie) lookupRoot(addr netip.Addr) *privacyPrefixTrieNode {
	if addr.Unmap().Is4() {
		return t.root4
	}

	return t.root6
}

// sortPrivacyPrefixTrieNode recursively sorts one bounded-depth trie branch.
func sortPrivacyPrefixTrieNode(node *privacyPrefixTrieNode) {
	if node == nil {
		return
	}

	sortPrivacyEvidence(node.evidence)
	sortPrivacyPrefixTrieNode(node.zero)
	sortPrivacyPrefixTrieNode(node.one)
}

// mergePrivacyEvidence creates a deterministic classification view without policy decisions.
func mergePrivacyEvidence(evidence []privacyEvidence, now time.Time) privacyLookupResult {
	if len(evidence) == 0 {
		return privacyLookupResult{}
	}

	copyOfEvidence := append([]privacyEvidence(nil), evidence...)
	sortPrivacyEvidence(copyOfEvidence)

	result := privacyLookupResult{}
	seenClasses := make(map[privacyClass]struct{})
	seenAuthorities := make(map[privacyAuthority]struct{})

	for _, item := range copyOfEvidence {
		if _, found := seenClasses[item.Class]; !found {
			seenClasses[item.Class] = struct{}{}
			result.Classes = append(result.Classes, item.Class)
		}

		if _, found := seenAuthorities[item.Authority]; !found {
			seenAuthorities[item.Authority] = struct{}{}
			result.Authorities = append(result.Authorities, item.Authority)
		}

		if result.PrimaryClass == "" {
			result.PrimaryClass = item.Class
			result.Confidence = item.Confidence
		}

		ageOrigin := item.GeneratedAt
		if ageOrigin.IsZero() {
			ageOrigin = item.ConfirmedAt
		}

		age := max(now.Sub(ageOrigin), 0)
		if age > result.DataAge {
			result.DataAge = age
		}

		if item.MaxAge > 0 && now.Sub(item.ConfirmedAt) > item.MaxAge {
			result.Stale = true
		}
	}

	return result
}

// applyPrivacyOverrides adds operator evidence and suppresses only permitted weaker evidence.
func applyPrivacyOverrides(addr netip.Addr, evidence []privacyEvidence, overrides []privacyOverrideConfig, now time.Time) []privacyEvidence {
	result := evidence
	copied := false

	for _, override := range overrides {
		if (!override.ExpiresAt.IsZero() && !override.ExpiresAt.After(now)) || !override.Network.Contains(addr) {
			continue
		}

		if !copied {
			result = append([]privacyEvidence(nil), evidence...)
			copied = true
		}

		result = slices.DeleteFunc(result, func(item privacyEvidence) bool {
			if !slices.Contains(override.SuppressClasses, item.Class) {
				return false
			}

			return item.Authority != privacyAuthorityOfficial || override.SuppressOfficial
		})

		for _, class := range override.AddClasses {
			result = append(result, privacyEvidence{GeneratedAt: now, ConfirmedAt: now, Prefix: override.Network, Class: class, Authority: privacyAuthorityOperator, SourceID: "override", MaxAge: 24 * time.Hour, Confidence: 100})
		}
	}

	return result
}

// parsePrivacyClasses converts configured class names into validated enum values.
func parsePrivacyClasses(values []string) ([]privacyClass, error) {
	classes := make([]privacyClass, 0, len(values))
	for _, value := range values {
		classes = append(classes, privacyClass(value))
	}

	return validatePrivacyClasses(classes)
}

// validatePrivacyClasses rejects empty and unsupported classifications.
func validatePrivacyClasses(classes []privacyClass) ([]privacyClass, error) {
	if len(classes) == 0 {
		return nil, fmt.Errorf("at least one class is required")
	}

	result := make([]privacyClass, 0, len(classes))
	for _, class := range classes {
		if !slices.Contains(privacyClassOrder, class) {
			return nil, fmt.Errorf("class %q is unsupported", class)
		}

		if !slices.Contains(result, class) {
			result = append(result, class)
		}
	}

	return result, nil
}

// validatePrivacyConfidence enforces evidence-authority confidence caps.
func validatePrivacyConfidence(authority privacyAuthority, confidence int) error {
	capValue := 100

	switch authority {
	case privacyAuthorityCommunity:
		capValue = maximumCommunityConfidence
	case privacyAuthorityDerived:
		capValue = maximumDerivedConfidence
	}

	if confidence < 0 || confidence > capValue {
		return fmt.Errorf("confidence must be between 0 and %d", capValue)
	}

	return nil
}

// deduplicatePrivacyEntries canonicalizes duplicate source-prefix-class records.
func deduplicatePrivacyEntries(entries []privacyEntry) []privacyEntry {
	sort.SliceStable(entries, func(left, right int) bool {
		leftKey := entries[left].Prefix.String() + "\x00" + string(entries[left].Class) + "\x00" + entries[left].Provider
		rightKey := entries[right].Prefix.String() + "\x00" + string(entries[right].Class) + "\x00" + entries[right].Provider

		return leftKey < rightKey
	})

	return slices.CompactFunc(entries, func(left, right privacyEntry) bool {
		return left.Prefix == right.Prefix && left.Class == right.Class && left.Provider == right.Provider
	})
}

// sortPrivacyEvidence orders authority, class, prefix, and source deterministically.
func sortPrivacyEvidence(evidence []privacyEvidence) {
	sort.SliceStable(evidence, func(left, right int) bool {
		leftAuthority := slices.Index(privacyAuthorityOrder, evidence[left].Authority)
		rightAuthority := slices.Index(privacyAuthorityOrder, evidence[right].Authority)

		if leftAuthority != rightAuthority {
			return leftAuthority < rightAuthority
		}

		leftClass := slices.Index(privacyClassOrder, evidence[left].Class)
		rightClass := slices.Index(privacyClassOrder, evidence[right].Class)

		if leftClass != rightClass {
			return leftClass < rightClass
		}

		if evidence[left].Prefix.Bits() != evidence[right].Prefix.Bits() {
			return evidence[left].Prefix.Bits() < evidence[right].Prefix.Bits()
		}

		return evidence[left].SourceID < evidence[right].SourceID
	})
}

// boundedPrivacyValue prevents provider metadata from becoming unbounded internal state.
func boundedPrivacyValue(value string) string {
	const maximumLength = 128
	if len(value) <= maximumLength {
		return value
	}

	return value[:maximumLength]
}
