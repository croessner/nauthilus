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
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const maximumPrivacyPrefixLineBytes = 64 * 1024

type privacyPrefixSet struct {
	root4 *privacyPrefixSetNode
	root6 *privacyPrefixSetNode
}

type privacyPrefixSetNode struct {
	zero     *privacyPrefixSetNode
	one      *privacyPrefixSetNode
	prefix   netip.Prefix
	terminal bool
}

type privacyPrefixCollector struct {
	config privacySourceConfig
	set    privacyPrefixSet
	count  int
}

// parsePrivacySnapshotCandidate dispatches every local and remote source through one parser contract.
func parsePrivacySnapshotCandidate(raw []byte, config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	switch config.Kind {
	case privacySourceKindTor:
		return parseTorPrivacySnapshot(raw, config, now)
	case privacySourceKindNormalized:
		return parseNormalizedPrivacySnapshot(raw, config, now)
	case privacySourceKindCIDRList:
		return parseCIDRListPrivacySnapshot(raw, config, now)
	case privacySourceKindCIDRCSV:
		return parseCIDRCSVPrivacySnapshot(raw, config, now)
	default:
		return privacySnapshot{}, fmt.Errorf("unsupported privacy source kind %q", config.Kind)
	}
}

// parseCIDRListPrivacySnapshot validates one line-oriented public-prefix source.
func parseCIDRListPrivacySnapshot(raw []byte, config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	collector := privacyPrefixCollector{config: config}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	lineNumber := 0

	scanner.Buffer(make([]byte, 4096), maximumPrivacyPrefixLineBytes)

	for scanner.Scan() {
		lineNumber++
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if strings.ContainsAny(line, " \t") {
			return privacySnapshot{}, fmt.Errorf("CIDR source %q line %d must contain exactly one prefix", config.ID, lineNumber)
		}

		if err := collector.Add(line, fmt.Sprintf("line %d", lineNumber)); err != nil {
			return privacySnapshot{}, err
		}
	}

	if err := scanner.Err(); err != nil {
		return privacySnapshot{}, fmt.Errorf("read CIDR source %q: %w", config.ID, err)
	}

	return collector.Snapshot(now)
}

// parseCIDRCSVPrivacySnapshot validates one CSV source using its configured prefix column.
func parseCIDRCSVPrivacySnapshot(raw []byte, config privacySourceConfig, now time.Time) (privacySnapshot, error) {
	collector := privacyPrefixCollector{config: config}
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	recordNumber := 0

	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return privacySnapshot{}, fmt.Errorf("read CIDR CSV source %q record %d: %w", config.ID, recordNumber+1, err)
		}

		recordNumber++
		if len(record) > maximumPrivacyCSVColumn+1 {
			return privacySnapshot{}, fmt.Errorf("CIDR CSV source %q record %d exceeds the field limit", config.ID, recordNumber)
		}

		if config.HasHeader && recordNumber == 1 {
			if config.CIDRColumn >= len(record) {
				return privacySnapshot{}, fmt.Errorf("CIDR CSV source %q header lacks column %d", config.ID, config.CIDRColumn)
			}

			continue
		}

		if config.CIDRColumn >= len(record) {
			return privacySnapshot{}, fmt.Errorf("CIDR CSV source %q record %d lacks column %d", config.ID, recordNumber, config.CIDRColumn)
		}

		if err := collector.Add(strings.TrimSpace(record[config.CIDRColumn]), fmt.Sprintf("record %d", recordNumber)); err != nil {
			return privacySnapshot{}, err
		}
	}

	return collector.Snapshot(now)
}

// Add validates and inserts one untrusted prefix while bounding raw input work.
func (c *privacyPrefixCollector) Add(value string, position string) error {
	c.count++

	limit := c.config.MaxEntries

	if limit <= 0 {
		limit = defaultPrivacyMaxSnapshotEntries
	}

	if c.count > limit {
		return fmt.Errorf("CIDR source %q exceeds entry limit", c.config.ID)
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return fmt.Errorf("CIDR source %q %s contains invalid prefix %q", c.config.ID, position, value)
	}

	prefix = prefix.Masked()
	if err := validatePrivacyFeedPrefix(prefix); err != nil {
		return fmt.Errorf("CIDR source %q %s contains non-public prefix %q", c.config.ID, position, value)
	}

	c.set.Add(prefix)

	return nil
}

// Snapshot expands compacted prefixes into the configured immutable evidence classes.
func (c *privacyPrefixCollector) Snapshot(now time.Time) (privacySnapshot, error) {
	prefixes := c.set.Prefixes()
	if len(prefixes) == 0 {
		return privacySnapshot{}, fmt.Errorf("CIDR source %q has no prefixes", c.config.ID)
	}

	limit := c.config.MaxEntries
	if limit <= 0 {
		limit = defaultPrivacyMaxSnapshotEntries
	}

	if len(c.config.Classes) == 0 || len(prefixes) > limit/len(c.config.Classes) {
		return privacySnapshot{}, fmt.Errorf("CIDR source %q expanded entries exceed entry limit", c.config.ID)
	}

	entries := make([]privacyEntry, 0, len(prefixes)*len(c.config.Classes))
	for _, prefix := range prefixes {
		for _, class := range c.config.Classes {
			entries = append(entries, privacyEntry{Prefix: prefix, Class: class, Provider: c.config.Provider, Confidence: c.config.Confidence})
		}
	}

	return privacySnapshot{Entries: entries, SourceID: c.config.ID, Kind: c.config.Kind, Authority: c.config.Authority, GeneratedAt: now, ConfirmedAt: now, LoadedAt: now, MaxAge: c.config.MaxAge}, nil
}

// Add inserts one prefix and recursively merges complete sibling coverage.
func (s *privacyPrefixSet) Add(prefix netip.Prefix) {
	prefix = prefix.Masked()

	root := &s.root6

	if prefix.Addr().Is4() {
		root = &s.root4
	}

	if *root == nil {
		*root = &privacyPrefixSetNode{}
	}

	(*root).add(prefix, 0)
}

// Prefixes returns deterministic minimal prefixes with identical coverage.
func (s privacyPrefixSet) Prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0)
	appendPrivacyPrefixes(s.root4, &prefixes)
	appendPrivacyPrefixes(s.root6, &prefixes)

	sort.Slice(prefixes, func(left, right int) bool {
		comparison := prefixes[left].Addr().Compare(prefixes[right].Addr())
		if comparison == 0 {
			return prefixes[left].Bits() < prefixes[right].Bits()
		}

		return comparison < 0
	})

	return prefixes
}

// add inserts one prefix below the current family root.
func (n *privacyPrefixSetNode) add(prefix netip.Prefix, bit int) {
	if n.terminal {
		return
	}

	if bit == prefix.Bits() {
		n.prefix = prefix
		n.terminal = true
		n.zero = nil
		n.one = nil

		return
	}

	child := &n.zero
	if addrBit(prefix.Addr(), bit) {
		child = &n.one
	}

	if *child == nil {
		*child = &privacyPrefixSetNode{}
	}

	(*child).add(prefix, bit+1)

	if n.zero != nil && n.zero.terminal && n.one != nil && n.one.terminal {
		n.prefix = netip.PrefixFrom(prefix.Addr(), bit).Masked()
		n.terminal = true
		n.zero = nil
		n.one = nil
	}
}

// appendPrivacyPrefixes collects terminal nodes without descending covered branches.
func appendPrivacyPrefixes(node *privacyPrefixSetNode, prefixes *[]netip.Prefix) {
	if node == nil {
		return
	}

	if node.terminal {
		*prefixes = append(*prefixes, node.prefix)

		return
	}

	appendPrivacyPrefixes(node.zero, prefixes)
	appendPrivacyPrefixes(node.one, prefixes)
}
