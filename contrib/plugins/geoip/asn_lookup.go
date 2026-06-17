// Copyright (C) 2026 Christian Roessner
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

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxASNLookupResponseBytes = 128 << 20

type asnRouteFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

type httpASNRouteFetcher struct {
	client *http.Client
}

type asnLookupService struct {
	snapshot *asnLookupSnapshot
	mu       sync.RWMutex
}

type asnLookupSnapshot struct {
	trie     asnLookupTrie
	loadedAt time.Time
	records  int
}

type asnLookupTrie struct {
	root4 *asnLookupTrieNode
	root6 *asnLookupTrieNode
}

type asnLookupTrieNode struct {
	zero   *asnLookupTrieNode
	one    *asnLookupTrieNode
	record *geoRecord
}

type asnLookupRoute struct {
	record geoRecord
	prefix netip.Prefix
}

// Fetch downloads one ASN routing source with a bounded response size.
func (f httpASNRouteFetcher) Fetch(ctx context.Context, sourceURL string) ([]byte, error) {
	return fetchHTTPSource(ctx, f.client, sourceURL, maxASNLookupResponseBytes, "ASN routing")
}

// newASNLookupService creates an empty local ASN routing lookup service.
func newASNLookupService() *asnLookupService {
	return &asnLookupService{}
}

// Lookup resolves one address against the current local routing snapshot.
func (s *asnLookupService) Lookup(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	if s == nil {
		return geoRecord{}, false, nil
	}

	select {
	case <-ctx.Done():
		return geoRecord{}, false, ctx.Err()
	default:
	}

	snapshot := s.currentSnapshot()
	if snapshot == nil {
		return geoRecord{}, false, nil
	}

	record, matched := snapshot.Lookup(addr)

	return record, matched, nil
}

// Swap publishes a new routing snapshot for subsequent request-time lookups.
func (s *asnLookupService) Swap(snapshot *asnLookupSnapshot) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot = snapshot
}

// currentSnapshot returns the active snapshot without holding the lock during lookup.
func (s *asnLookupService) currentSnapshot() *asnLookupSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.snapshot
}

// fetchASNLookupSnapshot downloads, resolves, parses, and merges routing sources.
func fetchASNLookupSnapshot(
	ctx context.Context,
	fetcher asnRouteFetcher,
	sourceURLs []string,
	timeout time.Duration,
) (*asnLookupSnapshot, error) {
	contents, err := fetchSourceContents(ctx, fetcher, sourceURLs, timeout, "ASN routing fetcher is nil", fetchASNLookupSource)
	if err != nil {
		return nil, err
	}

	return buildASNLookupSnapshot(contents)
}

// fetchASNLookupSource applies a per-source timeout and follows creation logs.
func fetchASNLookupSource(
	ctx context.Context,
	fetcher sourceBytesFetcher,
	sourceURL string,
	timeout time.Duration,
) ([]byte, error) {
	raw, err := fetchSourceWithTimeout(ctx, fetcher, sourceURL, timeout)
	if err != nil {
		return nil, err
	}

	latestURL, ok, err := latestASNLookupSnapshotURL(sourceURL, raw)
	if err != nil {
		return nil, err
	}

	if !ok {
		return raw, nil
	}

	return fetchSourceWithTimeout(ctx, fetcher, latestURL, timeout)
}

// buildASNLookupSnapshot merges route source files into a trie lookup snapshot.
func buildASNLookupSnapshot(contents [][]byte) (*asnLookupSnapshot, error) {
	snapshot := &asnLookupSnapshot{loadedAt: time.Now().UTC()}

	for index, raw := range contents {
		decoded, err := decodeASNLookupContent(raw)
		if err != nil {
			return nil, fmt.Errorf("decode ASN routing source %d: %w", index, err)
		}

		routes, err := parseASNLookupRoutes(decoded)
		if err != nil {
			return nil, fmt.Errorf("parse ASN routing source %d: %w", index, err)
		}

		for _, route := range routes {
			snapshot.trie.Insert(route.prefix, route.record)
			snapshot.records++
		}
	}

	if snapshot.records == 0 {
		return nil, fmt.Errorf("ASN routing data contains no prefixes")
	}

	return snapshot, nil
}

// Lookup returns the longest-prefix ASN match for one address.
func (s *asnLookupSnapshot) Lookup(addr netip.Addr) (geoRecord, bool) {
	if s == nil {
		return geoRecord{}, false
	}

	return s.trie.Lookup(addr.Unmap())
}

// Records reports how many routing prefixes are available.
func (s *asnLookupSnapshot) Records() int {
	if s == nil {
		return 0
	}

	return s.records
}

// Insert stores one route record at its masked prefix in the trie.
func (t *asnLookupTrie) Insert(prefix netip.Prefix, record geoRecord) {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return
	}

	root := t.root(prefix.Addr())
	if root == nil {
		return
	}

	node := root

	for bit := 0; bit < prefix.Bits(); bit++ {
		if addrBit(prefix.Addr(), bit) {
			if node.one == nil {
				node.one = &asnLookupTrieNode{}
			}

			node = node.one

			continue
		}

		if node.zero == nil {
			node.zero = &asnLookupTrieNode{}
		}

		node = node.zero
	}

	stored := record
	node.record = &stored
}

// Lookup walks the trie and returns the most specific matching route.
func (t asnLookupTrie) Lookup(addr netip.Addr) (geoRecord, bool) {
	root := t.lookupRoot(addr)
	if root == nil {
		return geoRecord{}, false
	}

	node := root
	match := node.record

	for bit := 0; bit < addrBits(addr); bit++ {
		if addrBit(addr, bit) {
			node = node.one
		} else {
			node = node.zero
		}

		if node == nil {
			break
		}

		if node.record != nil {
			match = node.record
		}
	}

	if match == nil {
		return geoRecord{}, false
	}

	return *match, true
}

// root returns the mutable trie root for an address family.
func (t *asnLookupTrie) root(addr netip.Addr) *asnLookupTrieNode {
	if addr.Is4() {
		if t.root4 == nil {
			t.root4 = &asnLookupTrieNode{}
		}

		return t.root4
	}

	if addr.Is6() {
		if t.root6 == nil {
			t.root6 = &asnLookupTrieNode{}
		}

		return t.root6
	}

	return nil
}

// lookupRoot returns the immutable trie root for an address family.
func (t asnLookupTrie) lookupRoot(addr netip.Addr) *asnLookupTrieNode {
	if addr.Is4() {
		return t.root4
	}

	if addr.Is6() {
		return t.root6
	}

	return nil
}

// addrBits reports the address width used while traversing the trie.
func addrBits(addr netip.Addr) int {
	if addr.Is4() {
		return 32
	}

	if addr.Is6() {
		return 128
	}

	return 0
}

// addrBit returns one network-order address bit.
func addrBit(addr netip.Addr, bit int) bool {
	if addr.Is4() {
		raw := addr.As4()

		return raw[bit/8]&(1<<uint(7-bit%8)) != 0
	}

	raw := addr.As16()

	return raw[bit/8]&(1<<uint(7-bit%8)) != 0
}

// latestASNLookupSnapshotURL resolves a CAIDA pfx2as creation log to its newest snapshot URL.
func latestASNLookupSnapshotURL(sourceURL string, raw []byte) (string, bool, error) {
	parsed, err := url.Parse(sourceURL)
	if err != nil {
		return "", false, fmt.Errorf("parse ASN routing source URL: %w", err)
	}

	if path.Base(parsed.Path) != "pfx2as-creation.log" {
		return "", false, nil
	}

	latestPath, err := latestASNLookupCreationLogPath(raw)
	if err != nil {
		return "", false, err
	}

	resolved, err := resolveASNLookupPath(parsed, latestPath)
	if err != nil {
		return "", false, err
	}

	return resolved, true, nil
}

// latestASNLookupCreationLogPath returns the last valid path from a creation log.
func latestASNLookupCreationLogPath(raw []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	latestPath := ""
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())
		if shouldSkipASNLookupLine(line) {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			return "", fmt.Errorf("creation log line %d has too few fields", lineNumber)
		}

		latestPath = fields[2]
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if latestPath == "" {
		return "", fmt.Errorf("creation log contains no snapshot paths")
	}

	return latestPath, nil
}

// resolveASNLookupPath resolves a relative creation-log path against the log URL.
func resolveASNLookupPath(baseURL *url.URL, latestPath string) (string, error) {
	trimmed := strings.TrimSpace(latestPath)
	if trimmed == "" {
		return "", fmt.Errorf("snapshot path must not be empty")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse snapshot path: %w", err)
	}

	if parsed.IsAbs() {
		return parsed.String(), nil
	}

	resolved := *baseURL
	resolved.Path = path.Join(path.Dir(baseURL.Path), trimmed)
	resolved.RawQuery = ""
	resolved.Fragment = ""

	return resolved.String(), nil
}

// decodeASNLookupContent inflates gzip-compressed routing snapshots.
func decodeASNLookupContent(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return raw, nil
	}

	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()

	limited := io.LimitReader(reader, maxASNLookupResponseBytes+1)

	decoded, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	if len(decoded) > maxASNLookupResponseBytes {
		return nil, fmt.Errorf("decoded ASN routing data exceeds %d bytes", maxASNLookupResponseBytes)
	}

	return decoded, nil
}

// parseASNLookupRoutes extracts routing prefixes from supported text formats.
func parseASNLookupRoutes(raw []byte) ([]asnLookupRoute, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	routes := make([]asnLookupRoute, 0)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())
		if shouldSkipASNLookupLine(line) {
			continue
		}

		route, err := parseASNLookupRouteLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}

		routes = append(routes, route)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return routes, nil
}

// parseASNLookupRouteLine converts one route row into a prefix record.
func parseASNLookupRouteLine(line string) (asnLookupRoute, error) {
	fields := splitASNLookupFields(line)
	if len(fields) < 2 {
		return asnLookupRoute{}, fmt.Errorf("ASN routing row has too few fields")
	}

	if prefix, ok, err := parseASNLookupPrefix(fields[0]); err != nil {
		return asnLookupRoute{}, err
	} else if ok {
		return buildASNLookupRoute(prefix, fields[1], fields[2:])
	}

	if prefix, ok, err := parseASNLookupPrefix(fields[1]); err != nil {
		return asnLookupRoute{}, err
	} else if ok {
		return buildASNLookupRoute(prefix, fields[0], fields[2:])
	}

	if len(fields) >= 3 {
		if prefix, ok, err := parseASNLookupPfx2ASPrefix(fields[0], fields[1]); err != nil {
			return asnLookupRoute{}, err
		} else if ok {
			return buildASNLookupRoute(prefix, fields[2], fields[3:])
		}
	}

	return asnLookupRoute{}, fmt.Errorf("ASN routing row must contain a prefix and ASN")
}

// splitASNLookupFields normalizes supported separators while preserving AS set tokens.
func splitASNLookupFields(line string) []string {
	withoutComment := line
	if index := strings.Index(withoutComment, "#"); index >= 0 {
		withoutComment = withoutComment[:index]
	}

	return strings.FieldsFunc(withoutComment, func(char rune) bool {
		return char == '|' || char == ';' || char == '\t' || char == ' '
	})
}

// parseASNLookupPrefix parses CIDR notation fields.
func parseASNLookupPrefix(value string) (netip.Prefix, bool, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, false, nil
	}

	return prefix.Masked(), true, nil
}

// parseASNLookupPfx2ASPrefix parses CAIDA pfx2as address and prefix-length fields.
func parseASNLookupPfx2ASPrefix(addressText string, bitsText string) (netip.Prefix, bool, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(addressText))
	if err != nil {
		return netip.Prefix{}, false, nil
	}

	bits, err := strconv.Atoi(strings.TrimSpace(bitsText))
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("prefix length must be numeric: %w", err)
	}

	prefix := netip.PrefixFrom(addr, bits)
	if !prefix.IsValid() {
		return netip.Prefix{}, false, fmt.Errorf("prefix length %d is invalid for %s", bits, addr)
	}

	return prefix.Masked(), true, nil
}

// buildASNLookupRoute maps parsed route fields into plugin facts.
func buildASNLookupRoute(prefix netip.Prefix, asnToken string, metadata []string) (asnLookupRoute, error) {
	asn, err := parseASNLookupASN(asnToken)
	if err != nil {
		return asnLookupRoute{}, err
	}

	record := geoRecord{
		ASN:       asn,
		ASNPrefix: prefix.Masked().String(),
	}

	if len(metadata) > 0 {
		record.ASNCountryISO = strings.ToUpper(metadata[0])
	}

	if len(metadata) > 1 {
		record.ASNRegistry = strings.ToLower(metadata[1])
	}

	if len(metadata) > 2 {
		record.ASNAllocated = metadata[2]
	}

	if len(metadata) > 3 {
		record.ASNStatus = metadata[3]
	}

	return asnLookupRoute{prefix: prefix.Masked(), record: record}, nil
}

// parseASNLookupASN returns the first ASN from a plain, AS-prefixed, set, or MOAS token.
func parseASNLookupASN(value string) (int, error) {
	text := strings.TrimSpace(value)
	text = strings.Trim(text, "{}")
	text = strings.TrimPrefix(strings.ToUpper(text), "AS")

	end := 0
	for end < len(text) && text[end] >= '0' && text[end] <= '9' {
		end++
	}

	if end == 0 {
		return 0, fmt.Errorf("ASN must start with digits")
	}

	asn64, err := strconv.ParseInt(text[:end], 10, 0)
	if err != nil {
		return 0, fmt.Errorf("ASN must be numeric: %w", err)
	}

	if asn64 <= 0 {
		return 0, fmt.Errorf("ASN must be positive")
	}

	return int(asn64), nil
}

// mergeASNLookupRecord adds local ASN routing data without overwriting GeoIP location facts.
func mergeASNLookupRecord(record *geoRecord, asnRecord geoRecord) {
	if record == nil {
		return
	}

	record.ASN = asnRecord.ASN
	record.ASNPrefix = asnRecord.ASNPrefix
	record.ASNCountryISO = asnRecord.ASNCountryISO
	record.ASNRegistry = asnRecord.ASNRegistry

	if asnRecord.ASNAllocated != "" {
		record.ASNAllocated = asnRecord.ASNAllocated
	}

	if asnRecord.ASNStatus != "" {
		record.ASNStatus = asnRecord.ASNStatus
	}
}

// shouldSkipASNLookupLine reports whether a routing source line is informational.
func shouldSkipASNLookupLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}
