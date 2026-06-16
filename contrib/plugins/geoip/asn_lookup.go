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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type asnDNSResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type asnLookupService struct {
	resolver asnDNSResolver
	config   asnLookupConfig
	cache    map[netip.Addr]asnLookupCacheEntry
	mu       sync.Mutex
}

type asnLookupCacheEntry struct {
	record  geoRecord
	expires time.Time
	matched bool
}

// newASNLookupService builds a Rspamd-compatible DNS ASN lookup service.
func newASNLookupService(config asnLookupConfig, resolver asnDNSResolver) *asnLookupService {
	if !config.Enabled {
		return nil
	}

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	return &asnLookupService{
		resolver: resolver,
		config:   config,
		cache:    make(map[netip.Addr]asnLookupCacheEntry),
	}
}

// Lookup resolves one address to ASN facts using the configured Rspamd-compatible DNS provider.
func (s *asnLookupService) Lookup(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	if s == nil {
		return geoRecord{}, false, nil
	}

	addr = addr.Unmap()

	now := time.Now()
	if record, matched, ok := s.cached(addr, now); ok {
		return record, matched, nil
	}

	record, matched, err := s.resolve(ctx, addr)
	if err != nil {
		return geoRecord{}, false, err
	}

	s.store(addr, record, matched, now)

	return record, matched, nil
}

// cached returns a fresh cache entry when one is available.
func (s *asnLookupService) cached(addr netip.Addr, now time.Time) (geoRecord, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.cache[addr]
	if !ok || !now.Before(entry.expires) {
		if ok {
			delete(s.cache, addr)
		}

		return geoRecord{}, false, false
	}

	return entry.record, entry.matched, true
}

// store records positive and negative DNS lookup results with bounded TTLs.
func (s *asnLookupService) store(addr netip.Addr, record geoRecord, matched bool, now time.Time) {
	ttl := s.config.NegativeCacheTTL
	if matched {
		ttl = s.config.CacheTTL
	}

	if ttl <= 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache[addr] = asnLookupCacheEntry{
		record:  record,
		expires: now.Add(ttl),
		matched: matched,
	}
}

// resolve performs the bounded DNS TXT query.
func (s *asnLookupService) resolve(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	queryName, err := rspamdASNQueryName(addr, s.config)
	if err != nil {
		return geoRecord{}, false, err
	}

	queryCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	answers, err := s.resolver.LookupTXT(queryCtx, queryName)
	if err != nil {
		if isASNLookupMiss(err) {
			return geoRecord{}, false, nil
		}

		return geoRecord{}, false, fmt.Errorf("lookup ASN TXT %q: %w", queryName, err)
	}

	for _, answer := range answers {
		record, err := parseRspamdASNAnswer(answer)
		if err == nil {
			return record, true, nil
		}
	}

	return geoRecord{}, false, fmt.Errorf("lookup ASN TXT %q returned no valid records", queryName)
}

// rspamdASNQueryName returns the reverse-address query name used by Rspamd's ASN provider.
func rspamdASNQueryName(addr netip.Addr, config asnLookupConfig) (string, error) {
	addr = addr.Unmap()
	if addr.Is4() {
		octets := addr.As4()

		return fmt.Sprintf("%d.%d.%d.%d.%s", octets[3], octets[2], octets[1], octets[0], config.IPv4Zone), nil
	}

	if !addr.Is6() {
		return "", fmt.Errorf("address %s is not IPv4 or IPv6", addr)
	}

	octets := addr.As16()

	parts := make([]string, 0, len(octets)*2)
	for index := len(octets) - 1; index >= 0; index-- {
		parts = append(parts, strconv.FormatUint(uint64(octets[index]&0x0f), 16))
		parts = append(parts, strconv.FormatUint(uint64(octets[index]>>4), 16))
	}

	return strings.Join(parts, ".") + "." + config.IPv6Zone, nil
}

// parseRspamdASNAnswer converts a Rspamd-compatible TXT response into plugin facts.
func parseRspamdASNAnswer(answer string) (geoRecord, error) {
	fields := strings.Fields(strings.ReplaceAll(answer, "|", " "))
	if len(fields) < 4 {
		return geoRecord{}, fmt.Errorf("ASN TXT response has too few fields")
	}

	asn, err := strconv.Atoi(fields[0])
	if err != nil || asn <= 0 {
		return geoRecord{}, fmt.Errorf("ASN TXT response has invalid ASN")
	}

	prefix, err := netip.ParsePrefix(fields[1])
	if err != nil {
		return geoRecord{}, fmt.Errorf("ASN TXT response has invalid prefix: %w", err)
	}

	record := geoRecord{
		ASN:           asn,
		ASNPrefix:     prefix.Masked().String(),
		ASNCountryISO: strings.ToUpper(fields[2]),
		ASNRegistry:   strings.ToLower(fields[3]),
	}

	if len(fields) > 4 {
		record.ASNAllocated = fields[4]
	}

	return record, nil
}

// mergeASNLookupRecord adds Rspamd-style ASN lookup data without overwriting GeoIP location facts.
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
}

// isASNLookupMiss reports resolver misses that should produce a negative cache entry.
func isASNLookupMiss(err error) bool {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return false
	}

	return dnsErr.IsNotFound
}
