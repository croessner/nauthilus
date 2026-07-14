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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/oschwald/maxminddb-golang"
)

var errGeoDatabaseEmpty = errors.New("geoip database has no records")

type geoDatabase interface {
	Lookup(context.Context, netip.Addr) (geoRecord, bool, error)
	Records() int
	Close() error
}

type databaseLoader func(context.Context, moduleConfig) (geoDatabase, error)

type maxMindReaderFactory interface {
	FromBytes([]byte) (*maxminddb.Reader, error)
}

type inMemoryMaxMindReaderFactory struct{}

type geoDatabases struct {
	primary geoDatabase
	asn     geoDatabase
}

type fileDatabase struct {
	records []geoRecord
}

type maxMindDatabase struct {
	reader *maxminddb.Reader
	path   string
}

type geoRecord struct {
	CountryISO    string
	CountryName   string
	CityName      string
	ASNOrg        string
	ASNPrefix     string
	ASNRegistry   string
	ASNCountryISO string
	ASNAllocated  string
	ASNStatus     string
	Prefix        netip.Prefix
	ASN           int
}

type maxMindRecord struct {
	Country           maxMindLocation `maxminddb:"country"`
	RegisteredCountry maxMindLocation `maxminddb:"registered_country"`
	City              maxMindLocation `maxminddb:"city"`
	Traits            maxMindTraits   `maxminddb:"traits"`
	ASNOrg            string          `maxminddb:"autonomous_system_organization"`
	ASN               uint            `maxminddb:"autonomous_system_number"`
}

type maxMindLocation struct {
	Names   map[string]string `maxminddb:"names"`
	ISOCode string            `maxminddb:"iso_code"`
}

type maxMindTraits struct {
	ASNOrg string `maxminddb:"autonomous_system_organization"`
	ASN    uint   `maxminddb:"autonomous_system_number"`
}

type databaseFile struct {
	Records []databaseRecord `json:"records"`
}

type databaseRecord struct {
	CIDR        string `json:"cidr"`
	CountryISO  string `json:"country_iso"`
	CountryName string `json:"country_name"`
	CityName    string `json:"city_name"`
	ASNOrg      string `json:"asn_org"`
	ASN         int    `json:"asn"`
}

// Ready reports whether the required primary database is available.
func (d geoDatabases) Ready() bool {
	return d.primary != nil
}

// Records reports the combined loaded record count for metrics.
func (d geoDatabases) Records() int {
	return d.PrimaryRecords() + d.ASNRecords()
}

// PrimaryRecords reports the primary GeoIP database record count.
func (d geoDatabases) PrimaryRecords() int {
	if d.primary == nil {
		return 0
	}

	return d.primary.Records()
}

// ASNRecords reports the optional ASN database record count.
func (d geoDatabases) ASNRecords() int {
	if d.asn == nil {
		return 0
	}

	return d.asn.Records()
}

// loadConfiguredDatabase loads the configured database format.
func loadConfiguredDatabase(ctx context.Context, config moduleConfig) (geoDatabase, error) {
	switch config.DatabaseFormat {
	case databaseFormatJSON:
		return loadFileDatabase(ctx, config.DatabasePath)
	case databaseFormatMMDB:
		return loadMaxMindDatabase(ctx, config.DatabasePath)
	default:
		return nil, fmt.Errorf("unsupported database_format %q", config.DatabaseFormat)
	}
}

// loadFileDatabase validates and loads a local JSON GeoIP fixture database.
func loadFileDatabase(ctx context.Context, path string) (*fileDatabase, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("database_path must be absolute: %s", path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read geoip database %q: %w", path, err)
	}

	var decoded databaseFile
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode geoip database %q: %w", path, err)
	}

	records, err := parseDatabaseRecords(decoded.Records)
	if err != nil {
		return nil, fmt.Errorf("validate geoip database %q: %w", path, err)
	}

	return &fileDatabase{records: records}, nil
}

// loadMaxMindDatabase eagerly loads a MaxMind database into process memory.
func loadMaxMindDatabase(ctx context.Context, path string) (*maxMindDatabase, error) {
	return loadMaxMindDatabaseWithFactory(ctx, path, inMemoryMaxMindReaderFactory{})
}

// loadMaxMindDatabaseWithFactory reads the complete database before constructing its reader.
func loadMaxMindDatabaseWithFactory(ctx context.Context, path string, factory maxMindReaderFactory) (*maxMindDatabase, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("database_path must be absolute: %s", path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MaxMind database %q: %w", path, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reader, err := factory.FromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("open MaxMind database %q from memory: %w", path, err)
	}

	return &maxMindDatabase{reader: reader, path: path}, nil
}

// FromBytes constructs a MaxMind reader over the retained in-memory database bytes.
func (inMemoryMaxMindReaderFactory) FromBytes(raw []byte) (*maxminddb.Reader, error) {
	return maxminddb.FromBytes(raw)
}

// parseDatabaseRecords converts JSON records into lookup records.
func parseDatabaseRecords(records []databaseRecord) ([]geoRecord, error) {
	if len(records) == 0 {
		return nil, errGeoDatabaseEmpty
	}

	parsed := make([]geoRecord, 0, len(records))
	for index, record := range records {
		prefix, err := netip.ParsePrefix(record.CIDR)
		if err != nil {
			return nil, fmt.Errorf("records[%d].cidr: %w", index, err)
		}

		parsed = append(parsed, geoRecord{
			CountryISO:  record.CountryISO,
			CountryName: record.CountryName,
			CityName:    record.CityName,
			ASNOrg:      record.ASNOrg,
			Prefix:      prefix.Masked(),
			ASN:         record.ASN,
		})
	}

	return parsed, nil
}

// Lookup returns the most specific record matching an address.
func (d *fileDatabase) Lookup(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	if d == nil {
		return geoRecord{}, false, nil
	}

	addr = addr.Unmap()
	bestIndex := -1
	bestBits := -1

	for index, record := range d.records {
		if index%64 == 0 {
			if err := ctx.Err(); err != nil {
				return geoRecord{}, false, err
			}
		}

		if !record.Prefix.Contains(addr) {
			continue
		}

		if bits := record.Prefix.Bits(); bits > bestBits {
			bestBits = bits
			bestIndex = index
		}
	}

	if bestIndex < 0 {
		return geoRecord{}, false, nil
	}

	return d.records[bestIndex], true, nil
}

// Records reports how many lookup records are loaded.
func (d *fileDatabase) Records() int {
	if d == nil {
		return 0
	}

	return len(d.records)
}

// Close releases resources held by the JSON fixture database.
func (d *fileDatabase) Close() error {
	return nil
}

// Lookup returns the MaxMind record matching an address.
func (d *maxMindDatabase) Lookup(ctx context.Context, addr netip.Addr) (geoRecord, bool, error) {
	if d == nil || d.reader == nil {
		return geoRecord{}, false, nil
	}

	if err := ctx.Err(); err != nil {
		return geoRecord{}, false, err
	}

	var decoded maxMindRecord

	network, ok, err := d.reader.LookupNetwork(netIPFromAddr(addr.Unmap()), &decoded)
	if err != nil {
		return geoRecord{}, false, fmt.Errorf("lookup MaxMind database %q: %w", d.path, err)
	}

	if !ok {
		return geoRecord{}, false, nil
	}

	prefix, err := netipPrefixFromIPNet(network)
	if err != nil {
		return geoRecord{}, false, fmt.Errorf("decode MaxMind network %q: %w", d.path, err)
	}

	return geoRecordFromMaxMind(decoded, prefix), true, nil
}

// Records reports the MaxMind search tree node count for operator visibility.
func (d *maxMindDatabase) Records() int {
	if d == nil || d.reader == nil {
		return 0
	}

	return int(d.reader.Metadata.NodeCount)
}

// Close releases the underlying MaxMind DB reader.
func (d *maxMindDatabase) Close() error {
	if d == nil || d.reader == nil {
		return nil
	}

	return d.reader.Close()
}

// geoRecordFromMaxMind maps MaxMind City, Country, or ASN records into plugin facts.
func geoRecordFromMaxMind(record maxMindRecord, prefix netip.Prefix) geoRecord {
	country := record.Country
	if country.ISOCode == "" {
		country = record.RegisteredCountry
	}

	asn := int(record.Traits.ASN)
	if asn == 0 {
		asn = int(record.ASN)
	}

	asnOrg := record.Traits.ASNOrg
	if asnOrg == "" {
		asnOrg = record.ASNOrg
	}

	return geoRecord{
		CountryISO:  country.ISOCode,
		CountryName: preferredName(country.Names),
		CityName:    preferredName(record.City.Names),
		ASNOrg:      asnOrg,
		Prefix:      prefix,
		ASN:         asn,
	}
}

// mergeASNDatabaseRecord fills ASN facts from a secondary ASN database.
func mergeASNDatabaseRecord(record *geoRecord, asnRecord geoRecord) {
	if record == nil || !asnRecordMatches(record.ASN, asnRecord.ASN) {
		return
	}

	if record.ASN <= 0 && asnRecord.ASN > 0 {
		record.ASN = asnRecord.ASN
	}

	if record.ASNOrg == "" {
		record.ASNOrg = asnRecord.ASNOrg
	}

	if record.ASNPrefix == "" && asnRecord.Prefix.IsValid() {
		record.ASNPrefix = asnRecord.Prefix.String()
	}
}

// asnRecordMatches prevents stale ASN metadata from being attached to a different ASN.
func asnRecordMatches(currentASN int, candidateASN int) bool {
	return currentASN <= 0 || candidateASN <= 0 || currentASN == candidateASN
}

// preferredName returns the English name or a deterministic fallback.
func preferredName(names map[string]string) string {
	if len(names) == 0 {
		return ""
	}

	if name := names["en"]; name != "" {
		return name
	}

	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return names[keys[0]]
}

// netIPFromAddr converts a netip address into the net.IP type used by the MaxMind reader.
func netIPFromAddr(addr netip.Addr) net.IP {
	if addr.Is4() {
		octets := addr.As4()

		return net.IPv4(octets[0], octets[1], octets[2], octets[3])
	}

	octets := addr.As16()

	return net.IP(append([]byte{}, octets[:]...))
}

// netipPrefixFromIPNet converts a MaxMind network into a netip prefix.
func netipPrefixFromIPNet(network *net.IPNet) (netip.Prefix, error) {
	if network == nil {
		return netip.Prefix{}, fmt.Errorf("network is nil")
	}

	ones, _ := network.Mask.Size()
	addr, ok := netip.AddrFromSlice(network.IP)

	if !ok {
		return netip.Prefix{}, fmt.Errorf("address %q is invalid", network.IP)
	}

	return netip.PrefixFrom(addr.Unmap(), ones).Masked(), nil
}
