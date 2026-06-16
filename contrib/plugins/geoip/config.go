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
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
)

const (
	asnLookupProviderRspamd           = "rspamd"
	defaultASNRspamdIPv4Zone          = "asn.rspamd.com"
	defaultASNRspamdIPv6Zone          = "asn6.rspamd.com"
	defaultASNLookupCacheTTL          = 12 * time.Hour
	defaultASNLookupNegativeCacheTTL  = 5 * time.Minute
	defaultASNLookupTimeout           = time.Second
	defaultASNRegistryRefreshInterval = 30 * 24 * time.Hour
	defaultASNRegistryTimeout         = 30 * time.Second
	defaultDatabaseFormat             = "auto"
	defaultLookupTimeout              = 50 * time.Millisecond
	databaseFormatAuto                = "auto"
	databaseFormatJSON                = "json"
	databaseFormatMMDB                = "mmdb"
)

type moduleConfig struct {
	ASNRegistry     asnRegistryConfig `mapstructure:"-"`
	ASNLookup       asnLookupConfig   `mapstructure:"-"`
	DatabasePath    string            `mapstructure:"-"`
	DatabaseFormat  string            `mapstructure:"-"`
	RefreshInterval time.Duration     `mapstructure:"-"`
	LookupTimeout   time.Duration     `mapstructure:"-"`
}

type asnLookupConfig struct {
	ProviderType     string        `mapstructure:"-"`
	IPv4Zone         string        `mapstructure:"-"`
	IPv6Zone         string        `mapstructure:"-"`
	Timeout          time.Duration `mapstructure:"-"`
	CacheTTL         time.Duration `mapstructure:"-"`
	NegativeCacheTTL time.Duration `mapstructure:"-"`
	Enabled          bool          `mapstructure:"-"`
}

type asnRegistryConfig struct {
	RefreshInterval time.Duration `mapstructure:"-"`
	Timeout         time.Duration `mapstructure:"-"`
	SourceURLs      []string      `mapstructure:"-"`
	Enabled         bool          `mapstructure:"-"`
}

type rawModuleConfig struct {
	ASNRegistry     rawASNRegistryConfig `mapstructure:"asn_registry"`
	ASNLookup       rawASNLookupConfig   `mapstructure:"asn_lookup"`
	DatabasePath    string               `mapstructure:"database_path"`
	DatabaseFormat  string               `mapstructure:"database_format"`
	RefreshInterval string               `mapstructure:"refresh_interval"`
	LookupTimeout   string               `mapstructure:"lookup_timeout"`
}

type rawASNLookupConfig struct {
	ProviderType     string `mapstructure:"provider_type"`
	IPv4Zone         string `mapstructure:"ipv4_zone"`
	IPv6Zone         string `mapstructure:"ipv6_zone"`
	Timeout          string `mapstructure:"timeout"`
	CacheTTL         string `mapstructure:"cache_ttl"`
	NegativeCacheTTL string `mapstructure:"negative_cache_ttl"`
	Enabled          bool   `mapstructure:"enabled"`
}

type rawASNRegistryConfig struct {
	RefreshInterval string   `mapstructure:"refresh_interval"`
	Timeout         string   `mapstructure:"timeout"`
	SourceURLs      []string `mapstructure:"source_urls"`
	Enabled         bool     `mapstructure:"enabled"`
}

// decodeModuleConfig reads and validates the plugin-owned configuration subtree.
func decodeModuleConfig(view pluginapi.ConfigView) (moduleConfig, error) {
	var raw rawModuleConfig
	if view != nil && !view.IsZero() {
		if err := view.Decode(&raw); err != nil {
			return moduleConfig{}, fmt.Errorf("decode geoip config: %w", err)
		}
	}

	databasePath := filepath.Clean(strings.TrimSpace(raw.DatabasePath))
	if databasePath == "." || databasePath == "" {
		return moduleConfig{}, fmt.Errorf("database_path must not be empty")
	}

	if !filepath.IsAbs(databasePath) {
		return moduleConfig{}, fmt.Errorf("database_path must be absolute: %s", databasePath)
	}

	refreshInterval, err := parseOptionalDuration("refresh_interval", raw.RefreshInterval)
	if err != nil {
		return moduleConfig{}, err
	}

	lookupTimeout, err := parseLookupTimeout(raw.LookupTimeout)
	if err != nil {
		return moduleConfig{}, err
	}

	databaseFormat, err := parseDatabaseFormat(raw.DatabaseFormat, databasePath)
	if err != nil {
		return moduleConfig{}, err
	}

	asnRegistry, err := parseASNRegistryConfig(raw.ASNRegistry)
	if err != nil {
		return moduleConfig{}, err
	}

	asnLookup, err := parseASNLookupConfig(raw.ASNLookup)
	if err != nil {
		return moduleConfig{}, err
	}

	return moduleConfig{
		ASNRegistry:     asnRegistry,
		ASNLookup:       asnLookup,
		DatabasePath:    databasePath,
		DatabaseFormat:  databaseFormat,
		RefreshInterval: refreshInterval,
		LookupTimeout:   lookupTimeout,
	}, nil
}

// parseDatabaseFormat validates the configured database format or infers it from the file extension.
func parseDatabaseFormat(value string, databasePath string) (string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		text = defaultDatabaseFormat
	}

	switch text {
	case databaseFormatAuto:
		if strings.EqualFold(filepath.Ext(databasePath), ".mmdb") {
			return databaseFormatMMDB, nil
		}

		return databaseFormatJSON, nil
	case databaseFormatJSON, databaseFormatMMDB:
		return text, nil
	default:
		return "", fmt.Errorf("database_format must be one of auto, json, or mmdb")
	}
}

// parseASNLookupConfig applies Rspamd-compatible ASN DNS lookup defaults.
func parseASNLookupConfig(raw rawASNLookupConfig) (asnLookupConfig, error) {
	timeout, err := parsePositiveDefaultedDuration("asn_lookup.timeout", raw.Timeout, defaultASNLookupTimeout)
	if err != nil {
		return asnLookupConfig{}, err
	}

	cacheTTL, err := parsePositiveDefaultedDuration("asn_lookup.cache_ttl", raw.CacheTTL, defaultASNLookupCacheTTL)
	if err != nil {
		return asnLookupConfig{}, err
	}

	negativeCacheTTL, err := parsePositiveDefaultedDuration("asn_lookup.negative_cache_ttl", raw.NegativeCacheTTL, defaultASNLookupNegativeCacheTTL)
	if err != nil {
		return asnLookupConfig{}, err
	}

	providerType := strings.TrimSpace(raw.ProviderType)
	if providerType == "" {
		providerType = asnLookupProviderRspamd
	}

	if providerType != asnLookupProviderRspamd {
		return asnLookupConfig{}, fmt.Errorf("asn_lookup.provider_type must be rspamd")
	}

	ipv4Zone, err := parseDNSZone("asn_lookup.ipv4_zone", raw.IPv4Zone, defaultASNRspamdIPv4Zone)
	if err != nil {
		return asnLookupConfig{}, err
	}

	ipv6Zone, err := parseDNSZone("asn_lookup.ipv6_zone", raw.IPv6Zone, defaultASNRspamdIPv6Zone)
	if err != nil {
		return asnLookupConfig{}, err
	}

	return asnLookupConfig{
		ProviderType:     providerType,
		IPv4Zone:         ipv4Zone,
		IPv6Zone:         ipv6Zone,
		Timeout:          timeout,
		CacheTTL:         cacheTTL,
		NegativeCacheTTL: negativeCacheTTL,
		Enabled:          raw.Enabled,
	}, nil
}

// parseDNSZone validates a DNS zone used by the Rspamd-compatible ASN provider.
func parseDNSZone(name string, value string, fallback string) (string, error) {
	zone := strings.Trim(strings.TrimSpace(value), ".")
	if zone == "" {
		zone = fallback
	}

	if !isDNSZoneName(zone) {
		return "", fmt.Errorf("%s must be a DNS zone name", name)
	}

	return zone, nil
}

// isDNSZoneName checks the restricted hostname form used for lookup zones.
func isDNSZoneName(value string) bool {
	if value == "" || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}

	for _, label := range strings.Split(value, ".") {
		if !isDNSLabelName(label) {
			return false
		}
	}

	return true
}

// isDNSLabelName validates one hostname label.
func isDNSLabelName(label string) bool {
	if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}

	for _, char := range label {
		if !isDNSLabelChar(char) {
			return false
		}
	}

	return true
}

// isDNSLabelChar reports whether a rune is valid inside a DNS label.
func isDNSLabelChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '-'
}

// parseASNRegistryConfig applies registry defaults and validates registry source URLs.
func parseASNRegistryConfig(raw rawASNRegistryConfig) (asnRegistryConfig, error) {
	refreshInterval, err := parseDefaultedDuration("asn_registry.refresh_interval", raw.RefreshInterval, defaultASNRegistryRefreshInterval)
	if err != nil {
		return asnRegistryConfig{}, err
	}

	timeout, err := parsePositiveDefaultedDuration("asn_registry.timeout", raw.Timeout, defaultASNRegistryTimeout)
	if err != nil {
		return asnRegistryConfig{}, err
	}

	sourceURLs := append([]string{}, raw.SourceURLs...)
	if raw.Enabled && len(sourceURLs) == 0 {
		sourceURLs = defaultASNRegistrySourceURLs()
	}

	for index, sourceURL := range sourceURLs {
		if err := validateRegistrySourceURL(sourceURL); err != nil {
			return asnRegistryConfig{}, fmt.Errorf("asn_registry.source_urls[%d]: %w", index, err)
		}
	}

	return asnRegistryConfig{
		Enabled:         raw.Enabled,
		RefreshInterval: refreshInterval,
		Timeout:         timeout,
		SourceURLs:      sourceURLs,
	}, nil
}

// parseDefaultedDuration parses a non-negative duration with a default.
func parseDefaultedDuration(name string, value string, fallback time.Duration) (time.Duration, error) {
	duration, err := parseOptionalDuration(name, value)
	if err != nil {
		return 0, err
	}

	if duration == 0 {
		return fallback, nil
	}

	return duration, nil
}

// parsePositiveDefaultedDuration parses a positive duration with a default.
func parsePositiveDefaultedDuration(name string, value string, fallback time.Duration) (time.Duration, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return fallback, nil
	}

	duration, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", name, err)
	}

	if duration <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return duration, nil
}

// validateRegistrySourceURL checks that registry fetch sources use HTTP(S).
func validateRegistrySourceURL(value string) error {
	text := strings.TrimSpace(value)
	if text == "" {
		return fmt.Errorf("must not be empty")
	}

	parsed, err := url.Parse(text)
	if err != nil {
		return fmt.Errorf("must be a valid URL: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("must use http or https")
	}

	if parsed.Host == "" {
		return fmt.Errorf("must include a host")
	}

	return nil
}

// defaultASNRegistrySourceURLs returns worldwide RIR delegated stats feeds.
func defaultASNRegistrySourceURLs() []string {
	return []string{
		"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
		"https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
		"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
		"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
		"https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest",
	}
}

// parseOptionalDuration parses a zero-or-positive optional duration.
func parseOptionalDuration(name string, value string) (time.Duration, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return 0, nil
	}

	duration, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", name, err)
	}

	if duration < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}

	return duration, nil
}

// parseLookupTimeout parses the request-time lookup timeout.
func parseLookupTimeout(value string) (time.Duration, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return defaultLookupTimeout, nil
	}

	duration, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("lookup_timeout must be a duration: %w", err)
	}

	if duration <= 0 {
		return 0, fmt.Errorf("lookup_timeout must be positive")
	}

	return duration, nil
}
