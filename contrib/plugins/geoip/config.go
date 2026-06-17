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
	defaultASNLookupRefreshInterval   = 30 * 24 * time.Hour
	defaultASNLookupTimeout           = 30 * time.Second
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
	RefreshInterval time.Duration `mapstructure:"-"`
	Timeout         time.Duration `mapstructure:"-"`
	SourceURLs      []string      `mapstructure:"-"`
	Enabled         bool          `mapstructure:"-"`
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
	RefreshInterval string   `mapstructure:"refresh_interval"`
	Timeout         string   `mapstructure:"timeout"`
	SourceURLs      []string `mapstructure:"source_urls"`
	Enabled         bool     `mapstructure:"enabled"`
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

// parseASNLookupConfig applies local ASN routing snapshot defaults.
func parseASNLookupConfig(raw rawASNLookupConfig) (asnLookupConfig, error) {
	refreshInterval, err := parseDefaultedDuration("asn_lookup.refresh_interval", raw.RefreshInterval, defaultASNLookupRefreshInterval)
	if err != nil {
		return asnLookupConfig{}, err
	}

	timeout, err := parsePositiveDefaultedDuration("asn_lookup.timeout", raw.Timeout, defaultASNLookupTimeout)
	if err != nil {
		return asnLookupConfig{}, err
	}

	sourceURLs := append([]string{}, raw.SourceURLs...)
	if raw.Enabled && len(sourceURLs) == 0 {
		sourceURLs = defaultASNLookupSourceURLs()
	}

	for index, sourceURL := range sourceURLs {
		if err := validateHTTPSourceURL(sourceURL); err != nil {
			return asnLookupConfig{}, fmt.Errorf("asn_lookup.source_urls[%d]: %w", index, err)
		}
	}

	return asnLookupConfig{
		Enabled:         raw.Enabled,
		RefreshInterval: refreshInterval,
		Timeout:         timeout,
		SourceURLs:      sourceURLs,
	}, nil
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
		if err := validateHTTPSourceURL(sourceURL); err != nil {
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

// validateHTTPSourceURL checks that fetch sources use HTTP(S).
func validateHTTPSourceURL(value string) error {
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

// defaultASNLookupSourceURLs returns CAIDA RouteViews pfx2as creation logs.
func defaultASNLookupSourceURLs() []string {
	return []string{
		"https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log",
		"https://publicdata.caida.org/datasets/routing/routeviews6-prefix2as/pfx2as-creation.log",
	}
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
