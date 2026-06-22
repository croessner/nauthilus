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

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
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
	ASNRegistry       asnRegistryConfig `mapstructure:"-"`
	ASNLookup         asnLookupConfig   `mapstructure:"-"`
	ASNDatabasePath   string            `mapstructure:"-"`
	DatabasePath      string            `mapstructure:"-"`
	ASNDatabaseFormat string            `mapstructure:"-"`
	DatabaseFormat    string            `mapstructure:"-"`
	RefreshInterval   time.Duration     `mapstructure:"-"`
	LookupTimeout     time.Duration     `mapstructure:"-"`
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
	ASNRegistry       rawASNRegistryConfig `mapstructure:"asn_registry"`
	ASNLookup         rawASNLookupConfig   `mapstructure:"asn_lookup"`
	ASNDatabasePath   string               `mapstructure:"asn_database_path"`
	DatabasePath      string               `mapstructure:"database_path"`
	ASNDatabaseFormat string               `mapstructure:"asn_database_format"`
	DatabaseFormat    string               `mapstructure:"database_format"`
	RefreshInterval   string               `mapstructure:"refresh_interval"`
	LookupTimeout     string               `mapstructure:"lookup_timeout"`
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

	databasePath, err := parseRequiredDatabasePath("database_path", raw.DatabasePath)
	if err != nil {
		return moduleConfig{}, err
	}

	asnDatabasePath, err := parseOptionalDatabasePath("asn_database_path", raw.ASNDatabasePath)
	if err != nil {
		return moduleConfig{}, err
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

	asnDatabaseFormat, err := parseASNDatabaseFormat(raw.ASNDatabaseFormat, asnDatabasePath)
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
		ASNRegistry:       asnRegistry,
		ASNLookup:         asnLookup,
		ASNDatabasePath:   asnDatabasePath,
		DatabasePath:      databasePath,
		ASNDatabaseFormat: asnDatabaseFormat,
		DatabaseFormat:    databaseFormat,
		RefreshInterval:   refreshInterval,
		LookupTimeout:     lookupTimeout,
	}, nil
}

// parseRequiredDatabasePath validates a mandatory absolute database path.
func parseRequiredDatabasePath(name string, value string) (string, error) {
	databasePath, err := parseOptionalDatabasePath(name, value)
	if err != nil {
		return "", err
	}

	if databasePath == "" {
		return "", fmt.Errorf("%s must not be empty", name)
	}

	return databasePath, nil
}

// parseOptionalDatabasePath validates an optional absolute database path.
func parseOptionalDatabasePath(name string, value string) (string, error) {
	databasePath := filepath.Clean(strings.TrimSpace(value))
	if databasePath == "." || databasePath == "" {
		return "", nil
	}

	if !filepath.IsAbs(databasePath) {
		return "", fmt.Errorf("%s must be absolute: %s", name, databasePath)
	}

	return databasePath, nil
}

// parseDatabaseFormat validates the configured database format or infers it from the file extension.
func parseDatabaseFormat(value string, databasePath string) (string, error) {
	return parseNamedDatabaseFormat("database_format", value, databasePath)
}

// parseASNDatabaseFormat validates the optional ASN database format.
func parseASNDatabaseFormat(value string, databasePath string) (string, error) {
	if databasePath == "" {
		if strings.TrimSpace(value) != "" {
			return "", fmt.Errorf("asn_database_path must be set when asn_database_format is set")
		}

		return "", nil
	}

	return parseNamedDatabaseFormat("asn_database_format", value, databasePath)
}

// parseNamedDatabaseFormat validates a configured database format or infers it from the file extension.
func parseNamedDatabaseFormat(name string, value string, databasePath string) (string, error) {
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
		return "", fmt.Errorf("%s must be one of auto, json, or mmdb", name)
	}
}

// parseASNLookupConfig applies local ASN routing snapshot defaults.
func parseASNLookupConfig(raw rawASNLookupConfig) (asnLookupConfig, error) {
	sourceConfig, err := parseASNSourceConfig(
		"asn_lookup",
		raw.Enabled,
		raw.RefreshInterval,
		defaultASNLookupRefreshInterval,
		raw.Timeout,
		defaultASNLookupTimeout,
		raw.SourceURLs,
		defaultASNLookupSourceURLs,
	)
	if err != nil {
		return asnLookupConfig{}, err
	}

	return asnLookupConfig{
		Enabled:         sourceConfig.enabled,
		RefreshInterval: sourceConfig.refreshInterval,
		Timeout:         sourceConfig.timeout,
		SourceURLs:      sourceConfig.sourceURLs,
	}, nil
}

// parseASNRegistryConfig applies registry defaults and validates registry source URLs.
func parseASNRegistryConfig(raw rawASNRegistryConfig) (asnRegistryConfig, error) {
	sourceConfig, err := parseASNSourceConfig(
		"asn_registry",
		raw.Enabled,
		raw.RefreshInterval,
		defaultASNRegistryRefreshInterval,
		raw.Timeout,
		defaultASNRegistryTimeout,
		raw.SourceURLs,
		defaultASNRegistrySourceURLs,
	)
	if err != nil {
		return asnRegistryConfig{}, err
	}

	return asnRegistryConfig{
		Enabled:         sourceConfig.enabled,
		RefreshInterval: sourceConfig.refreshInterval,
		Timeout:         sourceConfig.timeout,
		SourceURLs:      sourceConfig.sourceURLs,
	}, nil
}

type asnSourceConfig struct {
	sourceURLs      []string
	refreshInterval time.Duration
	timeout         time.Duration
	enabled         bool
}

// parseASNSourceConfig applies shared ASN source defaults and URL validation.
func parseASNSourceConfig(
	prefix string,
	enabled bool,
	refreshIntervalValue string,
	defaultRefreshInterval time.Duration,
	timeoutValue string,
	defaultTimeout time.Duration,
	rawSourceURLs []string,
	defaultSourceURLs func() []string,
) (asnSourceConfig, error) {
	refreshInterval, err := parseDefaultedDuration(prefix+".refresh_interval", refreshIntervalValue, defaultRefreshInterval)
	if err != nil {
		return asnSourceConfig{}, err
	}

	timeout, err := parsePositiveDefaultedDuration(prefix+".timeout", timeoutValue, defaultTimeout)
	if err != nil {
		return asnSourceConfig{}, err
	}

	sourceURLs := append([]string{}, rawSourceURLs...)
	if enabled && len(sourceURLs) == 0 {
		sourceURLs = defaultSourceURLs()
	}

	for index, sourceURL := range sourceURLs {
		if err := validateHTTPSourceURL(sourceURL); err != nil {
			return asnSourceConfig{}, fmt.Errorf("%s.source_urls[%d]: %w", prefix, index, err)
		}
	}

	return asnSourceConfig{
		enabled:         enabled,
		refreshInterval: refreshInterval,
		timeout:         timeout,
		sourceURLs:      sourceURLs,
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
