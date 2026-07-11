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
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	defaultPrivacyLookupTimeout       = 10 * time.Millisecond
	defaultPrivacyRefreshInterval     = 6 * time.Hour
	defaultPrivacyMinRefreshInterval  = time.Hour
	defaultPrivacyMaxRefreshBackoff   = 24 * time.Hour
	defaultPrivacySourceMaxAge        = 24 * time.Hour
	defaultPrivacyMaxDownloadBytes    = int64(32 << 20)
	defaultPrivacyMaxSnapshotEntries  = 1_000_000
	defaultPrivacyDownloadConcurrency = 2
	defaultPrivacyStartupJitter       = 30 * time.Second
	maxPrivacyDownloadConcurrency     = 8
	minimumTorRefreshInterval         = 30 * time.Minute
	defaultTorRefreshInterval         = time.Hour
	maximumCommunityConfidence        = 80
	maximumDerivedConfidence          = 60
)

type privacySourceKind string
type privacyAuthority string

const (
	privacySourceKindNormalized privacySourceKind = "normalized_json"
	privacySourceKindTor        privacySourceKind = "tor_exit_list"

	privacyAuthorityOfficial  privacyAuthority = "official"
	privacyAuthorityOperator  privacyAuthority = "operator"
	privacyAuthorityCommunity privacyAuthority = "community"
	privacyAuthorityDerived   privacyAuthority = "derived"
)

type privacyConfig struct {
	Refresh       privacyRefreshConfig
	Sources       []privacySourceConfig
	Hosting       privacyHostingConfig
	Overrides     []privacyOverrideConfig
	LookupTimeout time.Duration
	Enabled       bool
	PublicLogs    bool
}

type privacyRefreshConfig struct {
	CacheDir                  string
	DefaultRefreshInterval    time.Duration
	DefaultMinRefreshInterval time.Duration
	DefaultMaxRefreshBackoff  time.Duration
	StartupJitter             time.Duration
	MaxConcurrentDownloads    int
}

type privacySourceConfig struct {
	ID                 string
	Description        string
	Path               string
	URL                string
	CachePath          string
	License            string
	LicenseURL         string
	Kind               privacySourceKind
	Authority          privacyAuthority
	RefreshInterval    time.Duration
	MinRefreshInterval time.Duration
	MaxRefreshBackoff  time.Duration
	RefreshJitter      time.Duration
	MaxAge             time.Duration
	MaxDownloadBytes   int64
	MaxEntries         int
	Confidence         int
	Required           bool
}

type privacyHostingConfig struct {
	CIDRs      []netip.Prefix
	Patterns   []string
	ASNs       []int
	Confidence int
	Enabled    bool
}

type privacyOverrideConfig struct {
	Network          netip.Prefix
	AddClasses       []privacyClass
	SuppressClasses  []privacyClass
	Reason           string
	ExpiresAt        time.Time
	SuppressOfficial bool
}

type rawPrivacyConfig struct {
	Refresh       rawPrivacyRefreshConfig    `mapstructure:"refresh"`
	Sources       []rawPrivacySourceConfig   `mapstructure:"sources"`
	Hosting       rawPrivacyHostingConfig    `mapstructure:"hosting"`
	Overrides     []rawPrivacyOverrideConfig `mapstructure:"overrides"`
	LookupTimeout string                     `mapstructure:"lookup_timeout"`
	Enabled       bool                       `mapstructure:"enabled"`
	PublicLogs    bool                       `mapstructure:"public_log_fields"`
	MaxEntries    int                        `mapstructure:"max_snapshot_entries"`
	MaxBytes      int64                      `mapstructure:"max_download_bytes"`
}

type rawPrivacyRefreshConfig struct {
	CacheDir                  string `mapstructure:"cache_dir"`
	DefaultRefreshInterval    string `mapstructure:"default_refresh_interval"`
	DefaultMinRefreshInterval string `mapstructure:"default_min_refresh_interval"`
	DefaultMaxRefreshBackoff  string `mapstructure:"default_max_refresh_backoff"`
	StartupJitter             string `mapstructure:"startup_jitter"`
	MaxConcurrentDownloads    int    `mapstructure:"max_concurrent_downloads"`
}

type rawPrivacySourceConfig struct {
	ID                 string `mapstructure:"id"`
	Kind               string `mapstructure:"kind"`
	Authority          string `mapstructure:"authority"`
	Description        string `mapstructure:"description"`
	Path               string `mapstructure:"path"`
	URL                string `mapstructure:"url"`
	CachePath          string `mapstructure:"cache_path"`
	License            string `mapstructure:"license"`
	LicenseURL         string `mapstructure:"license_url"`
	RefreshInterval    string `mapstructure:"refresh_interval"`
	MinRefreshInterval string `mapstructure:"min_refresh_interval"`
	MaxRefreshBackoff  string `mapstructure:"max_refresh_backoff"`
	RefreshJitter      string `mapstructure:"refresh_jitter"`
	MaxAge             string `mapstructure:"max_age"`
	Confidence         int    `mapstructure:"confidence"`
	Required           bool   `mapstructure:"required"`
}

type rawPrivacyHostingConfig struct {
	OrganizationPatterns []string `mapstructure:"organization_patterns"`
	CIDRs                []string `mapstructure:"cidrs"`
	ASNs                 []int    `mapstructure:"asns"`
	Confidence           int      `mapstructure:"confidence"`
	Enabled              bool     `mapstructure:"enabled"`
}

type rawPrivacyOverrideConfig struct {
	Network          string   `mapstructure:"network"`
	AddClasses       []string `mapstructure:"add_classes"`
	SuppressClasses  []string `mapstructure:"suppress_classes"`
	Reason           string   `mapstructure:"reason"`
	ExpiresAt        string   `mapstructure:"expires_at"`
	SuppressOfficial bool     `mapstructure:"suppress_official"`
}

// parsePrivacyConfig validates the optional privacy-intelligence subtree.
func parsePrivacyConfig(raw rawPrivacyConfig, parentLookupTimeout time.Duration) (privacyConfig, error) {
	lookupTimeout, err := parsePositiveDefaultedDuration("privacy_intelligence.lookup_timeout", raw.LookupTimeout, defaultPrivacyLookupTimeout)
	if err != nil {
		return privacyConfig{}, err
	}

	if lookupTimeout > parentLookupTimeout {
		return privacyConfig{}, fmt.Errorf("privacy_intelligence.lookup_timeout must not exceed lookup_timeout")
	}

	refresh, err := parsePrivacyRefreshConfig(raw.Refresh)
	if err != nil {
		return privacyConfig{}, err
	}

	maxEntries, maxBytes, err := parsePrivacySizeLimits(raw)
	if err != nil {
		return privacyConfig{}, err
	}

	sources, err := parsePrivacySources(raw.Sources, refresh, maxEntries, maxBytes)
	if err != nil {
		return privacyConfig{}, err
	}

	hosting, err := parsePrivacyHostingConfig(raw.Hosting)
	if err != nil {
		return privacyConfig{}, err
	}

	overrides, err := parsePrivacyOverrides(raw.Overrides)
	if err != nil {
		return privacyConfig{}, err
	}

	if raw.Enabled && len(sources) == 0 && !hosting.Enabled {
		return privacyConfig{}, fmt.Errorf("privacy_intelligence requires at least one source or hosting rules")
	}

	return privacyConfig{Refresh: refresh, Sources: sources, Hosting: hosting, Overrides: overrides, LookupTimeout: lookupTimeout, Enabled: raw.Enabled, PublicLogs: raw.PublicLogs}, nil
}

// parsePrivacySizeLimits applies bounded snapshot and response defaults.
func parsePrivacySizeLimits(raw rawPrivacyConfig) (int, int64, error) {
	maxEntries := raw.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultPrivacyMaxSnapshotEntries
	}

	maxBytes := raw.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultPrivacyMaxDownloadBytes
	}

	if maxEntries < 1 || maxBytes < 1 {
		return 0, 0, fmt.Errorf("privacy intelligence size limits must be positive")
	}

	return maxEntries, maxBytes, nil
}

// parsePrivacySources validates source uniqueness and preserves configured order.
func parsePrivacySources(raw []rawPrivacySourceConfig, refresh privacyRefreshConfig, maxEntries int, maxBytes int64) ([]privacySourceConfig, error) {
	sources := make([]privacySourceConfig, 0, len(raw))
	ids := make(map[string]struct{}, len(raw))

	for index, sourceRaw := range raw {
		source, err := parsePrivacySourceConfig(sourceRaw, refresh, maxEntries, maxBytes)
		if err != nil {
			return nil, fmt.Errorf("privacy_intelligence.sources[%d]: %w", index, err)
		}

		if _, found := ids[source.ID]; found {
			return nil, fmt.Errorf("privacy source ID %q is duplicated", source.ID)
		}

		ids[source.ID] = struct{}{}
		sources = append(sources, source)
	}

	return sources, nil
}

// parsePrivacyRefreshConfig applies shared scheduling and cache defaults.
func parsePrivacyRefreshConfig(raw rawPrivacyRefreshConfig) (privacyRefreshConfig, error) {
	interval, err := parsePositiveDefaultedDuration("privacy_intelligence.refresh.default_refresh_interval", raw.DefaultRefreshInterval, defaultPrivacyRefreshInterval)
	if err != nil {
		return privacyRefreshConfig{}, err
	}

	minimum, err := parsePositiveDefaultedDuration("privacy_intelligence.refresh.default_min_refresh_interval", raw.DefaultMinRefreshInterval, defaultPrivacyMinRefreshInterval)
	if err != nil {
		return privacyRefreshConfig{}, err
	}

	backoff, err := parsePositiveDefaultedDuration("privacy_intelligence.refresh.default_max_refresh_backoff", raw.DefaultMaxRefreshBackoff, defaultPrivacyMaxRefreshBackoff)
	if err != nil {
		return privacyRefreshConfig{}, err
	}

	jitter, err := parseOptionalDuration("privacy_intelligence.refresh.startup_jitter", raw.StartupJitter)
	if err != nil {
		return privacyRefreshConfig{}, err
	}

	if raw.StartupJitter == "" {
		jitter = defaultPrivacyStartupJitter
	}

	concurrency := raw.MaxConcurrentDownloads
	if concurrency == 0 {
		concurrency = defaultPrivacyDownloadConcurrency
	}

	if concurrency < 1 || concurrency > maxPrivacyDownloadConcurrency {
		return privacyRefreshConfig{}, fmt.Errorf("privacy_intelligence.refresh.max_concurrent_downloads must be between 1 and %d", maxPrivacyDownloadConcurrency)
	}

	cacheDir, err := parseOptionalDatabasePath("privacy_intelligence.refresh.cache_dir", raw.CacheDir)
	if err != nil {
		return privacyRefreshConfig{}, err
	}

	return privacyRefreshConfig{CacheDir: cacheDir, DefaultRefreshInterval: interval, DefaultMinRefreshInterval: minimum, DefaultMaxRefreshBackoff: backoff, StartupJitter: jitter, MaxConcurrentDownloads: concurrency}, nil
}

// parsePrivacySourceConfig validates one local or remote privacy source.
func parsePrivacySourceConfig(raw rawPrivacySourceConfig, refresh privacyRefreshConfig, maxEntries int, maxBytes int64) (privacySourceConfig, error) {
	source, err := parsePrivacySourceIdentity(raw)
	if err != nil {
		return privacySourceConfig{}, err
	}

	if err := applyPrivacySourceSchedule(&source, raw, refresh); err != nil {
		return privacySourceConfig{}, err
	}

	cachePath, err := privacySourceCachePath(raw, refresh, source)
	if err != nil {
		return privacySourceConfig{}, err
	}

	source.CachePath = cachePath
	source.MaxDownloadBytes = maxBytes
	source.MaxEntries = maxEntries

	return source, nil
}

// parsePrivacySourceIdentity validates one source's format, authority, location, and confidence.
func parsePrivacySourceIdentity(raw rawPrivacySourceConfig) (privacySourceConfig, error) {
	if err := validatePrivacyID(raw.ID); err != nil {
		return privacySourceConfig{}, err
	}

	kind, authority, err := parsePrivacySourceContract(raw)
	if err != nil {
		return privacySourceConfig{}, err
	}

	path, sourceURL, err := parsePrivacySourceLocation(raw)
	if err != nil {
		return privacySourceConfig{}, err
	}

	if authority == privacyAuthorityCommunity && (raw.License == "" || raw.LicenseURL == "") {
		return privacySourceConfig{}, fmt.Errorf("community sources require license and license_url")
	}

	confidence, err := parsePrivacySourceConfidence(raw.Confidence, authority)
	if err != nil {
		return privacySourceConfig{}, err
	}

	return privacySourceConfig{ID: raw.ID, Description: raw.Description, Path: path, URL: sourceURL, License: raw.License, LicenseURL: raw.LicenseURL, Kind: kind, Authority: authority, Confidence: confidence, Required: raw.Required}, nil
}

// parsePrivacySourceContract validates kind and evidence authority compatibility.
func parsePrivacySourceContract(raw rawPrivacySourceConfig) (privacySourceKind, privacyAuthority, error) {
	kind := privacySourceKind(raw.Kind)
	if kind != privacySourceKindTor && kind != privacySourceKindNormalized {
		return "", "", fmt.Errorf("kind %q is unsupported", raw.Kind)
	}

	authority := privacyAuthority(raw.Authority)
	if !slices.Contains([]privacyAuthority{privacyAuthorityOfficial, privacyAuthorityOperator, privacyAuthorityCommunity, privacyAuthorityDerived}, authority) {
		return "", "", fmt.Errorf("authority %q is unsupported", raw.Authority)
	}

	if kind == privacySourceKindTor && authority != privacyAuthorityOfficial {
		return "", "", fmt.Errorf("tor exit sources require official authority")
	}

	return kind, authority, nil
}

// parsePrivacySourceLocation validates one absolute file or credential-free HTTPS URL.
func parsePrivacySourceLocation(raw rawPrivacySourceConfig) (string, string, error) {
	path := strings.TrimSpace(raw.Path)
	sourceURL := strings.TrimSpace(raw.URL)

	if (path == "") == (sourceURL == "") {
		return "", "", fmt.Errorf("exactly one of path or url is required")
	}

	if path != "" && !filepath.IsAbs(path) {
		return "", "", fmt.Errorf("path must be absolute")
	}

	if sourceURL != "" {
		parsed, err := url.Parse(sourceURL)
		if err != nil || parsed.Scheme != sourceSchemeHTTPS || parsed.Host == "" || parsed.User != nil {
			return "", "", fmt.Errorf("url must be credential-free HTTPS")
		}
	}

	return path, sourceURL, nil
}

// parsePrivacySourceConfidence applies authority-specific defaults and caps.
func parsePrivacySourceConfidence(configured int, authority privacyAuthority) (int, error) {
	confidenceCap := 100

	switch authority {
	case privacyAuthorityCommunity:
		confidenceCap = maximumCommunityConfidence
	case privacyAuthorityDerived:
		confidenceCap = maximumDerivedConfidence
	}

	confidence := configured
	if confidence == 0 && (authority == privacyAuthorityOfficial || authority == privacyAuthorityOperator) {
		confidence = 100
	}

	if confidence < 0 || confidence > confidenceCap {
		return 0, fmt.Errorf("confidence must be between 0 and %d for %s authority", confidenceCap, authority)
	}

	return confidence, nil
}

// applyPrivacySourceSchedule validates refresh, backoff, jitter, and freshness bounds.
func applyPrivacySourceSchedule(source *privacySourceConfig, raw rawPrivacySourceConfig, refresh privacyRefreshConfig) error {
	intervalFallback := refresh.DefaultRefreshInterval
	minimumFallback := refresh.DefaultMinRefreshInterval

	if source.Kind == privacySourceKindTor {
		intervalFallback = defaultTorRefreshInterval
		minimumFallback = minimumTorRefreshInterval
	}

	interval, err := parsePositiveDefaultedDuration("refresh_interval", raw.RefreshInterval, intervalFallback)
	if err != nil {
		return err
	}

	minimum, err := parsePositiveDefaultedDuration("min_refresh_interval", raw.MinRefreshInterval, minimumFallback)
	if err != nil {
		return err
	}

	if minimum < minimumFallback || interval < minimum {
		return fmt.Errorf("refresh interval must respect the %s minimum", minimumFallback)
	}

	backoff, err := parsePositiveDefaultedDuration("max_refresh_backoff", raw.MaxRefreshBackoff, refresh.DefaultMaxRefreshBackoff)
	if err != nil || backoff < interval {
		return fmt.Errorf("max_refresh_backoff must be at least refresh_interval")
	}

	jitter, err := parseOptionalDuration("refresh_jitter", raw.RefreshJitter)
	if err != nil {
		return err
	}

	if raw.RefreshJitter == "" {
		jitter = min(interval/10, 10*time.Minute)
	}

	if jitter >= interval {
		return fmt.Errorf("refresh_jitter must be smaller than refresh_interval")
	}

	maxAge, err := parsePositiveDefaultedDuration("max_age", raw.MaxAge, defaultPrivacySourceMaxAge)
	if err != nil {
		return err
	}

	source.RefreshInterval = interval
	source.MinRefreshInterval = minimum
	source.MaxRefreshBackoff = backoff
	source.RefreshJitter = jitter
	source.MaxAge = maxAge

	return nil
}

// privacySourceCachePath resolves a validated remote cache location.
func privacySourceCachePath(raw rawPrivacySourceConfig, refresh privacyRefreshConfig, source privacySourceConfig) (string, error) {
	cachePath := strings.TrimSpace(raw.CachePath)
	if cachePath != "" && (source.Path != "" || !filepath.IsAbs(cachePath)) {
		return "", fmt.Errorf("cache_path requires a remote source and must be absolute")
	}

	if cachePath == "" && source.URL != "" && refresh.CacheDir != "" {
		cachePath = filepath.Join(refresh.CacheDir, raw.ID+"-"+raw.Kind+".json")
	}

	return cachePath, nil
}

// parsePrivacyHostingConfig validates derived hosting rules independently from VPN evidence.
func parsePrivacyHostingConfig(raw rawPrivacyHostingConfig) (privacyHostingConfig, error) {
	if raw.Confidence < 0 || raw.Confidence > maximumDerivedConfidence {
		return privacyHostingConfig{}, fmt.Errorf("privacy_intelligence.hosting.confidence must be between 0 and %d", maximumDerivedConfidence)
	}

	prefixes := make([]netip.Prefix, 0, len(raw.CIDRs))
	for index, value := range raw.CIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return privacyHostingConfig{}, fmt.Errorf("privacy_intelligence.hosting.cidrs[%d]: %w", index, err)
		}

		prefixes = append(prefixes, prefix.Masked())
	}

	asns := make([]int, 0, len(raw.ASNs))
	for index, asn := range raw.ASNs {
		if asn <= 0 {
			return privacyHostingConfig{}, fmt.Errorf("privacy_intelligence.hosting.asns[%d] must be positive", index)
		}

		if !slices.Contains(asns, asn) {
			asns = append(asns, asn)
		}
	}

	patterns := make([]string, 0, len(raw.OrganizationPatterns))
	for index, value := range raw.OrganizationPatterns {
		pattern := strings.ToLower(strings.TrimSpace(value))
		if pattern == "" || len(pattern) > 128 {
			return privacyHostingConfig{}, fmt.Errorf("privacy_intelligence.hosting.organization_patterns[%d] must contain 1 to 128 characters", index)
		}

		if !slices.Contains(patterns, pattern) {
			patterns = append(patterns, pattern)
		}
	}

	return privacyHostingConfig{CIDRs: prefixes, Patterns: patterns, ASNs: asns, Confidence: raw.Confidence, Enabled: raw.Enabled}, nil
}

// matches reports whether a GeoIP record satisfies configured derived hosting rules.
func (c privacyHostingConfig) matches(record geoRecord) bool {
	if slices.Contains(c.ASNs, record.ASN) {
		return true
	}

	organization := strings.ToLower(record.ASNOrg)

	return slices.ContainsFunc(c.Patterns, func(pattern string) bool {
		return strings.Contains(organization, pattern)
	})
}

// parsePrivacyOverrides validates explicit operator additions and suppressions.
func parsePrivacyOverrides(raw []rawPrivacyOverrideConfig) ([]privacyOverrideConfig, error) {
	overrides := make([]privacyOverrideConfig, 0, len(raw))
	for index, item := range raw {
		prefix, err := netip.ParsePrefix(item.Network)
		if err != nil {
			return nil, fmt.Errorf("privacy_intelligence.overrides[%d].network: %w", index, err)
		}

		var added []privacyClass
		if len(item.AddClasses) > 0 {
			added, err = parsePrivacyClasses(item.AddClasses)
			if err != nil {
				return nil, fmt.Errorf("privacy_intelligence.overrides[%d].add_classes: %w", index, err)
			}
		}

		var suppressed []privacyClass
		if len(item.SuppressClasses) > 0 {
			suppressed, err = parsePrivacyClasses(item.SuppressClasses)
			if err != nil {
				return nil, fmt.Errorf("privacy_intelligence.overrides[%d].suppress_classes: %w", index, err)
			}
		}

		if len(added) == 0 && len(suppressed) == 0 {
			return nil, fmt.Errorf("privacy_intelligence.overrides[%d] requires add_classes or suppress_classes", index)
		}

		var expires time.Time
		if item.ExpiresAt != "" {
			expires, err = time.Parse(time.RFC3339, item.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("privacy_intelligence.overrides[%d].expires_at: %w", index, err)
			}
		}

		overrides = append(overrides, privacyOverrideConfig{Network: prefix.Masked(), AddClasses: added, SuppressClasses: suppressed, Reason: item.Reason, ExpiresAt: expires, SuppressOfficial: item.SuppressOfficial})
	}

	return overrides, nil
}

// validatePrivacyID enforces stable bounded source identifiers.
func validatePrivacyID(value string) error {
	if value == "" || len(value) > 63 {
		return fmt.Errorf("source id must contain 1 to 63 characters")
	}

	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || (char == '_' && index > 0) {
			continue
		}

		return fmt.Errorf("source id %q is invalid", value)
	}

	return nil
}
