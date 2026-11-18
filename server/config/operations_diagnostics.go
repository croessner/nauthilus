// Copyright (C) 2026 Christian Rößner
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

package config

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
)

const (
	// DiagnosticsQueryProfileNauthilus is the only compiled query profile of the historical sources.
	DiagnosticsQueryProfileNauthilus = "nauthilus_diagnostics"

	defaultHistoricalTimeout          = 3 * time.Second
	maxHistoricalTimeout              = 30 * time.Second
	defaultHistoricalMaxTimeWindow    = time.Hour
	maxHistoricalMaxTimeWindow        = 24 * time.Hour
	defaultHistoricalMaxSeries        = 200
	maxHistoricalMaxSeries            = 1000
	defaultHistoricalMaxResponseBytes = int64(1 << 20)
	maxHistoricalMaxResponseBytes     = int64(8 << 20)

	operationsDiagnosticsPath = "observability.diagnostics.operations"
)

var (
	// historicalLabelNamePattern restricts selector and instance label names to Prometheus label syntax.
	historicalLabelNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

	// historicalLabelValuePattern restricts selector values to characters that need no LogQL or PromQL escaping.
	historicalLabelValuePattern = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,128}$`)

	// historicalTenantPattern restricts the tenant header value (X-Scope-OrgID).
	historicalTenantPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// DiagnosticsSection groups support diagnostics below observability.
type DiagnosticsSection struct {
	Operations OperationsDiagnosticsSection `mapstructure:"operations" validate:"omitempty"`
}

// OperationsDiagnosticsSection configures the read-only operational diagnostics service. Sources are built at
// startup; changing them requires a restart.
type OperationsDiagnosticsSection struct {
	Sources OperationsDiagnosticsSources `mapstructure:"sources" validate:"omitempty"`
	Enabled bool                         `mapstructure:"enabled"`
}

// OperationsDiagnosticsSources lists the observation sources of the diagnostics service.
type OperationsDiagnosticsSources struct {
	NauthilusRuntime RuntimeDiagnosticsSource    `mapstructure:"nauthilus_runtime" validate:"omitempty"`
	Loki             HistoricalDiagnosticsSource `mapstructure:"loki" validate:"omitempty"`
	Prometheus       HistoricalDiagnosticsSource `mapstructure:"prometheus" validate:"omitempty"`
}

// namedHistoricalSource pairs a historical source with its configuration key.
type namedHistoricalSource struct {
	settings *HistoricalDiagnosticsSource `mapstructure:"-"`
	name     string                       `mapstructure:"-"`
}

// historical returns the historical sources in response order.
func (s *OperationsDiagnosticsSources) historical() []namedHistoricalSource {
	return []namedHistoricalSource{{name: "loki", settings: &s.Loki}, {name: "prometheus", settings: &s.Prometheus}}
}

// RuntimeDiagnosticsSource configures the instance-local runtime source. It is enabled unless disabled explicitly.
type RuntimeDiagnosticsSource struct {
	Enabled *bool `mapstructure:"enabled"`
}

// IsEnabled reports whether the local runtime source is active.
func (s *RuntimeDiagnosticsSource) IsEnabled() bool {
	return s == nil || s.Enabled == nil || *s.Enabled
}

// HistoricalDiagnosticsSource configures one optional historical source (Loki log counts or Prometheus metric
// counts). Only the compiled query profile runs; the selector and tenant are fixed here and never come from a
// request. The tenant is sent as X-Scope-OrgID, which Loki, Mimir, and Cortex read.
type HistoricalDiagnosticsSource struct {
	Selector         map[string]string   `mapstructure:"selector"`
	TLS              HTTPClientTLS       `mapstructure:"tls" validate:"omitempty"`
	BasicAuth        HistoricalBasicAuth `mapstructure:"basic_auth" validate:"omitempty"`
	BearerToken      secret.Value        `mapstructure:"bearer_token"`
	URL              string              `mapstructure:"url"`
	Tenant           string              `mapstructure:"tenant"`
	InstanceLabel    string              `mapstructure:"instance_label"`
	QueryProfile     string              `mapstructure:"query_profile"`
	Timeout          time.Duration       `mapstructure:"timeout"`
	MaxTimeWindow    time.Duration       `mapstructure:"max_time_window"`
	MaxSeries        int                 `mapstructure:"max_series"`
	MaxResponseBytes int64               `mapstructure:"max_response_bytes"`
	Enabled          bool                `mapstructure:"enabled"`
}

// HistoricalBasicAuth carries optional HTTP Basic credentials for a historical source.
type HistoricalBasicAuth struct {
	Password secret.Value `mapstructure:"password"`
	Username string       `mapstructure:"username"`
}

// GetOperationsDiagnostics returns the operations diagnostics section; the empty section disables the service.
func (f *FileSettings) GetOperationsDiagnostics() *OperationsDiagnosticsSection {
	if f == nil || f.Observability == nil {
		return &OperationsDiagnosticsSection{}
	}

	return &f.Observability.Diagnostics.Operations
}

// GetTimeout returns the per-request Loki timeout.
func (s *HistoricalDiagnosticsSource) GetTimeout() time.Duration {
	return positiveDurationOr(s.Timeout, defaultHistoricalTimeout)
}

// GetMaxTimeWindow returns the longest window one Loki query covers.
func (s *HistoricalDiagnosticsSource) GetMaxTimeWindow() time.Duration {
	return positiveDurationOr(s.MaxTimeWindow, defaultHistoricalMaxTimeWindow)
}

// GetMaxSeries returns the series bound of one Loki query result.
func (s *HistoricalDiagnosticsSource) GetMaxSeries() int {
	if s.MaxSeries <= 0 {
		return defaultHistoricalMaxSeries
	}

	return s.MaxSeries
}

// GetMaxResponseBytes returns the byte bound of one Loki response.
func (s *HistoricalDiagnosticsSource) GetMaxResponseBytes() int64 {
	if s.MaxResponseBytes <= 0 {
		return defaultHistoricalMaxResponseBytes
	}

	return s.MaxResponseBytes
}

// GetQueryProfile returns the compiled query profile name.
func (s *HistoricalDiagnosticsSource) GetQueryProfile() string {
	if s.QueryProfile == "" {
		return DiagnosticsQueryProfileNauthilus
	}

	return s.QueryProfile
}

// positiveDurationOr returns value when positive, otherwise fallback.
func positiveDurationOr(value time.Duration, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}

	return value
}

// validateOperationsDiagnostics rejects an invalid diagnostics configuration at load time.
func (f *FileSettings) validateOperationsDiagnostics() error {
	section := f.GetOperationsDiagnostics()
	historical := section.Sources.historical()

	if !section.Enabled {
		for _, source := range historical {
			if source.settings.Enabled {
				return NewValidationProblem(operationsDiagnosticsPath+".enabled", "must be enabled when the "+source.name+" source is enabled")
			}
		}

		return nil
	}

	if !section.Sources.NauthilusRuntime.IsEnabled() && !slices.ContainsFunc(historical, func(source namedHistoricalSource) bool {
		return source.settings.Enabled
	}) {
		return NewValidationProblem(operationsDiagnosticsPath+".sources", "at least one source must be enabled")
	}

	for _, source := range historical {
		if !source.settings.Enabled {
			continue
		}

		if err := source.settings.validate(operationsDiagnosticsPath + ".sources." + source.name); err != nil {
			return err
		}
	}

	return nil
}

// validate checks one enabled historical source.
func (s *HistoricalDiagnosticsSource) validate(path string) error {
	checks := []func(string) error{s.validateEndpoint, s.validateLabels, s.validateCredentials, s.validateBounds}

	for _, check := range checks {
		if err := check(path); err != nil {
			return err
		}
	}

	return nil
}

// validateEndpoint requires an http(s) base URL without query, fragment, or user info and a valid tenant.
func (s *HistoricalDiagnosticsSource) validateEndpoint(path string) error {
	parsed, err := url.Parse(s.URL)
	if err != nil || (parsed.Scheme != uriSchemeHTTPS && parsed.Scheme != uriSchemeHTTP) || parsed.Host == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return NewValidationProblem(path+".url", "must be an http(s) base URL without query, fragment, or user info")
	}

	if s.Tenant != "" && !historicalTenantPattern.MatchString(s.Tenant) {
		return NewValidationProblem(path+".tenant", "must be 1-64 letters, digits, dots, dashes, or underscores")
	}

	if s.GetQueryProfile() != DiagnosticsQueryProfileNauthilus {
		return NewValidationProblem(path+".query_profile", "must be "+DiagnosticsQueryProfileNauthilus)
	}

	return nil
}

// validateLabels requires a non-empty fixed selector and a valid instance label.
func (s *HistoricalDiagnosticsSource) validateLabels(path string) error {
	if len(s.Selector) == 0 {
		return NewValidationProblem(path+".selector", "must name at least one label")
	}

	names := make([]string, 0, len(s.Selector))
	for name := range s.Selector {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if !historicalLabelNamePattern.MatchString(name) {
			return NewValidationProblem(fmt.Sprintf("%s.selector.%s", path, name), "label name is not valid")
		}

		if !historicalLabelValuePattern.MatchString(s.Selector[name]) {
			return NewValidationProblem(fmt.Sprintf("%s.selector.%s", path, name), "label value must be 1-128 plain characters")
		}
	}

	if !historicalLabelNamePattern.MatchString(s.InstanceLabel) {
		return NewValidationProblem(path+".instance_label", "must be a valid label name")
	}

	return nil
}

// validateCredentials allows at most one authentication method; Basic auth needs both parts.
func (s *HistoricalDiagnosticsSource) validateCredentials(path string) error {
	hasBasic := s.BasicAuth.Username != "" || !s.BasicAuth.Password.IsZero()

	if hasBasic && !s.BearerToken.IsZero() {
		return NewValidationProblem(path, "basic_auth and bearer_token are mutually exclusive")
	}

	if hasBasic && (s.BasicAuth.Username == "" || s.BasicAuth.Password.IsZero() || strings.ContainsAny(s.BasicAuth.Username, ": ")) {
		return NewValidationProblem(path+".basic_auth", "requires a username without colon or space and a password")
	}

	return nil
}

// validateBounds keeps timeouts, windows, and result sizes inside fixed ceilings.
func (s *HistoricalDiagnosticsSource) validateBounds(path string) error {
	switch {
	case s.Timeout < 0 || s.GetTimeout() > maxHistoricalTimeout:
		return NewValidationProblem(path+".timeout", "must be at most 30s")
	case s.MaxTimeWindow < 0 || s.GetMaxTimeWindow() > maxHistoricalMaxTimeWindow:
		return NewValidationProblem(path+".max_time_window", "must be at most 24h")
	case s.MaxSeries < 0 || s.GetMaxSeries() > maxHistoricalMaxSeries:
		return NewValidationProblem(path+".max_series", "must be at most 1000")
	case s.MaxResponseBytes < 0 || s.GetMaxResponseBytes() > maxHistoricalMaxResponseBytes:
		return NewValidationProblem(path+".max_response_bytes", "must be at most 8388608")
	default:
		return nil
	}
}

// artifactOperationsDiagnosticsPaths returns the TLS trust and identity paths of every enabled historical source.
func artifactOperationsDiagnosticsPaths(configured File) []string {
	provider, ok := configured.(interface {
		GetOperationsDiagnostics() *OperationsDiagnosticsSection
	})
	if !ok {
		return nil
	}

	section := provider.GetOperationsDiagnostics()
	if !section.Enabled {
		return nil
	}

	var paths []string

	for _, source := range section.Sources.historical() {
		if source.settings.Enabled {
			paths = append(paths, source.settings.TLS.CAFile, source.settings.TLS.Cert, source.settings.TLS.Key)
		}
	}

	return paths
}
