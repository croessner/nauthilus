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
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
)

const (
	// LokiQueryProfileNauthilusDiagnostics is the only compiled Loki query profile.
	LokiQueryProfileNauthilusDiagnostics = "nauthilus_diagnostics"

	defaultLokiTimeout          = 3 * time.Second
	maxLokiTimeout              = 30 * time.Second
	defaultLokiMaxTimeWindow    = time.Hour
	maxLokiMaxTimeWindow        = 24 * time.Hour
	defaultLokiMaxSeries        = 200
	maxLokiMaxSeries            = 1000
	defaultLokiMaxResponseBytes = int64(1 << 20)
	maxLokiMaxResponseBytes     = int64(8 << 20)

	operationsDiagnosticsPath = "observability.diagnostics.operations"
)

var (
	// lokiLabelNamePattern restricts selector and instance label names to Prometheus label syntax.
	lokiLabelNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

	// lokiLabelValuePattern restricts selector values to characters that need no LogQL escaping.
	lokiLabelValuePattern = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,128}$`)

	// lokiTenantPattern restricts the tenant header value.
	lokiTenantPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
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
	NauthilusRuntime RuntimeDiagnosticsSource `mapstructure:"nauthilus_runtime" validate:"omitempty"`
	Loki             LokiDiagnosticsSource    `mapstructure:"loki" validate:"omitempty"`
}

// RuntimeDiagnosticsSource configures the instance-local runtime source. It is enabled unless disabled explicitly.
type RuntimeDiagnosticsSource struct {
	Enabled *bool `mapstructure:"enabled"`
}

// IsEnabled reports whether the local runtime source is active.
func (s *RuntimeDiagnosticsSource) IsEnabled() bool {
	return s == nil || s.Enabled == nil || *s.Enabled
}

// LokiDiagnosticsSource configures the optional historical Loki source. Only the compiled query profile runs; the
// selector and tenant are fixed here and never come from a request.
type LokiDiagnosticsSource struct {
	Selector         map[string]string `mapstructure:"selector"`
	TLS              HTTPClientTLS     `mapstructure:"tls" validate:"omitempty"`
	BasicAuth        LokiBasicAuth     `mapstructure:"basic_auth" validate:"omitempty"`
	BearerToken      secret.Value      `mapstructure:"bearer_token"`
	URL              string            `mapstructure:"url"`
	Tenant           string            `mapstructure:"tenant"`
	InstanceLabel    string            `mapstructure:"instance_label"`
	QueryProfile     string            `mapstructure:"query_profile"`
	Timeout          time.Duration     `mapstructure:"timeout"`
	MaxTimeWindow    time.Duration     `mapstructure:"max_time_window"`
	MaxSeries        int               `mapstructure:"max_series"`
	MaxResponseBytes int64             `mapstructure:"max_response_bytes"`
	Enabled          bool              `mapstructure:"enabled"`
}

// LokiBasicAuth carries optional HTTP Basic credentials for Loki.
type LokiBasicAuth struct {
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
func (s *LokiDiagnosticsSource) GetTimeout() time.Duration {
	return positiveDurationOr(s.Timeout, defaultLokiTimeout)
}

// GetMaxTimeWindow returns the longest window one Loki query covers.
func (s *LokiDiagnosticsSource) GetMaxTimeWindow() time.Duration {
	return positiveDurationOr(s.MaxTimeWindow, defaultLokiMaxTimeWindow)
}

// GetMaxSeries returns the series bound of one Loki query result.
func (s *LokiDiagnosticsSource) GetMaxSeries() int {
	if s.MaxSeries <= 0 {
		return defaultLokiMaxSeries
	}

	return s.MaxSeries
}

// GetMaxResponseBytes returns the byte bound of one Loki response.
func (s *LokiDiagnosticsSource) GetMaxResponseBytes() int64 {
	if s.MaxResponseBytes <= 0 {
		return defaultLokiMaxResponseBytes
	}

	return s.MaxResponseBytes
}

// GetQueryProfile returns the compiled query profile name.
func (s *LokiDiagnosticsSource) GetQueryProfile() string {
	if s.QueryProfile == "" {
		return LokiQueryProfileNauthilusDiagnostics
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
	if !section.Enabled {
		if section.Sources.Loki.Enabled {
			return NewValidationProblem(operationsDiagnosticsPath+".enabled", "must be enabled when the loki source is enabled")
		}

		return nil
	}

	if !section.Sources.NauthilusRuntime.IsEnabled() && !section.Sources.Loki.Enabled {
		return NewValidationProblem(operationsDiagnosticsPath+".sources", "at least one source must be enabled")
	}

	if !section.Sources.Loki.Enabled {
		return nil
	}

	return section.Sources.Loki.validate(operationsDiagnosticsPath + ".sources.loki")
}

// validate checks one enabled Loki source.
func (s *LokiDiagnosticsSource) validate(path string) error {
	checks := []func(string) error{s.validateEndpoint, s.validateLabels, s.validateCredentials, s.validateBounds}

	for _, check := range checks {
		if err := check(path); err != nil {
			return err
		}
	}

	return nil
}

// validateEndpoint requires an http(s) base URL without query, fragment, or user info and a valid tenant.
func (s *LokiDiagnosticsSource) validateEndpoint(path string) error {
	parsed, err := url.Parse(s.URL)
	if err != nil || (parsed.Scheme != uriSchemeHTTPS && parsed.Scheme != uriSchemeHTTP) || parsed.Host == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return NewValidationProblem(path+".url", "must be an http(s) base URL without query, fragment, or user info")
	}

	if s.Tenant != "" && !lokiTenantPattern.MatchString(s.Tenant) {
		return NewValidationProblem(path+".tenant", "must be 1-64 letters, digits, dots, dashes, or underscores")
	}

	if s.GetQueryProfile() != LokiQueryProfileNauthilusDiagnostics {
		return NewValidationProblem(path+".query_profile", "must be "+LokiQueryProfileNauthilusDiagnostics)
	}

	return nil
}

// validateLabels requires a non-empty fixed selector and a valid instance label.
func (s *LokiDiagnosticsSource) validateLabels(path string) error {
	if len(s.Selector) == 0 {
		return NewValidationProblem(path+".selector", "must name at least one label")
	}

	names := make([]string, 0, len(s.Selector))
	for name := range s.Selector {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if !lokiLabelNamePattern.MatchString(name) {
			return NewValidationProblem(fmt.Sprintf("%s.selector.%s", path, name), "label name is not valid")
		}

		if !lokiLabelValuePattern.MatchString(s.Selector[name]) {
			return NewValidationProblem(fmt.Sprintf("%s.selector.%s", path, name), "label value must be 1-128 plain characters")
		}
	}

	if !lokiLabelNamePattern.MatchString(s.InstanceLabel) {
		return NewValidationProblem(path+".instance_label", "must be a valid label name")
	}

	return nil
}

// validateCredentials allows at most one authentication method; Basic auth needs both parts.
func (s *LokiDiagnosticsSource) validateCredentials(path string) error {
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
func (s *LokiDiagnosticsSource) validateBounds(path string) error {
	switch {
	case s.Timeout < 0 || s.GetTimeout() > maxLokiTimeout:
		return NewValidationProblem(path+".timeout", "must be at most 30s")
	case s.MaxTimeWindow < 0 || s.GetMaxTimeWindow() > maxLokiMaxTimeWindow:
		return NewValidationProblem(path+".max_time_window", "must be at most 24h")
	case s.MaxSeries < 0 || s.GetMaxSeries() > maxLokiMaxSeries:
		return NewValidationProblem(path+".max_series", "must be at most 1000")
	case s.MaxResponseBytes < 0 || s.GetMaxResponseBytes() > maxLokiMaxResponseBytes:
		return NewValidationProblem(path+".max_response_bytes", "must be at most 8388608")
	default:
		return nil
	}
}

// artifactOperationsDiagnosticsPaths returns the Loki TLS trust and identity paths of an enabled Loki source.
func artifactOperationsDiagnosticsPaths(configured File) []string {
	provider, ok := configured.(interface {
		GetOperationsDiagnostics() *OperationsDiagnosticsSection
	})
	if !ok {
		return nil
	}

	section := provider.GetOperationsDiagnostics()
	if !section.Enabled || !section.Sources.Loki.Enabled {
		return nil
	}

	tls := section.Sources.Loki.TLS

	return []string{tls.CAFile, tls.Cert, tls.Key}
}
