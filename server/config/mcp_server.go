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
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	// MCPTLSTerminationTrustedReverseProxy terminates TLS at a trusted reverse proxy in front of the listener.
	MCPTLSTerminationTrustedReverseProxy = "trusted_reverse_proxy"

	defaultMCPAddress                   = "127.0.0.1:9097"
	defaultMCPTimeout                   = 15 * time.Second
	maxMCPTimeout                       = time.Minute
	defaultMCPMaxConcurrent             = 8
	maxMCPMaxConcurrent                 = 64
	defaultMCPMaxConcurrentPerPrincipal = 2
	defaultMCPMaxRequestBytes           = int64(64 << 10)
	maxMCPMaxRequestBytes               = int64(1 << 20)
	defaultMCPMaxResponseBytes          = int64(1 << 20)
	maxMCPMaxResponseBytes              = int64(16 << 20)
	defaultMCPFailedAuthPerMinute       = 30

	mcpServerPath = "runtime.servers.mcp"
)

// RuntimeMCPServerSection configures the optional read-only MCP endpoint. Its address, transport, and limits are
// read at startup (changing them requires a restart); the protected resource, its clients, and its scopes live in
// identity.oidc.hosted_resources and follow the identity reload semantics.
type RuntimeMCPServerSection struct {
	TrustedProxies        []string        `mapstructure:"trusted_proxies"`
	AllowedHosts          []string        `mapstructure:"allowed_hosts"`
	AllowedBrowserOrigins []string        `mapstructure:"allowed_browser_origins"`
	Limits                MCPLimits       `mapstructure:"limits" validate:"omitempty"`
	Audit                 MCPAuditSection `mapstructure:"audit" validate:"omitempty"`
	Address               string          `mapstructure:"address"`
	HostedResource        string          `mapstructure:"hosted_resource"`
	TLSTermination        string          `mapstructure:"tls_termination"`
	Enabled               bool            `mapstructure:"enabled"`
}

// MCPLimits bounds the MCP endpoint.
type MCPLimits struct {
	Timeout                   time.Duration `mapstructure:"timeout"`
	MaxConcurrent             int           `mapstructure:"max_concurrent"`
	MaxConcurrentPerPrincipal int           `mapstructure:"max_concurrent_per_principal"`
	MaxRequestBytes           int64         `mapstructure:"max_request_bytes"`
	MaxResponseBytes          int64         `mapstructure:"max_response_bytes"`
	FailedAuthPerMinute       int           `mapstructure:"failed_auth_per_minute"`
}

// MCPAuditSection toggles the transport audit of the MCP endpoint; it is enabled unless disabled explicitly.
type MCPAuditSection struct {
	Enabled *bool `mapstructure:"enabled"`
}

// IsEnabled reports whether MCP transport audit records are written.
func (s *MCPAuditSection) IsEnabled() bool {
	return s == nil || s.Enabled == nil || *s.Enabled
}

// GetMCPServer returns the MCP endpoint section; the empty section disables the endpoint.
func (f *FileSettings) GetMCPServer() *RuntimeMCPServerSection {
	if f == nil || f.Runtime == nil {
		return &RuntimeMCPServerSection{}
	}

	return &f.Runtime.Servers.MCP
}

// GetAddress returns the listen address or the loopback default.
func (s *RuntimeMCPServerSection) GetAddress() string {
	if s == nil || s.Address == "" {
		return defaultMCPAddress
	}

	return s.Address
}

// GetTLSTermination returns the TLS termination mode.
func (s *RuntimeMCPServerSection) GetTLSTermination() string {
	if s == nil || s.TLSTermination == "" {
		return MCPTLSTerminationTrustedReverseProxy
	}

	return s.TLSTermination
}

// GetTimeout returns the per-call time budget.
func (l *MCPLimits) GetTimeout() time.Duration {
	return positiveDurationOr(l.Timeout, defaultMCPTimeout)
}

// GetMaxConcurrent returns the in-flight request bound of the endpoint.
func (l *MCPLimits) GetMaxConcurrent() int {
	return positiveIntOr(l.MaxConcurrent, defaultMCPMaxConcurrent)
}

// GetMaxConcurrentPerPrincipal returns the in-flight request bound of one principal.
func (l *MCPLimits) GetMaxConcurrentPerPrincipal() int {
	return positiveIntOr(l.MaxConcurrentPerPrincipal, defaultMCPMaxConcurrentPerPrincipal)
}

// GetMaxRequestBytes returns the request body bound.
func (l *MCPLimits) GetMaxRequestBytes() int64 {
	return positiveInt64Or(l.MaxRequestBytes, defaultMCPMaxRequestBytes)
}

// GetMaxResponseBytes returns the bound of one tool result (structured content and its text copy together).
func (l *MCPLimits) GetMaxResponseBytes() int64 {
	return positiveInt64Or(l.MaxResponseBytes, defaultMCPMaxResponseBytes)
}

// GetFailedAuthPerMinute returns the failed bearer attempts one client IP may make per minute.
func (l *MCPLimits) GetFailedAuthPerMinute() int {
	return positiveIntOr(l.FailedAuthPerMinute, defaultMCPFailedAuthPerMinute)
}

// positiveIntOr returns value when positive, otherwise fallback.
func positiveIntOr(value int, fallback int) int {
	if value <= 0 {
		return fallback
	}

	return value
}

// positiveInt64Or returns value when positive, otherwise fallback.
func positiveInt64Or(value int64, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}

	return value
}

// validateMCPServer rejects an invalid MCP endpoint configuration at load time.
func (f *FileSettings) validateMCPServer() error {
	section := f.GetMCPServer()
	if !section.Enabled {
		return nil
	}

	if f.IDP == nil || !f.IDP.OIDC.Enabled {
		return NewValidationProblem("identity.oidc.enabled", "must be enabled when the MCP endpoint is enabled")
	}

	hosted, ok := f.IDP.OIDC.FindHostedResource(section.HostedResource)
	if !ok {
		return NewValidationProblem(mcpServerPath+".hosted_resource", "must name an entry of identity.oidc.hosted_resources")
	}

	resource, err := url.Parse(hosted.Resource)
	if err != nil {
		return NewValidationProblem(mcpServerPath+".hosted_resource", "names a resource that is not a URL")
	}

	checks := []func(*RuntimeMCPServerSection, *url.URL) error{
		validateMCPListener, validateMCPProxies, validateMCPHostsAndOrigins, validateMCPLimits,
	}

	for _, check := range checks {
		if err = check(section, resource); err != nil {
			return err
		}
	}

	return nil
}

// validateMCPListener requires a host:port address and the supported TLS termination.
func validateMCPListener(section *RuntimeMCPServerSection, _ *url.URL) error {
	if _, _, err := net.SplitHostPort(section.GetAddress()); err != nil {
		return NewValidationProblem(mcpServerPath+".address", "must be host:port")
	}

	if section.GetTLSTermination() != MCPTLSTerminationTrustedReverseProxy {
		return NewValidationProblem(mcpServerPath+".tls_termination", "must be "+MCPTLSTerminationTrustedReverseProxy)
	}

	return nil
}

// validateMCPProxies requires trusted proxies for an https resource; plain http is accepted only for a loopback
// resource reached directly from loopback.
func validateMCPProxies(section *RuntimeMCPServerSection, resource *url.URL) error {
	for idx, entry := range section.TrustedProxies {
		if _, err := netip.ParsePrefix(entry); err == nil {
			continue
		}

		if _, err := netip.ParseAddr(entry); err != nil {
			return NewValidationProblem(fmt.Sprintf("%s.trusted_proxies[%d]", mcpServerPath, idx), "must be an IP address or CIDR")
		}
	}

	if resource.Scheme == uriSchemeHTTPS && len(section.TrustedProxies) == 0 {
		return NewValidationProblem(mcpServerPath+".trusted_proxies", "must list the TLS-terminating reverse proxy for an https resource")
	}

	return nil
}

// validateMCPHostsAndOrigins requires plain host values and absolute browser origins.
func validateMCPHostsAndOrigins(section *RuntimeMCPServerSection, _ *url.URL) error {
	for idx, host := range section.AllowedHosts {
		if host == "" || strings.ContainsAny(host, "/ @") {
			return NewValidationProblem(fmt.Sprintf("%s.allowed_hosts[%d]", mcpServerPath, idx), "must be a host or host:port")
		}
	}

	for idx, origin := range section.AllowedBrowserOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") ||
			parsed.RawQuery != "" || slices.Contains([]string{"*", "null"}, origin) {
			return NewValidationProblem(fmt.Sprintf("%s.allowed_browser_origins[%d]", mcpServerPath, idx), "must be an origin such as https://host")
		}
	}

	return nil
}

// validateMCPLimits keeps every limit inside its ceiling.
func validateMCPLimits(section *RuntimeMCPServerSection, _ *url.URL) error {
	limits := &section.Limits
	path := mcpServerPath + ".limits"

	switch {
	case limits.Timeout < 0 || limits.GetTimeout() > maxMCPTimeout:
		return NewValidationProblem(path+".timeout", "must be at most 1m")
	case limits.MaxConcurrent < 0 || limits.GetMaxConcurrent() > maxMCPMaxConcurrent:
		return NewValidationProblem(path+".max_concurrent", "must be at most 64")
	case limits.MaxConcurrentPerPrincipal < 0 || limits.GetMaxConcurrentPerPrincipal() > limits.GetMaxConcurrent():
		return NewValidationProblem(path+".max_concurrent_per_principal", "must not exceed max_concurrent")
	case limits.MaxRequestBytes < 0 || limits.GetMaxRequestBytes() > maxMCPMaxRequestBytes:
		return NewValidationProblem(path+".max_request_bytes", "must be at most 1048576")
	case limits.MaxResponseBytes < 0 || limits.GetMaxResponseBytes() > maxMCPMaxResponseBytes:
		return NewValidationProblem(path+".max_response_bytes", "must be at most 16777216")
	case limits.FailedAuthPerMinute < 0:
		return NewValidationProblem(path+".failed_auth_per_minute", "must not be negative")
	default:
		return nil
	}
}
