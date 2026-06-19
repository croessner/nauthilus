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

// Package monitoring contains backend reachability and protocol health-check logic.
package monitoring

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
)

// HealthAuthMechanism identifies one authentication mechanism executable by backend health checks.
type HealthAuthMechanism string

const (
	// HealthAuthMechanismAuto requests automatic health-check mechanism selection.
	HealthAuthMechanismAuto HealthAuthMechanism = config.BackendAuthMechanismAuto
	// HealthAuthMechanismPlain selects SASL PLAIN.
	HealthAuthMechanismPlain HealthAuthMechanism = config.BackendAuthMechanismPlain
	// HealthAuthMechanismLogin selects SASL LOGIN.
	HealthAuthMechanismLogin HealthAuthMechanism = config.BackendAuthMechanismLogin
	// HealthAuthMechanismUserPass selects POP3 USER/PASS.
	HealthAuthMechanismUserPass HealthAuthMechanism = config.BackendAuthMechanismUserPass
	// HealthAuthMechanismBasic selects HTTP Basic authentication.
	HealthAuthMechanismBasic HealthAuthMechanism = config.BackendAuthMechanismBasic
)

// AuthCapabilities is the protocol-neutral capability model consumed by AuthSelector.
type AuthCapabilities struct {
	Mechanisms           map[HealthAuthMechanism]struct{}
	InitialResponses     map[HealthAuthMechanism]struct{}
	NativeMechanisms     map[HealthAuthMechanism]struct{}
	Raw                  []string
	Source               string
	SASLIR               bool
	SupportsCapabilities bool
	SupportsMechanisms   bool
}

// NewAuthCapabilities creates an empty capability set for one protocol adapter.
func NewAuthCapabilities(source string) AuthCapabilities {
	return AuthCapabilities{
		Mechanisms:           make(map[HealthAuthMechanism]struct{}),
		InitialResponses:     make(map[HealthAuthMechanism]struct{}),
		NativeMechanisms:     make(map[HealthAuthMechanism]struct{}),
		Source:               source,
		SupportsCapabilities: true,
		SupportsMechanisms:   true,
	}
}

// newAuthCapabilitiesWithRaw creates a capability set that preserves original protocol lines for diagnostics.
func newAuthCapabilitiesWithRaw(source string, raw []string) AuthCapabilities {
	capabilities := NewAuthCapabilities(source)

	capabilities.Raw = append([]string(nil), raw...)

	return capabilities
}

// AddMechanism records one executable mechanism and its protocol-specific execution traits.
func (c *AuthCapabilities) AddMechanism(mechanism HealthAuthMechanism, initialResponse bool, native bool) {
	if c == nil || mechanism == "" || mechanism == HealthAuthMechanismAuto {
		return
	}

	if c.Mechanisms == nil {
		c.Mechanisms = make(map[HealthAuthMechanism]struct{})
	}

	c.Mechanisms[mechanism] = struct{}{}
	if initialResponse {
		if c.InitialResponses == nil {
			c.InitialResponses = make(map[HealthAuthMechanism]struct{})
		}

		c.InitialResponses[mechanism] = struct{}{}
	}

	if native {
		if c.NativeMechanisms == nil {
			c.NativeMechanisms = make(map[HealthAuthMechanism]struct{})
		}

		c.NativeMechanisms[mechanism] = struct{}{}
	}
}

// HasMechanism reports whether the adapter advertised one executable mechanism.
func (c *AuthCapabilities) HasMechanism(mechanism HealthAuthMechanism) bool {
	if c == nil {
		return false
	}

	_, exists := c.Mechanisms[mechanism]

	return exists
}

// allowsInitialResponse reports whether a mechanism may be sent with an initial client response.
func (c *AuthCapabilities) allowsInitialResponse(mechanism HealthAuthMechanism) bool {
	if c == nil {
		return false
	}

	_, exists := c.InitialResponses[mechanism]

	return exists
}

// isNative reports whether a mechanism is backed by a protocol-native command flow.
func (c *AuthCapabilities) isNative(mechanism HealthAuthMechanism) bool {
	if c == nil {
		return false
	}

	_, exists := c.NativeMechanisms[mechanism]

	return exists
}

// advertisedMechanisms returns a stable mechanism list for logs and typed errors.
func (c *AuthCapabilities) advertisedMechanisms() []string {
	if c == nil {
		return nil
	}

	mechanisms := make([]string, 0, len(c.Mechanisms))
	for mechanism := range c.Mechanisms {
		mechanisms = append(mechanisms, string(mechanism))
	}

	slices.Sort(mechanisms)

	return mechanisms
}

// AuthSelection is the selector result executed by a protocol session.
type AuthSelection struct {
	Mechanism       HealthAuthMechanism
	InitialResponse bool
	Native          bool
}

// AuthMechanismUnavailableError reports that the selected target mechanism cannot be used.
type AuthMechanismUnavailableError struct {
	Protocol   string
	Host       string
	Configured HealthAuthMechanism
	Advertised []string
	Port       int
	SASLIR     bool
	Auto       bool
	Capability string
}

// Error formats the mechanism mismatch for callers while leaving sensitive payloads out.
func (e *AuthMechanismUnavailableError) Error() string {
	if e == nil {
		return "backend health-check auth mechanism unavailable"
	}

	configured := string(e.Configured)
	if e.Auto {
		configured = string(HealthAuthMechanismAuto)
	}

	return fmt.Sprintf("backend health-check auth mechanism unavailable: protocol=%s host=%s port=%d configured=%s advertised=%s",
		e.Protocol, e.Host, e.Port, configured, strings.Join(e.Advertised, ","))
}

// AuthSelector applies target configuration to protocol-neutral auth capabilities.
type AuthSelector struct {
	logger *slog.Logger
	server *config.BackendServer
	phase  BackendCheckPhase
}

// NewAuthSelector returns a selector for one backend target and health-check phase.
func NewAuthSelector(logger *slog.Logger, server *config.BackendServer, phase BackendCheckPhase) *AuthSelector {
	return &AuthSelector{
		logger: logger,
		server: server,
		phase:  phase,
	}
}

// Select validates the configured mechanism and returns the concrete exchange form to execute.
func (s *AuthSelector) Select(capabilities AuthCapabilities) (AuthSelection, error) {
	configured := normalizeHealthAuthMechanism(s.server.GetAuthMechanism())
	if configured != HealthAuthMechanismAuto {
		return s.selectExplicit(configured, capabilities)
	}

	for _, candidate := range authAutoSelectionPriority() {
		if !capabilities.HasMechanism(candidate.mechanism) {
			continue
		}

		if candidate.initialResponse && !capabilities.allowsInitialResponse(candidate.mechanism) {
			continue
		}

		return AuthSelection{
			Mechanism:       candidate.mechanism,
			InitialResponse: candidate.initialResponse,
			Native:          capabilities.isNative(candidate.mechanism),
		}, nil
	}

	return AuthSelection{}, s.unavailable(HealthAuthMechanismAuto, capabilities, true)
}

// selectExplicit validates one configured mechanism against the adapter capability set.
func (s *AuthSelector) selectExplicit(configured HealthAuthMechanism, capabilities AuthCapabilities) (AuthSelection, error) {
	if !capabilities.HasMechanism(configured) {
		return AuthSelection{}, s.unavailable(configured, capabilities, false)
	}

	return AuthSelection{
		Mechanism:       configured,
		InitialResponse: capabilities.allowsInitialResponse(configured),
		Native:          capabilities.isNative(configured),
	}, nil
}

// unavailable builds and logs a structured mechanism selection failure.
func (s *AuthSelector) unavailable(configured HealthAuthMechanism, capabilities AuthCapabilities, auto bool) error {
	err := &AuthMechanismUnavailableError{
		Configured: configured,
		Advertised: capabilities.advertisedMechanisms(),
		SASLIR:     capabilities.SASLIR,
		Auto:       auto,
		Capability: capabilities.Source,
	}
	if s != nil && s.server != nil {
		err.Protocol = strings.ToLower(s.server.Protocol)
		err.Host = s.server.Host
		err.Port = s.server.Port
	}

	if s != nil {
		s.logUnavailable(err)
	}

	return err
}

// logUnavailable emits the configured-mechanism mismatch without exposing credentials or SASL payloads.
func (s *AuthSelector) logUnavailable(err *AuthMechanismUnavailableError) {
	if s == nil || err == nil {
		return
	}

	_ = level.Error(s.logger).Log(
		definitions.LogKeyMsg, "Backend health-check auth mechanism unavailable",
		"protocol", err.Protocol,
		"host", err.Host,
		"port", err.Port,
		"configured_auth_mechanism", string(err.Configured),
		"advertised_auth_mechanisms", err.Advertised,
		"sasl_ir", err.SASLIR,
		"auth_capability_source", err.Capability,
		"health_check_phase", string(s.phase),
		definitions.LogKeyError, err,
	)
}

// authSelectionCandidate describes one preference slot in automatic mechanism selection.
type authSelectionCandidate struct {
	mechanism       HealthAuthMechanism
	initialResponse bool
}

// authAutoSelectionPriority returns the deterministic order used for target-local auto selection.
func authAutoSelectionPriority() []authSelectionCandidate {
	return []authSelectionCandidate{
		{mechanism: HealthAuthMechanismPlain, initialResponse: true},
		{mechanism: HealthAuthMechanismPlain},
		{mechanism: HealthAuthMechanismLogin, initialResponse: true},
		{mechanism: HealthAuthMechanismLogin},
		{mechanism: HealthAuthMechanismUserPass},
		{mechanism: HealthAuthMechanismBasic},
	}
}

// normalizeHealthAuthMechanism converts config strings into the selector mechanism type.
func normalizeHealthAuthMechanism(mechanism string) HealthAuthMechanism {
	return HealthAuthMechanism(config.NormalizeBackendAuthMechanism(mechanism))
}

// normalizeAdvertisedAuthMechanism accepts only mechanisms executable by health checks.
func normalizeAdvertisedAuthMechanism(mechanism string) (HealthAuthMechanism, bool) {
	normalized := normalizeHealthAuthMechanism(strings.Trim(mechanism, `"`))
	switch normalized {
	case HealthAuthMechanismPlain, HealthAuthMechanismLogin, HealthAuthMechanismUserPass, HealthAuthMechanismBasic:
		return normalized, true
	default:
		return "", false
	}
}

// plainInitialResponse builds the SASL PLAIN initial-response payload.
func plainInitialResponse(username string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
}

// loginResponse encodes one SASL LOGIN challenge response.
func loginResponse(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

// basicAuthResponse builds the HTTP Basic credential payload.
func basicAuthResponse(username string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// logInitialResponseFallback records the single permitted retry from initial response to classic exchange.
func logInitialResponseFallback(logger *slog.Logger, server *config.BackendServer, mechanism HealthAuthMechanism, response string) {
	if server == nil {
		return
	}

	_ = level.Warn(logger).Log(
		definitions.LogKeyMsg, "Backend health-check auth initial response rejected; falling back to classic exchange",
		"protocol", strings.ToLower(server.Protocol),
		"host", server.Host,
		"port", server.Port,
		"selected_auth_mechanism", string(mechanism),
		"initial_response_fallback", true,
		"server_response", response,
	)
}
