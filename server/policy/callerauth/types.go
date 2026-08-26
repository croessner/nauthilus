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

// Package callerauth authenticates opaque Policy caller evidence against one immutable generation.
package callerauth

import (
	"context"
	"errors"
	"reflect"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/secret"
)

var (
	// ErrAuthentication identifies rejected opaque Policy caller evidence.
	ErrAuthentication = errors.New("policy caller authentication rejected")

	// ErrConfiguration identifies an invalid immutable caller-authentication generation.
	ErrConfiguration = errors.New("invalid policy caller authentication configuration")

	// ErrBasicThrottleLimit identifies a Policy-Basic identity whose bounded failure window is full.
	ErrBasicThrottleLimit = errors.New("policy Basic authentication is throttled")

	// ErrBasicThrottleState identifies malformed Policy-Basic failure state.
	ErrBasicThrottleState = errors.New("invalid policy Basic throttle state")
)

// AccessTokenValidator returns only issuer-validated access-token evidence.
type AccessTokenValidator interface {
	ValidateAccessToken(context.Context, []byte) (ValidatedAccessToken, error)
}

// BasicThrottler gates and records dedicated Policy-Basic verification attempts.
type BasicThrottler interface {
	BeforeAttempt(context.Context, BasicThrottleKey) error
	RecordFailure(context.Context, BasicThrottleKey) error
	RecordSuccess(context.Context, BasicThrottleKey) error
}

// Configuration contains every caller-authentication rule captured by one runtime generation.
type Configuration struct {
	TokenValidator        AccessTokenValidator
	Throttler             BasicThrottler
	ExternalProfiles      []ExternalProfile
	InternalCallers       []InternalCaller
	TransportCapabilities TransportCapabilities
	RequireGRPCMTLS       bool
}

// RequiresBasicThrottler reports whether any candidate profile declares Policy-Basic material or kind.
func (c Configuration) RequiresBasicThrottler() bool {
	for _, profile := range c.ExternalProfiles {
		if profile.Basic != nil {
			return true
		}

		for _, kind := range profile.AuthenticationKinds {
			if kind == policy.CallerAuthenticationKindBasic {
				return true
			}
		}
	}

	return false
}

// TransportCapabilities declares enabled Policy transports capable of satisfying protection.
type TransportCapabilities struct {
	HTTPProtected                 bool
	GRPCProtected                 bool
	GRPCVerifiedClientCertificate bool
}

// ExternalProfile binds one exact OAuth principal to allowed primary authentication kinds.
type ExternalProfile struct {
	Basic               *BasicCredential
	AuthenticationKinds []string
	Principal           string
	RequireMTLS         bool
}

// BasicCredential contains dedicated profile-owned Policy-Basic material.
type BasicCredential struct {
	Password secret.Value
	Username string
}

// InternalCaller binds one named internal principal to an exact opaque capability rule.
type InternalCaller struct {
	Capability           secret.Value
	TransportKinds       []string
	Principal            string
	EvidenceKind         string
	ExpectedMTLSIdentity string
	RequireProtected     bool
}

// ValidatedAccessToken contains structured evidence from an issuer-validating adapter.
type ValidatedAccessToken struct {
	Audiences []string
	Scopes    []string
	ClientID  string
	Subject   string
	Issuer    string
	TokenType string
}

// BasicThrottleKey is a secret-free per-username and normalized source-IP throttle identity.
type BasicThrottleKey struct {
	peer           string
	identityDigest [32]byte
}

// Peer returns the normalized source IP, or an empty fail-safe bucket when unavailable.
func (k BasicThrottleKey) Peer() string {
	return k.peer
}

// IdentityDigest returns a non-reversible fixed-size username identity.
func (k BasicThrottleKey) IdentityDigest() [32]byte {
	return k.identityDigest
}

// typedNilInterface reports whether a non-nil interface contains a nil reference value.
func typedNilInterface(input any) bool {
	if input == nil {
		return false
	}

	value := reflect.ValueOf(input)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
