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
	"fmt"
	"reflect"

	servererrors "github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/secret"
)

var (
	// ErrAuthentication identifies rejected opaque Policy caller evidence.
	ErrAuthentication = errors.New("policy caller authentication rejected")

	// ErrAuthenticationUnavailable identifies caller evidence that could not be validated for technical
	// reasons. It is never a rejection of the presented credential.
	ErrAuthenticationUnavailable = fmt.Errorf("policy caller authentication unavailable: %w", servererrors.ErrTokenValidationUnavailable)

	// ErrConfiguration identifies an invalid immutable caller-authentication generation.
	ErrConfiguration = errors.New("invalid policy caller authentication configuration")
)

// AccessTokenValidator returns only issuer-validated access-token evidence.
type AccessTokenValidator interface {
	ValidateAccessToken(context.Context, []byte) (ValidatedAccessToken, error)
}

// Configuration contains every caller-authentication rule captured by one runtime generation.
type Configuration struct {
	TokenValidator        AccessTokenValidator
	ExternalProfiles      []ExternalProfile
	InternalCallers       []InternalCaller
	TransportCapabilities TransportCapabilities
	RequireGRPCMTLS       bool
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
