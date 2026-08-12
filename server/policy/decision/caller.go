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

package decision

import (
	"net/netip"
	"unicode/utf8"
)

const maximumIdentityTextLength = 512

// TrustedCallerInput is host-created evidence, never public request input.
type TrustedCallerInput struct {
	Principal          string
	ClientID           string
	Subject            string
	Issuer             string
	Scopes             []string
	AuthenticationKind string
	SourceIP           netip.Addr
	MTLSIdentity       string
	TransportKind      string
	Listener           string
	HTTPRoute          string
	GRPCMethod         string
	Internal           bool
}

// CallerContext is deeply owned trusted caller and transport evidence.
type CallerContext struct {
	principal          string
	clientID           string
	subject            string
	issuer             string
	scopes             []string
	authenticationKind string
	mtlsIdentity       string
	transportKind      string
	listener           string
	httpRoute          string
	grpcMethod         string
	sourceIP           netip.Addr
	internal           bool
}

// NewCallerContext validates and copies host-created caller evidence.
func NewCallerContext(input TrustedCallerInput) (CallerContext, error) {
	if !validIdentityText(input.Principal) {
		return CallerContext{}, invalidCaller("caller.principal", "must be non-empty bounded UTF-8")
	}

	if !validIdentityText(input.AuthenticationKind) || !validIdentityText(input.TransportKind) {
		return CallerContext{}, invalidCaller(
			"caller",
			"authentication and transport kinds must be non-empty bounded UTF-8",
		)
	}

	if input.SourceIP.IsValid() && input.SourceIP.Is4In6() {
		input.SourceIP = input.SourceIP.Unmap()
	}

	if !validOptionalCallerFields(input) || !validScopes(input.Scopes) {
		return CallerContext{}, invalidCaller("caller", "contains invalid identity text or scopes")
	}

	return CallerContext{
		principal:          input.Principal,
		clientID:           input.ClientID,
		subject:            input.Subject,
		issuer:             input.Issuer,
		scopes:             append([]string(nil), input.Scopes...),
		authenticationKind: input.AuthenticationKind,
		mtlsIdentity:       input.MTLSIdentity,
		transportKind:      input.TransportKind,
		listener:           input.Listener,
		httpRoute:          input.HTTPRoute,
		grpcMethod:         input.GRPCMethod,
		sourceIP:           input.SourceIP,
		internal:           input.Internal,
	}, nil
}

// Principal returns the authenticated caller principal.
func (c CallerContext) Principal() string {
	return c.principal
}

// ClientID returns the authenticated client identity.
func (c CallerContext) ClientID() string {
	return c.clientID
}

// Subject returns the validated token subject.
func (c CallerContext) Subject() string {
	return c.subject
}

// Issuer returns the validated token issuer.
func (c CallerContext) Issuer() string {
	return c.issuer
}

// Scopes returns a detached copy of authenticated scopes.
func (c CallerContext) Scopes() []string {
	return append([]string(nil), c.scopes...)
}

// AuthenticationKind returns the host-selected authentication kind.
func (c CallerContext) AuthenticationKind() string {
	return c.authenticationKind
}

// SourceIP returns the server-observed source address.
func (c CallerContext) SourceIP() netip.Addr {
	return c.sourceIP
}

// MTLSIdentity returns the verified mutual-TLS identity.
func (c CallerContext) MTLSIdentity() string {
	return c.mtlsIdentity
}

// TransportKind returns the host-selected transport kind.
func (c CallerContext) TransportKind() string {
	return c.transportKind
}

// Listener returns the host-selected listener identity.
func (c CallerContext) Listener() string {
	return c.listener
}

// HTTPRoute returns the matched host route.
func (c CallerContext) HTTPRoute() string {
	return c.httpRoute
}

// GRPCMethod returns the matched host gRPC method.
func (c CallerContext) GRPCMethod() string {
	return c.grpcMethod
}

// Internal reports whether the host selected a named internal caller profile.
func (c CallerContext) Internal() bool {
	return c.internal
}

// valid reports whether caller context satisfies its constructor invariant.
func (c CallerContext) valid() bool {
	return validIdentityText(c.principal) &&
		validIdentityText(c.authenticationKind) &&
		validIdentityText(c.transportKind) &&
		validScopes(c.scopes)
}

// validOptionalCallerFields validates optional trusted text fields.
func validOptionalCallerFields(input TrustedCallerInput) bool {
	for _, value := range []string{
		input.ClientID,
		input.Subject,
		input.Issuer,
		input.MTLSIdentity,
		input.Listener,
		input.HTTPRoute,
		input.GRPCMethod,
	} {
		if value != "" && !validIdentityText(value) {
			return false
		}
	}

	return true
}

// validScopes validates bounded unique authenticated scope values.
func validScopes(scopes []string) bool {
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !validIdentityText(scope) {
			return false
		}

		if _, exists := seen[scope]; exists {
			return false
		}

		seen[scope] = struct{}{}
	}

	return true
}

// validIdentityText validates bounded non-empty UTF-8 identity text.
func validIdentityText(input string) bool {
	return input != "" && len(input) <= maximumIdentityTextLength && utf8.ValidString(input)
}

// invalidCaller constructs a trusted-caller taxonomy error.
func invalidCaller(field string, reason string) error {
	return newContractError(ErrInvalidCaller, ErrorCodeInvalidCaller, field, reason)
}
