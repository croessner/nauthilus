// Copyright (C) 2025 Christian Rößner
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

// Package clientauth provides OOP abstractions for OIDC client authentication methods.
// It supports client_secret_basic, client_secret_post, and private_key_jwt (RFC 7523).
package clientauth

import (
	"crypto/subtle"
	"fmt"
	"slices"
	"time"

	"github.com/croessner/nauthilus/server/idp/signing"
	"github.com/golang-jwt/jwt/v5"
)

// Method constants for supported client authentication methods.
const (
	MethodClientSecretBasic = "client_secret_basic"
	MethodClientSecretPost  = "client_secret_post"
	MethodPrivateKeyJWT     = "private_key_jwt"

	// AssertionTypeJWTBearer is the expected client_assertion_type for private_key_jwt.
	AssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// ClientAuthenticator defines the interface for authenticating OIDC clients at the token endpoint.
type ClientAuthenticator interface {
	// Authenticate verifies the client credentials and returns nil on success.
	Authenticate(request *AuthRequest) error

	// Method returns the authentication method name (e.g. "client_secret_basic", "private_key_jwt").
	Method() string
}

// AuthRequest encapsulates the data needed to authenticate a client at the token endpoint.
type AuthRequest struct {
	// ClientID is the client identifier.
	ClientID string

	// ClientSecret is the client secret (for client_secret_basic/post).
	ClientSecret string

	// ClientAssertion is the JWT assertion (for private_key_jwt).
	ClientAssertion string

	// ClientAssertionType is the assertion type (for private_key_jwt).
	ClientAssertionType string

	// TokenEndpointURL is the URL of the token endpoint (audience for private_key_jwt).
	TokenEndpointURL string
}

// ClientSecretAuthenticator authenticates clients using a shared secret.
// It supports both client_secret_basic and client_secret_post methods.
type ClientSecretAuthenticator struct {
	expectedSecret string
	method         string
}

// NewClientSecretAuthenticator creates a new ClientSecretAuthenticator.
// The method parameter should be MethodClientSecretBasic or MethodClientSecretPost.
func NewClientSecretAuthenticator(expectedSecret string, method string) *ClientSecretAuthenticator {
	return &ClientSecretAuthenticator{
		expectedSecret: expectedSecret,
		method:         method,
	}
}

// Authenticate verifies the client secret using constant-time comparison.
func (a *ClientSecretAuthenticator) Authenticate(request *AuthRequest) error {
	if request == nil {
		return fmt.Errorf("auth request is nil")
	}

	if request.ClientSecret == "" {
		return fmt.Errorf("client secret is empty")
	}

	if subtle.ConstantTimeCompare([]byte(a.expectedSecret), []byte(request.ClientSecret)) != 1 {
		return fmt.Errorf("client secret mismatch")
	}

	return nil
}

// Method returns the authentication method name.
func (a *ClientSecretAuthenticator) Method() string {
	return a.method
}

// PrivateKeyJWTAuthenticator authenticates clients using a signed JWT assertion (RFC 7523).
// The client signs a JWT with its private key, and the server verifies it using the client's public key.
type PrivateKeyJWTAuthenticator struct {
	verifier signing.Verifier
	issuer   string
	audience string
}

// NewPrivateKeyJWTAuthenticator creates a new PrivateKeyJWTAuthenticator.
// The verifier is used to verify the client's JWT assertion.
// The issuer should match the client_id, and audience should be the token endpoint URL.
func NewPrivateKeyJWTAuthenticator(verifier signing.Verifier, issuer string, audience string) *PrivateKeyJWTAuthenticator {
	return &PrivateKeyJWTAuthenticator{
		verifier: verifier,
		issuer:   issuer,
		audience: audience,
	}
}

// Authenticate verifies the client assertion JWT per RFC 7523.
func (a *PrivateKeyJWTAuthenticator) Authenticate(request *AuthRequest) error {
	if request == nil {
		return fmt.Errorf("auth request is nil")
	}

	if request.ClientAssertionType != AssertionTypeJWTBearer {
		return fmt.Errorf("unsupported client_assertion_type: %s", request.ClientAssertionType)
	}

	if request.ClientAssertion == "" {
		return fmt.Errorf("client_assertion is empty")
	}

	claims, err := a.verifier.Verify(request.ClientAssertion)
	if err != nil {
		return fmt.Errorf("client assertion verification failed: %w", err)
	}

	// Validate issuer (must match client_id)
	if err := a.validateIssuer(claims); err != nil {
		return err
	}

	// Validate subject (must match client_id)
	if err := a.validateSubject(claims); err != nil {
		return err
	}

	// Validate audience (must contain token endpoint URL)
	if err := a.validateAudience(claims); err != nil {
		return err
	}

	// Validate expiry
	return a.validateExpiry(claims)
}

// validateIssuer checks that iss matches the expected client_id.
func (a *PrivateKeyJWTAuthenticator) validateIssuer(claims jwt.MapClaims) error {
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		return fmt.Errorf("missing or invalid iss claim")
	}

	if iss != a.issuer {
		return fmt.Errorf("iss claim mismatch: expected %s, got %s", a.issuer, iss)
	}

	return nil
}

// validateSubject checks that sub matches the expected client_id.
func (a *PrivateKeyJWTAuthenticator) validateSubject(claims jwt.MapClaims) error {
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return fmt.Errorf("missing or invalid sub claim")
	}

	if sub != a.issuer {
		return fmt.Errorf("sub claim mismatch: expected %s, got %s", a.issuer, sub)
	}

	return nil
}

// validateAudience checks that aud contains the token endpoint URL.
func (a *PrivateKeyJWTAuthenticator) validateAudience(claims jwt.MapClaims) error {
	switch aud := claims["aud"].(type) {
	case string:
		if aud != a.audience {
			return fmt.Errorf("aud claim mismatch: expected %s, got %s", a.audience, aud)
		}
	case []any:
		if !slices.ContainsFunc(aud, func(value any) bool {
			audience, ok := value.(string)
			return ok && audience == a.audience
		}) {
			return fmt.Errorf("aud claim does not contain expected audience %s", a.audience)
		}
	default:
		return fmt.Errorf("missing or invalid aud claim")
	}

	return nil
}

// validateExpiry checks that the token is not expired.
func (a *PrivateKeyJWTAuthenticator) validateExpiry(claims jwt.MapClaims) error {
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("missing or invalid exp claim")
	}

	if time.Now().Unix() > int64(exp) {
		return fmt.Errorf("client assertion has expired")
	}

	return nil
}

// Method returns "private_key_jwt".
func (a *PrivateKeyJWTAuthenticator) Method() string {
	return MethodPrivateKeyJWT
}
