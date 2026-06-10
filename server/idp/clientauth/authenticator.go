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

// Package clientauth provides OOP abstractions for OIDC client authentication endpoints.
// It supports client_secret_basic, client_secret_post, and private_key_jwt (RFC 7523).
package clientauth

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/idp/signing"
	"github.com/croessner/nauthilus/server/secret"
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

const (
	// DefaultPrivateKeyJWTMaxAssertionLifetime bounds accepted private_key_jwt assertion validity.
	DefaultPrivateKeyJWTMaxAssertionLifetime = 5 * time.Minute
	// DefaultPrivateKeyJWTClockSkew allows small clock drift for private_key_jwt assertion validation.
	DefaultPrivateKeyJWTClockSkew = 30 * time.Second

	defaultPrivateKeyJWTMaxAssertionLifetime = DefaultPrivateKeyJWTMaxAssertionLifetime
	defaultPrivateKeyJWTClockSkew            = DefaultPrivateKeyJWTClockSkew
)

// ClientAuthenticator defines the interface for authenticating OIDC clients at protocol endpoints.
type ClientAuthenticator interface {
	// Authenticate verifies the client credentials and returns nil on success.
	Authenticate(request *AuthRequest) error

	// Method returns the authentication method name (e.g. "client_secret_basic", "private_key_jwt").
	Method() string
}

// AuthRequest encapsulates the data needed to authenticate a client at an OIDC protocol endpoint.
type AuthRequest struct {
	// ClientID is the client identifier.
	ClientID string

	// ClientSecret is the client secret (for client_secret_basic/post).
	ClientSecret secret.Value

	// ClientAssertion is the JWT assertion (for private_key_jwt).
	ClientAssertion string

	// ClientAssertionType is the assertion type (for private_key_jwt).
	ClientAssertionType string

	// TokenEndpointURL is the endpoint URL used as the private_key_jwt audience.
	TokenEndpointURL string
}

// PrivateKeyJWTClaims carries claim data needed after successful private_key_jwt authentication.
type PrivateKeyJWTClaims struct {
	ClientID  string
	Audience  string
	JWTID     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// ClientSecretAuthenticator authenticates clients using a shared secret.
// It supports both client_secret_basic and client_secret_post methods.
type ClientSecretAuthenticator struct {
	expectedSecret secret.Value
	method         string
}

// NewClientSecretAuthenticator creates a new ClientSecretAuthenticator.
// The method parameter should be MethodClientSecretBasic or MethodClientSecretPost.
func NewClientSecretAuthenticator(expectedSecret secret.Value, method string) *ClientSecretAuthenticator {
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

	if request.ClientSecret.IsZero() {
		return fmt.Errorf("client secret is empty")
	}

	var expectedSecret []byte
	a.expectedSecret.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		expectedSecret = bytes.Clone(value)
	})

	var providedSecret []byte
	request.ClientSecret.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		providedSecret = bytes.Clone(value)
	})

	if subtle.ConstantTimeCompare(expectedSecret, providedSecret) != 1 {
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
// The issuer should match the client_id, and audience should match the target endpoint URL.
func NewPrivateKeyJWTAuthenticator(verifier signing.Verifier, issuer string, audience string) *PrivateKeyJWTAuthenticator {
	return &PrivateKeyJWTAuthenticator{
		verifier: verifier,
		issuer:   issuer,
		audience: audience,
	}
}

// Authenticate verifies the client assertion JWT per RFC 7523.
func (a *PrivateKeyJWTAuthenticator) Authenticate(request *AuthRequest) error {
	_, err := a.AuthenticateAssertion(request)

	return err
}

// AuthenticateAssertion verifies the assertion and returns replay-relevant claim data.
func (a *PrivateKeyJWTAuthenticator) AuthenticateAssertion(request *AuthRequest) (*PrivateKeyJWTClaims, error) {
	if request == nil {
		return nil, fmt.Errorf("auth request is nil")
	}

	if request.ClientAssertionType != AssertionTypeJWTBearer {
		return nil, fmt.Errorf("unsupported client_assertion_type: %s", request.ClientAssertionType)
	}

	if request.ClientAssertion == "" {
		return nil, fmt.Errorf("client_assertion is empty")
	}

	if a.verifier == nil {
		return nil, fmt.Errorf("client assertion verifier is not configured")
	}

	claims, err := a.verifier.Verify(request.ClientAssertion)
	if err != nil {
		return nil, fmt.Errorf("client assertion verification failed: %w", err)
	}

	// Validate issuer (must match client_id)
	if err := a.validateIssuer(claims); err != nil {
		return nil, err
	}

	// Validate subject (must match client_id)
	if err := a.validateSubject(claims); err != nil {
		return nil, err
	}

	// Validate audience (must contain token endpoint URL)
	if err := a.validateAudience(claims); err != nil {
		return nil, err
	}

	jwtID, err := a.validateJWTID(claims)
	if err != nil {
		return nil, err
	}

	issuedAt, expiresAt, err := a.validateExpiryAndLifetime(claims, time.Now())
	if err != nil {
		return nil, err
	}

	return &PrivateKeyJWTClaims{
		ClientID:  a.issuer,
		Audience:  a.audience,
		JWTID:     jwtID,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}, nil
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

// validateJWTID checks that jti is present and usable as a replay key component.
func (a *PrivateKeyJWTAuthenticator) validateJWTID(claims jwt.MapClaims) (string, error) {
	jwtID, ok := claims["jti"].(string)
	if !ok || strings.TrimSpace(jwtID) == "" {
		return "", fmt.Errorf("missing or invalid jti claim")
	}

	return strings.TrimSpace(jwtID), nil
}

// validateExpiryAndLifetime checks expiry, issued-at skew, and maximum assertion lifetime.
func (a *PrivateKeyJWTAuthenticator) validateExpiryAndLifetime(claims jwt.MapClaims, now time.Time) (time.Time, time.Time, error) {
	expiresAt, ok, err := privateKeyJWTClaimTime(claims, "exp")
	if err != nil || !ok {
		return time.Time{}, time.Time{}, fmt.Errorf("missing or invalid exp claim")
	}

	if !expiresAt.After(now.Add(-defaultPrivateKeyJWTClockSkew)) {
		return time.Time{}, time.Time{}, fmt.Errorf("client assertion has expired")
	}

	notBefore, hasNotBefore, err := privateKeyJWTClaimTime(claims, "nbf")
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("missing or invalid nbf claim")
	}

	if hasNotBefore && notBefore.After(now.Add(defaultPrivateKeyJWTClockSkew)) {
		return time.Time{}, time.Time{}, fmt.Errorf("nbf claim is too far in the future")
	}

	issuedAt, hasIssuedAt, err := privateKeyJWTClaimTime(claims, "iat")
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("missing or invalid iat claim")
	}

	if hasIssuedAt {
		if issuedAt.After(now.Add(defaultPrivateKeyJWTClockSkew)) {
			return time.Time{}, time.Time{}, fmt.Errorf("iat claim is too far in the future")
		}

		if expiresAt.Sub(issuedAt) > defaultPrivateKeyJWTMaxAssertionLifetime {
			return time.Time{}, time.Time{}, fmt.Errorf("client assertion lifetime exceeds maximum")
		}

		return issuedAt, expiresAt, nil
	}

	if expiresAt.Sub(now) > defaultPrivateKeyJWTMaxAssertionLifetime+defaultPrivateKeyJWTClockSkew {
		return time.Time{}, time.Time{}, fmt.Errorf("client assertion lifetime exceeds maximum")
	}

	return time.Time{}, expiresAt, nil
}

// privateKeyJWTClaimTime converts a JWT numeric date claim to a time value.
func privateKeyJWTClaimTime(claims jwt.MapClaims, name string) (time.Time, bool, error) {
	value, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}

	switch typed := value.(type) {
	case float64:
		return time.Unix(int64(typed), 0), true, nil
	case json.Number:
		seconds, err := typed.Int64()
		if err == nil {
			return time.Unix(seconds, 0), true, nil
		}

		floatSeconds, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil {
			return time.Time{}, true, err
		}

		return time.Unix(int64(floatSeconds), 0), true, nil
	case int64:
		return time.Unix(typed, 0), true, nil
	case int:
		return time.Unix(int64(typed), 0), true, nil
	default:
		return time.Time{}, true, fmt.Errorf("claim %s is not a numeric date", name)
	}
}

// Method returns "private_key_jwt".
func (a *PrivateKeyJWTAuthenticator) Method() string {
	return MethodPrivateKeyJWT
}
