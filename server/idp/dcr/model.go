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

// Package dcr implements the restricted public-native dynamic registration profile.
package dcr

import (
	"errors"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
)

const (
	// ProfileMailClientV1 identifies the restricted public-native mail profile.
	ProfileMailClientV1 = "mail-client-v1"
	// ClientIDPrefix reserves the namespace for dynamic clients.
	ClientIDPrefix = "dcr_"

	// ApplicationTypeNative is the imposed OAuth native application type.
	ApplicationTypeNative = "native"
	// TokenEndpointAuthMethodNone is the imposed public-client authentication method.
	TokenEndpointAuthMethodNone = "none"
	// SubjectTypePublic is the imposed OIDC subject type.
	SubjectTypePublic = "public"
	// IDTokenSigningAlgorithm is the imposed ID token signing algorithm.
	IDTokenSigningAlgorithm = "RS256"
	// GrantAuthorizationCode is the required OAuth authorization code grant.
	GrantAuthorizationCode = "authorization_code"
	// GrantRefreshToken is the optional paired refresh grant.
	GrantRefreshToken = "refresh_token"
	// ResponseTypeCode is the only supported authorization response type.
	ResponseTypeCode = "code"
)

var (
	// ErrNotFound indicates absent, expired, or revoked dynamic-client state.
	ErrNotFound = errors.New("dynamic client not found")
	// ErrUnavailable indicates that authoritative dynamic-client state cannot be reached.
	ErrUnavailable = errors.New("dynamic client repository unavailable")
	// ErrCorrupt indicates invalid authoritative dynamic-client state.
	ErrCorrupt = errors.New("dynamic client record corrupt")
	// ErrRateLimited indicates a bounded source or global registration rate rejection.
	ErrRateLimited = errors.New("dynamic client registration rate limited")
	// ErrQuota indicates that the active dynamic-client quota is exhausted.
	ErrQuota             = errors.New("dynamic client quota exceeded")
	errClientIDCollision = errors.New("dynamic client id collision")
)

// ProtocolError is a stable RFC 7591 registration error response.
type ProtocolError struct {
	Code        string
	Description string
}

// Error returns the public protocol error code.
func (e *ProtocolError) Error() string {
	if e == nil {
		return ""
	}

	return e.Code
}

// newProtocolError constrains error descriptions to the RFC 7591 character set.
func newProtocolError(code string, description string) *ProtocolError {
	return &ProtocolError{Code: code, Description: sanitizeProtocolErrorDescription(description)}
}

// sanitizeProtocolErrorDescription replaces bytes forbidden by RFC 7591 with question marks.
func sanitizeProtocolErrorDescription(description string) string {
	var result strings.Builder

	result.Grow(len(description))

	for _, value := range []byte(description) {
		if value < 0x20 || value == 0x22 || value == 0x5c || value > 0x7e {
			result.WriteByte('?')

			continue
		}

		result.WriteByte(value)
	}

	return result.String()
}

// RegistrationRequest contains the recognized native-profile metadata.
type RegistrationRequest struct {
	RedirectURIs             []string
	GrantTypes               []string
	ResponseTypes            []string
	ClientName               string
	Scope                    string
	TokenEndpointAuthMethod  string
	ApplicationType          string
	SubjectType              string
	IDTokenSignedResponseAlg string
	SoftwareID               string
	SoftwareVersion          string
}

// EffectiveMetadata contains only metadata accepted and imposed by the profile.
type EffectiveMetadata struct {
	RedirectURIs             []string `json:"redirect_uris"`
	GrantTypes               []string `json:"grant_types"`
	ResponseTypes            []string `json:"response_types"`
	ClientName               string   `json:"client_name,omitempty"`
	Scope                    string   `json:"scope"`
	TokenEndpointAuthMethod  string   `json:"token_endpoint_auth_method"`
	ApplicationType          string   `json:"application_type"`
	SubjectType              string   `json:"subject_type"`
	IDTokenSignedResponseAlg string   `json:"id_token_signed_response_alg"`
	SoftwareID               string   `json:"software_id,omitempty"`
	SoftwareVersion          string   `json:"software_version,omitempty"`
}

// RegistrationResponse is the RFC 7591 success representation for this profile.
type RegistrationResponse struct {
	EffectiveMetadata
	ClientID         string `json:"client_id"`
	ClientIDIssuedAt int64  `json:"client_id_issued_at"`
}

// DynamicClientRecord is the authoritative Redis representation of a dynamic client.
type DynamicClientRecord struct {
	EffectiveMetadata
	ClientID         string        `json:"client_id"`
	Profile          string        `json:"profile"`
	SourceHash       string        `json:"source_hash"`
	ProfileVersion   int           `json:"profile_version"`
	RequiredMFALevel int           `json:"required_mfa_level"`
	CreatedAt        time.Time     `json:"created_at"`
	FirstUsedAt      time.Time     `json:"first_used_at,omitzero"`
	LastUsedAt       time.Time     `json:"last_used_at,omitzero"`
	RevokedAt        time.Time     `json:"revoked_at,omitzero"`
	AccessTokenTTL   time.Duration `json:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `json:"refresh_token_ttl"`
}

// Response returns the public registration representation.
func (r *DynamicClientRecord) Response() RegistrationResponse {
	return RegistrationResponse{
		EffectiveMetadata: r.EffectiveMetadata,
		ClientID:          r.ClientID,
		ClientIDIssuedAt:  r.CreatedAt.Unix(),
	}
}

// OIDCClient materializes the constrained runtime client view.
func (r *DynamicClientRecord) OIDCClient() *config.OIDCClient {
	if r == nil {
		return nil
	}

	revokeRefreshToken := true

	scopes := append([]string(nil), splitScope(r.Scope)...)

	return &config.OIDCClient{
		Name:                    r.ClientName,
		ClientID:                r.ClientID,
		RedirectURIs:            append([]string(nil), r.RedirectURIs...),
		Scopes:                  scopes,
		RequiredScopes:          nil,
		OptionalScopes:          scopes,
		GrantTypes:              append([]string(nil), r.GrantTypes...),
		RequiredMFALevel:        r.RequiredMFALevel,
		AccessTokenType:         "opaque",
		TokenEndpointAuthMethod: TokenEndpointAuthMethodNone,
		AccessTokenLifetime:     r.AccessTokenTTL,
		RefreshTokenLifetime:    r.RefreshTokenTTL,
		ConsentMode:             config.OIDCConsentModeAllOrNothing,
		RequirePKCE:             true,
		RevokeRefreshToken:      &revokeRefreshToken,
		Dynamic:                 true,
	}
}
