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

package dcr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

const (
	metadataSoftwareID      = "software_id"
	metadataSoftwareVersion = "software_version"
	loopbackIPv4            = "127.0.0.1"
	loopbackIPv6            = "::1"
)

var unsupportedRecognizedMetadata = map[string]struct{}{
	"contacts": {}, "client_uri": {}, "logo_uri": {}, "tos_uri": {}, "policy_uri": {},
	"jwks_uri": {}, "jwks": {}, "sector_identifier_uri": {}, "default_max_age": {},
	"require_auth_time": {}, "default_acr_values": {}, "initiate_login_uri": {},
	"request_uris": {}, "post_logout_redirect_uris": {}, "request_object_signing_alg": {},
	"request_object_encryption_alg": {}, "request_object_encryption_enc": {},
	"userinfo_signed_response_alg": {}, "userinfo_encrypted_response_alg": {},
	"userinfo_encrypted_response_enc": {}, "id_token_encrypted_response_alg": {},
	"id_token_encrypted_response_enc": {}, "token_endpoint_auth_signing_alg": {},
	"client_id": {}, "client_secret": {}, "client_id_issued_at": {}, "client_secret_expires_at": {},
	"registration_access_token": {}, "registration_client_uri": {},
}

// DecodeMetadata decodes one RFC 7591 JSON object while ignoring unrecognized metadata.
func DecodeMetadata(reader io.Reader) (RegistrationRequest, *ProtocolError) { //nolint:funlen,gocyclo
	body, err := io.ReadAll(reader)
	if err != nil {
		return RegistrationRequest{}, invalidClientMetadata("request body must be readable JSON")
	}

	if !utf8.Valid(body) {
		return RegistrationRequest{}, invalidClientMetadata("request body must contain valid UTF-8")
	}

	if duplicateJSONMetadataName(body) {
		return RegistrationRequest{}, invalidClientMetadata("request body contains a duplicate metadata name")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return RegistrationRequest{}, invalidClientMetadata("request body must be a JSON object")
	}

	if err := ensureJSONEOF(decoder); err != nil {
		return RegistrationRequest{}, invalidClientMetadata("request body must contain one JSON object")
	}

	request := RegistrationRequest{}
	decoders := map[string]func(json.RawMessage) error{
		"redirect_uris":                func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.RedirectURIs) },
		"grant_types":                  func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.GrantTypes) },
		"response_types":               func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.ResponseTypes) },
		"client_name":                  func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.ClientName) },
		"scope":                        func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.Scope) },
		"token_endpoint_auth_method":   func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.TokenEndpointAuthMethod) },
		"application_type":             func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.ApplicationType) },
		"subject_type":                 func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.SubjectType) },
		"id_token_signed_response_alg": func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.IDTokenSignedResponseAlg) },
		metadataSoftwareID:             func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.SoftwareID) },
		metadataSoftwareVersion:        func(raw json.RawMessage) error { return decodeMetadataValue(raw, &request.SoftwareVersion) },
	}

	for name, raw := range fields {
		if name == "software_statement" {
			var statement string
			if err := decodeMetadataValue(raw, &statement); err != nil {
				return RegistrationRequest{}, invalidClientMetadata("software_statement must be a string")
			}

			return RegistrationRequest{}, newProtocolError("unapproved_software_statement", "software statements are not accepted by this registration profile")
		}

		if _, unsupported := unsupportedRecognizedMetadata[name]; unsupported {
			return RegistrationRequest{}, invalidClientMetadata(fmt.Sprintf("metadata %q is not allowed by this registration profile", name))
		}

		decode, recognized := decoders[name]
		if !recognized {
			continue
		}

		if err := decode(raw); err != nil {
			return RegistrationRequest{}, invalidClientMetadata(fmt.Sprintf("metadata %q has the wrong JSON type", name))
		}
	}

	return request, nil
}

// BuildEffectiveMetadata validates request metadata against the configured native profile.
func BuildEffectiveMetadata(request RegistrationRequest, policy config.OIDCDynamicClientRegistrationConfig) (EffectiveMetadata, *ProtocolError) { //nolint:funlen,gocyclo
	limits := policy.GetLimits()

	redirectURIs, err := validateRedirectURIs(request.RedirectURIs, limits.GetRedirectURIs(), limits.StringBytes)
	if err != nil {
		return EffectiveMetadata{}, err
	}

	if err := validateBoundedString("client_name", request.ClientName, limits.StringBytes, limits.ClientNameRunes); err != nil {
		return EffectiveMetadata{}, err
	}

	for name, value := range map[string]string{metadataSoftwareID: request.SoftwareID, metadataSoftwareVersion: request.SoftwareVersion} {
		if err := validateBoundedString(name, value, limits.StringBytes, limits.StringBytes); err != nil {
			return EffectiveMetadata{}, err
		}
	}

	grantTypes := request.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{GrantAuthorizationCode}
	}

	if !validSet(grantTypes, []string{GrantAuthorizationCode, GrantRefreshToken}) || !slices.Contains(grantTypes, GrantAuthorizationCode) {
		return EffectiveMetadata{}, invalidClientMetadata("grant_types must contain authorization_code and may contain refresh_token")
	}

	responseTypes := request.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{ResponseTypeCode}
	}

	if !slices.Equal(responseTypes, []string{ResponseTypeCode}) {
		return EffectiveMetadata{}, invalidClientMetadata("response_types must be exactly [code]")
	}

	if !emptyOrEqual(request.TokenEndpointAuthMethod, TokenEndpointAuthMethodNone) ||
		!emptyOrEqual(request.ApplicationType, ApplicationTypeNative) ||
		!emptyOrEqual(request.SubjectType, SubjectTypePublic) ||
		!emptyOrEqual(request.IDTokenSignedResponseAlg, IDTokenSigningAlgorithm) {
		return EffectiveMetadata{}, invalidClientMetadata("requested authentication, application, subject, or signing metadata is not allowed")
	}

	scopes, scopeErr := effectiveScopes(request.Scope, policy, limits.GetScopes())
	if scopeErr != nil {
		return EffectiveMetadata{}, scopeErr
	}

	hasRefreshGrant := slices.Contains(grantTypes, GrantRefreshToken)
	hasOfflineAccess := slices.Contains(scopes, definitions.ScopeOfflineAccess)

	if hasRefreshGrant != hasOfflineAccess || (hasRefreshGrant && !policy.AllowRefreshTokens) {
		return EffectiveMetadata{}, invalidClientMetadata("refresh_token and offline_access must be requested together and allowed by policy")
	}

	return EffectiveMetadata{
		RedirectURIs:             redirectURIs,
		GrantTypes:               append([]string(nil), grantTypes...),
		ResponseTypes:            []string{ResponseTypeCode},
		ClientName:               request.ClientName,
		Scope:                    strings.Join(scopes, " "),
		TokenEndpointAuthMethod:  TokenEndpointAuthMethodNone,
		ApplicationType:          ApplicationTypeNative,
		SubjectType:              SubjectTypePublic,
		IDTokenSignedResponseAlg: IDTokenSigningAlgorithm,
		SoftwareID:               request.SoftwareID,
		SoftwareVersion:          request.SoftwareVersion,
	}, nil
}

// MatchRedirectURI applies exact string matching with only the RFC 8252 loopback-port exception.
func MatchRedirectURI(registered []string, candidate string) bool {
	candidateURL, ok := parseLoopbackRedirect(candidate)
	if !ok {
		return false
	}

	for _, registeredValue := range registered {
		registeredURL, valid := parseLoopbackRedirect(registeredValue)
		if !valid {
			continue
		}

		if loopbackURIWithoutPort(candidate, candidateURL) == loopbackURIWithoutPort(registeredValue, registeredURL) && loopbackHostEqual(candidateURL, registeredURL) {
			return true
		}
	}

	return false
}

// duplicateJSONMetadataName reports duplicate top-level registration member names.
func duplicateJSONMetadataName(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))

	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}

	seen := make(map[string]struct{})

	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return false
		}

		name, ok := nameToken.(string)
		if !ok {
			return false
		}

		if _, exists := seen[name]; exists {
			return true
		}

		seen[name] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}

	return false
}

// ensureJSONEOF rejects trailing JSON values.
func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any

	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}

	return fmt.Errorf("trailing JSON value")
}

// decodeMetadataValue decodes one recognized non-null metadata value.
func decodeMetadataValue(raw json.RawMessage, target any) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("null metadata")
	}

	return json.Unmarshal(raw, target)
}

// validateRedirectURIs validates unique literal IPv4 or IPv6 loopback redirects.
func validateRedirectURIs(values []string, maximum int, maximumBytes int) ([]string, *ProtocolError) {
	if len(values) == 0 || len(values) > maximum {
		return nil, invalidRedirectURI("redirect_uris must contain between one and the configured maximum number of values")
	}

	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		if len(value) > maximumBytes {
			return nil, invalidRedirectURI("redirect URI exceeds the configured string limit")
		}

		parsed, ok := parseLoopbackRedirect(value)
		if !ok {
			return nil, invalidRedirectURI("redirect URI must use HTTP with a literal loopback host, numeric port, and safe path without query or fragment")
		}

		identity := loopbackURIWithoutPort(value, parsed)
		if _, exists := seen[identity]; exists {
			return nil, invalidRedirectURI("redirect URIs must remain unique after loopback port normalization")
		}

		seen[identity] = struct{}{}

		result = append(result, value)
	}

	return result, nil
}

// parseLoopbackRedirect parses one strict RFC 8252 loopback-profile URI.
func parseLoopbackRedirect(value string) (*url.URL, bool) { //nolint:gocyclo
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Path == "" {
		return nil, false
	}

	if parsed.EscapedPath() != parsed.Path || strings.Contains(parsed.Path, "\\") || containsTraversalSegment(parsed.Path) {
		return nil, false
	}

	host := parsed.Hostname()
	if host != loopbackIPv4 && host != loopbackIPv6 {
		return nil, false
	}

	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, false
		}
	}

	return parsed, true
}

// containsTraversalSegment rejects dot segments before any path normalization can occur.
func containsTraversalSegment(path string) bool {
	return slices.ContainsFunc(strings.Split(path, "/"), func(segment string) bool {
		return segment == "." || segment == ".."
	})
}

// loopbackHostEqual compares literal loopback hosts while ignoring ports.
func loopbackHostEqual(left *url.URL, right *url.URL) bool {
	return left.Hostname() == right.Hostname()
}

// loopbackURIWithoutPort removes only the authority port from the original string.
func loopbackURIWithoutPort(raw string, parsed *url.URL) string {
	const schemePrefix = "http://"

	authorityEnd := strings.IndexAny(raw[len(schemePrefix):], "/?#")
	if authorityEnd < 0 {
		return raw
	}

	host := parsed.Hostname()
	if host == loopbackIPv6 {
		host = "[" + loopbackIPv6 + "]"
	}

	return schemePrefix + host + raw[len(schemePrefix)+authorityEnd:]
}

// effectiveScopes constructs the requested subset plus mandatory scopes.
func effectiveScopes(raw string, policy config.OIDCDynamicClientRegistrationConfig, maximum int) ([]string, *ProtocolError) {
	requested := splitScope(raw)
	if (raw != "" && strings.Join(requested, " ") != raw) || len(requested) > maximum || !uniqueStrings(requested) ||
		slices.ContainsFunc(requested, func(scope string) bool { return !definitions.IsOAuthScopeToken(scope) }) {
		return nil, invalidClientMetadata("scope contains too many or duplicate values")
	}

	allowed := append(append([]string(nil), policy.RequiredScopes...), policy.OptionalScopes...)
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return nil, invalidClientMetadata(fmt.Sprintf("scope %q is not allowed", scope))
		}
	}

	result := append([]string(nil), policy.RequiredScopes...)
	for _, scope := range requested {
		if !slices.Contains(result, scope) {
			result = append(result, scope)
		}
	}

	if len(result) > maximum {
		return nil, invalidClientMetadata("effective scope exceeds the configured limit")
	}

	return result, nil
}

// splitScope parses an OAuth space-delimited scope string.
func splitScope(raw string) []string {
	if raw == "" {
		return nil
	}

	return strings.Split(raw, " ")
}

// uniqueStrings reports whether every non-empty string occurs once.
func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}

		if _, exists := seen[value]; exists {
			return false
		}

		seen[value] = struct{}{}
	}

	return true
}

// validSet reports whether values are unique and contained in the allowed set.
func validSet(values []string, allowed []string) bool {
	return uniqueStrings(values) && !slices.ContainsFunc(values, func(value string) bool {
		return !slices.Contains(allowed, value)
	})
}

// emptyOrEqual accepts an omitted value or the imposed profile value.
func emptyOrEqual(value string, expected string) bool {
	return value == "" || value == expected
}

// validateBoundedString enforces UTF-8, byte, and rune limits.
func validateBoundedString(name string, value string, maximumBytes int, maximumRunes int) *ProtocolError {
	if !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) || len(value) > maximumBytes || utf8.RuneCountInString(value) > maximumRunes {
		return invalidClientMetadata(fmt.Sprintf("metadata %q exceeds the configured string limit", name))
	}

	return nil
}

// invalidClientMetadata builds a stable RFC 7591 metadata error.
func invalidClientMetadata(description string) *ProtocolError {
	return newProtocolError("invalid_client_metadata", description)
}

// invalidRedirectURI builds a stable RFC 7591 redirect error.
func invalidRedirectURI(description string) *ProtocolError {
	return newProtocolError("invalid_redirect_uri", description)
}
