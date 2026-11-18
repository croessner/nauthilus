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

package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	nautherrors "github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
	"github.com/croessner/nauthilus/v4/server/tokenclaims"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	extraCredential     = "nauthilus.credential"
	extraRequestContext = "nauthilus.request_context"

	errorInvalidToken      = "invalid_token"
	errorInsufficientScope = "insufficient_scope"
	retryAfterSeconds      = "60"
)

var (
	// errInvalidToken rejects a token with 401; the reason is never published.
	errInvalidToken = errors.New("invalid token")

	// errInsufficientScope rejects a valid token without any scope of the resource with 403.
	errInsufficientScope = errors.New("insufficient scope")

	// errUnavailable answers 503 when the token state or the resource configuration cannot be read.
	errUnavailable = errors.New("token authority unavailable")
)

// verifiedKey carries the SDK token info of an authenticated request to the SDK bridge.
type verifiedKey struct{}

// authenticate verifies the bearer token of every endpoint request, answers RFC 6750 / RFC 9728 challenges, bounds
// failed attempts per client IP and in-flight requests per principal, inspects the JSON-RPC body, and hands the
// verified facts to the SDK. No anonymous request reaches a tool.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		clientIP := clientIPOf(request.Context())

		if s.limiter.blocked(clientIP) {
			writer.Header().Set("Retry-After", retryAfterSeconds)
			s.reject(writer, request, http.StatusTooManyRequests, resultRateLimited, "failed_authentication_limit")

			return
		}

		token, present := bearerToken(request)
		if !present {
			s.challenge(writer, request, http.StatusUnauthorized, "", s.resourceScopes(), "missing_token")

			return
		}

		credential, expiry, err := s.verify(request.Context(), token)
		if !s.answerVerification(writer, request, err) {
			return
		}

		release, acquired := s.gate.Acquire(request.Context(), credential.Identity())
		if !acquired {
			writer.Header().Set("Retry-After", "1")
			s.reject(writer, request, http.StatusTooManyRequests, resultBusy, "too_many_requests")

			return
		}

		defer release()

		if !s.inspectBody(writer, request, credential) {
			return
		}

		info := &auth.TokenInfo{Scopes: credential.Scopes, Expiration: expiry, UserID: credential.Identity(),
			Extra: map[string]any{extraCredential: credential, extraRequestContext: request.Context()}}

		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), verifiedKey{}, info)))
	})
}

// answerVerification answers a failed verification and reports whether the request may continue.
func (s *Server) answerVerification(writer http.ResponseWriter, request *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, errUnavailable):
		writer.Header().Set("Retry-After", "5")
		s.reject(writer, request, http.StatusServiceUnavailable, resultError, "token_authority_unavailable")
	case errors.Is(err, errInsufficientScope):
		s.challenge(writer, request, http.StatusForbidden, errorInsufficientScope, s.resourceScopes(), "insufficient_scope")
	default:
		s.limiter.fail(clientIPOf(request.Context()))
		s.challenge(writer, request, http.StatusUnauthorized, errorInvalidToken, s.resourceScopes(), "invalid_token")
	}

	return false
}

// sdkBridge hands the already verified token info to the SDK, which only accepts it through its bearer middleware.
// The bridge verifier never validates anything itself; a request without verified facts is refused.
func sdkBridge(next http.Handler) http.Handler {
	return auth.RequireBearerToken(func(_ context.Context, _ string, request *http.Request) (*auth.TokenInfo, error) {
		info, ok := request.Context().Value(verifiedKey{}).(*auth.TokenInfo)
		if !ok || info == nil {
			return nil, auth.ErrInvalidToken
		}

		return info, nil
	}, nil)(next)
}

// bearerToken returns the token of exactly one Authorization header in the Bearer scheme.
func bearerToken(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}

	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}

	return token, true
}

// verify accepts only a current user access token of the own issuer whose audience is exactly the admitted static
// client plus this resource, issued to a client the hosted resource admits now, with at least one resource scope.
func (s *Server) verify(ctx context.Context, token string) (supportaccess.VerifiedCredential, time.Time, error) {
	verified, err := s.deps.Tokens.ValidateUserAccessToken(ctx, token)
	if err != nil {
		if nautherrors.IsTokenValidationUnavailable(err) {
			return supportaccess.VerifiedCredential{}, time.Time{}, errUnavailable
		}

		return supportaccess.VerifiedCredential{}, time.Time{}, errInvalidToken
	}

	hosted, ok := s.deps.Tokens.HostedResource(s.deps.Settings.HostedResource)
	if !ok || hosted.Resource() != s.resource.String() {
		return supportaccess.VerifiedCredential{}, time.Time{}, errUnavailable
	}

	if !tokenclaims.HasExactAudienceSet(verified.Claims, verified.ClientID, hosted.Resource()) {
		return supportaccess.VerifiedCredential{}, time.Time{}, errInvalidToken
	}

	client, err := s.deps.Tokens.ResolveClient(ctx, verified.ClientID)
	if err != nil || !hosted.Admits(client) {
		return supportaccess.VerifiedCredential{}, time.Time{}, errInvalidToken
	}

	scopes := slices.DeleteFunc(hosted.Scopes(), func(scope string) bool { return !verified.HasScope(scope) })
	if len(scopes) == 0 {
		return supportaccess.VerifiedCredential{}, time.Time{}, errInsufficientScope
	}

	return supportaccess.VerifiedCredential{Method: supportaccess.CredentialOAuthUser, ClientID: verified.ClientID,
		Subject: verified.Subject, Scopes: scopes}, verified.ExpiresAt, nil
}

// resourceScopes returns the scopes the hosted resource gates, for challenges and metadata.
func (s *Server) resourceScopes() []string {
	if hosted, ok := s.deps.Tokens.HostedResource(s.deps.Settings.HostedResource); ok {
		return hosted.Scopes()
	}

	return nil
}

// challenge answers 401 or 403 with an RFC 6750 challenge that points to the RFC 9728 protected resource metadata.
func (s *Server) challenge(writer http.ResponseWriter, request *http.Request, status int, errorCode string, scopes []string, reason string) {
	params := []string{fmt.Sprintf("resource_metadata=%q", s.metadataURL)}

	if errorCode != "" {
		params = append(params, fmt.Sprintf("error=%q", errorCode))
	}

	if len(scopes) > 0 {
		params = append(params, fmt.Sprintf("scope=%q", strings.Join(scopes, " ")))
	}

	writer.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))

	result := resultUnauthorized
	if status == http.StatusForbidden {
		result = resultForbidden
	}

	s.reject(writer, request, status, result, reason)
}

// protectedResourceMetadata serves the RFC 9728 document of the hosted resource from the current configuration.
func (s *Server) protectedResourceMetadata(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed")

		return
	}

	hosted, ok := s.deps.Tokens.HostedResource(s.deps.Settings.HostedResource)
	if !ok || hosted.Resource() != s.resource.String() {
		writeJSONError(writer, http.StatusServiceUnavailable, "resource_not_configured")

		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "max-age=60")

	_ = json.NewEncoder(writer).Encode(map[string]any{
		"resource":                 hosted.Resource(),
		"authorization_servers":    []string{s.deps.Tokens.Issuer()},
		"scopes_supported":         hosted.Scopes(),
		"bearer_methods_supported": []string{"header"},
		"resource_name":            implementationTitle,
	})
}
