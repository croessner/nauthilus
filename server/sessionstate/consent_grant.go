// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strings"
	"time"
)

const (
	consentIdentityReferenceMaxBytes = 512
	consentClientIDMaxBytes          = 256
	consentScopeMaxBytes             = 256
	consentScopeLimit                = 64
)

// ConsentGrantReference derives a stable opaque selector for one identity/client consent pair.
func ConsentGrantReference(identityReference string, clientID string) (Reference, error) {
	identityReference = strings.TrimSpace(identityReference)

	clientID = strings.TrimSpace(clientID)
	if identityReference == "" || len(identityReference) > consentIdentityReferenceMaxBytes ||
		clientID == "" || len(clientID) > consentClientIDMaxBytes {
		return Reference{}, ErrBindingMismatch
	}

	return Reference{
		Session: consentGrantHandle("consent-identity-v1", identityReference),
		Record:  consentGrantHandle("consent-client-v1", identityReference, clientID),
	}, nil
}

func consentGrantHandle(domain string, values ...string) Handle {
	hash := sha256.New()

	_, _ = hash.Write([]byte(domain))
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}

	return Handle(base64.RawURLEncoding.EncodeToString(hash.Sum(nil)))
}

// Covers reports whether a live grant contains every requested normalized scope.
func (g ConsentGrant) Covers(requested []string, now time.Time) bool {
	if !g.GrantedAt.IsZero() && !g.GrantedAt.After(now) && g.GrantExpiresAt.After(now) {
		granted := make(map[string]struct{}, len(g.Scopes))
		for _, scope := range g.Scopes {
			granted[strings.TrimSpace(scope)] = struct{}{}
		}

		for _, scope := range requested {
			if _, ok := granted[strings.TrimSpace(scope)]; !ok {
				return false
			}
		}

		return true
	}

	return false
}

func validateConsentGrant(grant ConsentGrant, reference Reference) error {
	expected, err := ConsentGrantReference(grant.IdentityReference, grant.ClientID)
	if err != nil || expected != reference || grant.Handle != reference.Record ||
		grant.GrantedAt.IsZero() || !grant.GrantExpiresAt.After(grant.GrantedAt) ||
		len(grant.Scopes) == 0 || len(grant.Scopes) > consentScopeLimit {
		return ErrBindingMismatch
	}

	seen := make(map[string]struct{}, len(grant.Scopes))
	for _, scope := range grant.Scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || len(scope) > consentScopeMaxBytes {
			return ErrBindingMismatch
		}

		seen[scope] = struct{}{}
	}

	if len(seen) == 0 {
		return ErrBindingMismatch
	}

	return nil
}

// NormalizeConsentScopes returns one deterministic bounded scope set for persistence.
func NormalizeConsentScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > consentScopeLimit {
		return nil, ErrBindingMismatch
	}

	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || len(scope) > consentScopeMaxBytes {
			return nil, ErrBindingMismatch
		}

		seen[scope] = struct{}{}
	}

	normalized := make([]string, 0, len(seen))
	for scope := range seen {
		normalized = append(normalized, scope)
	}

	slices.Sort(normalized)

	return normalized, nil
}
