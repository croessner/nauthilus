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

package idp

import (
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/gin-gonic/gin"
)

// oidcAuthorizeFlowContext wraps cookie-backed context handling for the
// OIDC authorization-code flow.
type oidcAuthorizeFlowContext struct {
	mgr cookie.Manager
}

// newOIDCAuthorizeFlowContext creates an authorization flow context bound
// to the current cookie manager.
func newOIDCAuthorizeFlowContext(mgr cookie.Manager) *oidcAuthorizeFlowContext {
	return &oidcAuthorizeFlowContext{mgr: mgr}
}

// StoreRequest stores non-flow OIDC authorization request context needed by
// downstream authentication helpers.
func (c *oidcAuthorizeFlowContext) StoreRequest(
	clientID, redirectURI, scope, state, nonce, responseType, prompt string,
) {
	_ = clientID
	_ = redirectURI
	_ = scope
	_ = state
	_ = nonce
	_ = responseType
	_ = prompt

	if c == nil || c.mgr == nil {
		return
	}

	// Flow-specific request values are written via FlowController/FlowStore metadata.
	// Keep only protocol as non-flow session context for downstream auth helpers.
	c.mgr.Set(definitions.SessionKeyProtocol, definitions.ProtoOIDC)
}

// Account returns the currently selected account from session context.
func (c *oidcAuthorizeFlowContext) Account() string {
	if c == nil || c.mgr == nil {
		return ""
	}

	return c.mgr.GetString(definitions.SessionKeyAccount, "")
}

// HasClientConsent reports whether consent for the given client already
// exists in the session context.
func (c *oidcAuthorizeFlowContext) HasClientConsent(clientID string, requestedScopes []string) bool {
	if c == nil || c.mgr == nil {
		return false
	}

	consents := c.getConsentExpiries()
	if len(consents) == 0 {
		return c.hasLegacyClientConsent(clientID)
	}

	if pruneExpiredConsentGrants(consents, time.Now().Unix()) {
		c.setConsentExpiries(consents)
	}

	return consentGrantsCoverScopes(consents[clientID], normalizeScopes(requestedScopes))
}

// pruneExpiredConsentGrants removes expired consent grants in place.
func pruneExpiredConsentGrants(consents map[string][]oidcConsentGrant, now int64) bool {
	changed := false

	for clientID, grants := range consents {
		filtered := activeConsentGrants(grants, now)
		if len(filtered) != len(grants) {
			changed = true
		}

		if len(filtered) == 0 {
			delete(consents, clientID)
			continue
		}

		consents[clientID] = filtered
	}

	return changed
}

// activeConsentGrants returns only grants that have not expired.
func activeConsentGrants(grants []oidcConsentGrant, now int64) []oidcConsentGrant {
	filtered := grants[:0]
	for _, grant := range grants {
		if grant.Expiry > now {
			filtered = append(filtered, grant)
		}
	}

	return filtered
}

// consentGrantsCoverScopes reports whether any grant covers all requested scopes.
func consentGrantsCoverScopes(grants []oidcConsentGrant, requested []string) bool {
	for _, grant := range grants {
		if grant.Covers(requested) {
			return true
		}
	}

	return false
}

// hasLegacyClientConsent checks pre-TTL client consent markers.
func (c *oidcAuthorizeFlowContext) hasLegacyClientConsent(clientID string) bool {
	oidcClients := c.mgr.GetString(definitions.SessionKeyOIDCClients, "")
	for id := range strings.SplitSeq(oidcClients, ",") {
		if id == clientID {
			return true
		}
	}

	return false
}

// AddClientConsent appends a client consent marker when not already present.
func (c *oidcAuthorizeFlowContext) AddClientConsent(clientID string, grantedScopes []string, ttl time.Duration) {
	if c == nil || c.mgr == nil {
		return
	}

	c.addClientLoginMarker(clientID)

	if ttl <= 0 {
		return
	}

	consents := c.getConsentExpiries()
	if consents == nil {
		consents = make(map[string][]oidcConsentGrant)
	}

	scopes := normalizeScopes(grantedScopes)
	expiry := time.Now().Add(ttl).Unix()
	grants := consents[clientID]

	for i := range grants {
		if slices.Equal(grants[i].Scopes, scopes) {
			grants[i].Expiry = expiry
			consents[clientID] = grants
			c.setConsentExpiries(consents)

			return
		}
	}

	consents[clientID] = append(grants, oidcConsentGrant{
		Scopes: scopes,
		Expiry: expiry,
	})
	c.setConsentExpiries(consents)
}

func (c *oidcAuthorizeFlowContext) addClientLoginMarker(clientID string) {
	if c == nil || c.mgr == nil {
		return
	}

	oidcClients := c.mgr.GetString(definitions.SessionKeyOIDCClients, "")

	if oidcClients != "" {
		for id := range strings.SplitSeq(oidcClients, ",") {
			if id == clientID {
				return
			}
		}

		oidcClients += "," + clientID
	} else {
		oidcClients = clientID
	}

	c.mgr.Set(definitions.SessionKeyOIDCClients, oidcClients)
}

// getConsentExpiries reads consent expiries from current and legacy session formats.
func (c *oidcAuthorizeFlowContext) getConsentExpiries() map[string][]oidcConsentGrant {
	raw := c.mgr.GetString(definitions.SessionKeyOIDCConsentExpiries, "")
	if raw == "" {
		return nil
	}

	if consents := consentExpiriesFromJSON(raw); consents != nil {
		return consents
	}

	if consents := legacyConsentExpiriesFromJSON(raw); consents != nil {
		return consents
	}

	return legacyConsentExpiriesFromCSV(raw)
}

// consentExpiriesFromJSON parses the current JSON consent-grant format.
func consentExpiriesFromJSON(raw string) map[string][]oidcConsentGrant {
	var consents map[string][]oidcConsentGrant
	if err := json.Unmarshal([]byte(raw), &consents); err == nil {
		normalizeConsentGrantScopes(consents)
		return consents
	}

	return nil
}

// legacyConsentExpiriesFromJSON parses the old JSON form {"client":unix}.
func legacyConsentExpiriesFromJSON(raw string) map[string][]oidcConsentGrant {
	var legacy map[string]int64
	if err := json.Unmarshal([]byte(raw), &legacy); err == nil && len(legacy) > 0 {
		converted := make(map[string][]oidcConsentGrant, len(legacy))
		for clientID, expiry := range legacy {
			converted[clientID] = []oidcConsentGrant{{Expiry: expiry}}
		}

		return converted
	}

	return nil
}

// legacyConsentExpiriesFromCSV parses the old CSV form "client=unix,client2=unix".
func legacyConsentExpiriesFromCSV(raw string) map[string][]oidcConsentGrant {
	consents := make(map[string][]oidcConsentGrant)
	for pair := range strings.SplitSeq(raw, ",") {
		appendLegacyCSVConsent(consents, pair)
	}

	if len(consents) == 0 {
		return nil
	}

	return consents
}

// normalizeConsentGrantScopes sorts and de-duplicates scopes in parsed consent grants.
func normalizeConsentGrantScopes(consents map[string][]oidcConsentGrant) {
	for clientID, grants := range consents {
		for i := range grants {
			grants[i].Scopes = normalizeScopes(grants[i].Scopes)
		}

		consents[clientID] = grants
	}
}

// appendLegacyCSVConsent appends one legacy CSV consent pair when it is valid.
func appendLegacyCSVConsent(consents map[string][]oidcConsentGrant, pair string) {
	clientID, expRaw, ok := strings.Cut(pair, "=")
	if !ok || clientID == "" {
		return
	}

	exp, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil {
		return
	}

	consents[clientID] = append(consents[clientID], oidcConsentGrant{Expiry: exp})
}

func (c *oidcAuthorizeFlowContext) setConsentExpiries(expiries map[string][]oidcConsentGrant) {
	if len(expiries) == 0 {
		c.mgr.Delete(definitions.SessionKeyOIDCConsentExpiries)

		return
	}

	raw, err := json.Marshal(expiries)
	if err != nil {
		return
	}

	c.mgr.Set(definitions.SessionKeyOIDCConsentExpiries, string(raw))
}

type oidcConsentGrant struct {
	Scopes []string `json:"scopes,omitempty"`
	Expiry int64    `json:"expiry"`
}

func (g oidcConsentGrant) Covers(requested []string) bool {
	if len(requested) == 0 {
		return true
	}

	// Legacy entries did not store scopes and therefore act as wildcard.
	if len(g.Scopes) == 0 {
		return true
	}

	for _, scope := range requested {
		if !slices.Contains(g.Scopes, scope) {
			return false
		}
	}

	return true
}

func normalizeScopes(scopes []string) []string {
	unique := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}

		if _, exists := seen[scope]; exists {
			continue
		}

		seen[scope] = struct{}{}
		unique = append(unique, scope)
	}

	slices.Sort(unique)

	return unique
}

// ResumeAuthorizeURL reconstructs the /oidc/authorize URL from session cookie data
// so that the authorization flow can be resumed after login.
func (c *oidcAuthorizeFlowContext) ResumeAuthorizeURL() string {
	if c == nil || c.mgr == nil {
		return ""
	}

	clientID := c.mgr.GetString(definitions.SessionKeyIDPClientID, "")
	redirectURI := c.mgr.GetString(definitions.SessionKeyIDPRedirectURI, "")

	if clientID == "" || redirectURI == "" {
		return ""
	}

	authorizeURL := "/oidc/authorize?client_id=" + url.QueryEscape(clientID)
	authorizeURL += "&redirect_uri=" + url.QueryEscape(redirectURI)

	if scope := c.mgr.GetString(definitions.SessionKeyIDPScope, ""); scope != "" {
		authorizeURL += "&scope=" + url.QueryEscape(scope)
	}

	if state := c.mgr.GetString(definitions.SessionKeyIDPState, ""); state != "" {
		authorizeURL += "&state=" + url.QueryEscape(state)
	}

	if nonce := c.mgr.GetString(definitions.SessionKeyIDPNonce, ""); nonce != "" {
		authorizeURL += "&nonce=" + url.QueryEscape(nonce)
	}

	if responseType := c.mgr.GetString(definitions.SessionKeyIDPResponseType, ""); responseType != "" {
		authorizeURL += "&response_type=" + url.QueryEscape(responseType)
	}

	if codeChallenge := c.mgr.GetString(definitions.SessionKeyIDPCodeChallenge, ""); codeChallenge != "" {
		authorizeURL += "&code_challenge=" + url.QueryEscape(codeChallenge)
	}

	if codeChallengeMethod := c.mgr.GetString(definitions.SessionKeyIDPCodeChallengeMethod, ""); codeChallengeMethod != "" {
		authorizeURL += "&code_challenge_method=" + url.QueryEscape(codeChallengeMethod)
	}

	return authorizeURL
}

// Save persists the cookie-backed authorization context.
func (c *oidcAuthorizeFlowContext) Save(ctx *gin.Context) error {
	if c == nil || c.mgr == nil {
		return nil
	}

	return c.mgr.Save(ctx)
}

// oidcDeviceFlowContext wraps cookie-backed context handling for the OIDC
// device-code flow.
type oidcDeviceFlowContext struct {
	mgr cookie.Manager
}

// newOIDCDeviceFlowContext creates a device-code flow context bound to the
// current cookie manager.
func newOIDCDeviceFlowContext(mgr cookie.Manager) *oidcDeviceFlowContext {
	return &oidcDeviceFlowContext{mgr: mgr}
}

// StoreMFAContext stores MFA-relevant session data for a device-code flow.
func (c *oidcDeviceFlowContext) StoreMFAContext(
	username, userID, deviceCode, clientID, protocol string,
	authResult definitions.AuthResult,
	multi bool,
) {
	if c == nil || c.mgr == nil {
		return
	}

	c.mgr.Set(definitions.SessionKeyUsername, username)
	c.mgr.Set(definitions.SessionKeyUniqueUserID, userID)
	cookie.SetAuthResult(c.mgr, username, authResult)
	c.mgr.Set(definitions.SessionKeyProtocol, protocol)
	c.mgr.Set(definitions.SessionKeyMFAMulti, multi)

	_ = clientID
	_ = deviceCode
}

// StoreConsentContext stores consent-relevant session data for a device-code flow.
func (c *oidcDeviceFlowContext) StoreConsentContext(deviceCode, clientID, userID string) {
	if c == nil || c.mgr == nil {
		return
	}

	c.mgr.Set(definitions.SessionKeyUniqueUserID, userID)

	_ = clientID
	_ = deviceCode
}

// DeviceCode returns the current device code from session state.
func (c *oidcDeviceFlowContext) DeviceCode() string {
	if c == nil || c.mgr == nil {
		return ""
	}

	return c.mgr.GetString(definitions.SessionKeyDeviceCode, "")
}

// UniqueUserID returns the user identifier associated with the flow.
func (c *oidcDeviceFlowContext) UniqueUserID() string {
	if c == nil || c.mgr == nil {
		return ""
	}

	return c.mgr.GetString(definitions.SessionKeyUniqueUserID, "")
}

// ClearDeviceCode is intentionally a no-op because flow cleanup is handled
// centrally by the flow controller cleanup path.
func (c *oidcDeviceFlowContext) ClearDeviceCode() {
	_ = c
}
