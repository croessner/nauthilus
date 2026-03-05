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

	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
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
	if len(consents) > 0 {
		requested := normalizeScopes(requestedScopes)
		now := time.Now().Unix()
		changed := false

		for cid, grants := range consents {
			filtered := grants[:0]
			for _, grant := range grants {
				if grant.Expiry > now {
					filtered = append(filtered, grant)
				} else {
					changed = true
				}
			}

			if len(filtered) == 0 {
				delete(consents, cid)
				continue
			}

			consents[cid] = filtered
		}

		if changed {
			c.setConsentExpiries(consents)
		}

		for _, grant := range consents[clientID] {
			if grant.Covers(requested) {
				return true
			}
		}

		return false
	}

	// Backward compatibility for sessions created before consent TTL support.
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

func (c *oidcAuthorizeFlowContext) getConsentExpiries() map[string][]oidcConsentGrant {
	raw := c.mgr.GetString(definitions.SessionKeyOIDCConsentExpiries, "")
	if raw == "" {
		return nil
	}

	var consents map[string][]oidcConsentGrant
	if err := json.Unmarshal([]byte(raw), &consents); err == nil {
		for clientID, grants := range consents {
			for i := range grants {
				grants[i].Scopes = normalizeScopes(grants[i].Scopes)
			}
			consents[clientID] = grants
		}

		return consents
	}

	// Backward compatibility: old JSON form {"client":unix}.
	var legacy map[string]int64
	if err := json.Unmarshal([]byte(raw), &legacy); err == nil && len(legacy) > 0 {
		converted := make(map[string][]oidcConsentGrant, len(legacy))
		for clientID, expiry := range legacy {
			converted[clientID] = []oidcConsentGrant{{Expiry: expiry}}
		}

		return converted
	}

	// Backward compatibility: old CSV form "client=unix,client2=unix".
	consents = make(map[string][]oidcConsentGrant)
	for pair := range strings.SplitSeq(raw, ",") {
		clientID, expRaw, ok := strings.Cut(pair, "=")
		if !ok || clientID == "" {
			continue
		}

		exp, err := strconv.ParseInt(expRaw, 10, 64)
		if err != nil {
			continue
		}

		consents[clientID] = append(consents[clientID], oidcConsentGrant{Expiry: exp})
	}

	if len(consents) == 0 {
		return nil
	}

	return consents
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

	clientID := c.mgr.GetString(definitions.SessionKeyIdPClientID, "")
	redirectURI := c.mgr.GetString(definitions.SessionKeyIdPRedirectURI, "")

	if clientID == "" || redirectURI == "" {
		return ""
	}

	authorizeURL := "/oidc/authorize?client_id=" + url.QueryEscape(clientID)
	authorizeURL += "&redirect_uri=" + url.QueryEscape(redirectURI)

	if scope := c.mgr.GetString(definitions.SessionKeyIdPScope, ""); scope != "" {
		authorizeURL += "&scope=" + url.QueryEscape(scope)
	}

	if state := c.mgr.GetString(definitions.SessionKeyIdPState, ""); state != "" {
		authorizeURL += "&state=" + url.QueryEscape(state)
	}

	if nonce := c.mgr.GetString(definitions.SessionKeyIdPNonce, ""); nonce != "" {
		authorizeURL += "&nonce=" + url.QueryEscape(nonce)
	}

	if responseType := c.mgr.GetString(definitions.SessionKeyIdPResponseType, ""); responseType != "" {
		authorizeURL += "&response_type=" + url.QueryEscape(responseType)
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
	authResult uint8,
	multi bool,
) {
	if c == nil || c.mgr == nil {
		return
	}

	c.mgr.Set(definitions.SessionKeyUsername, username)
	c.mgr.Set(definitions.SessionKeyUniqueUserID, userID)
	c.mgr.Set(definitions.SessionKeyAuthResult, authResult)
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
