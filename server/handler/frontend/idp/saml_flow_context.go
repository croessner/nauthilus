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
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

// samlFlowContext wraps cookie-backed context handling for SAML flows.
type samlFlowContext struct {
	mgr cookie.Manager
}

// newSAMLFlowContext creates a SAML flow context bound to the current
// cookie manager.
func newSAMLFlowContext(mgr cookie.Manager) *samlFlowContext {
	return &samlFlowContext{mgr: mgr}
}

// StoreRequest persists SAML-specific flow data in the session cookie.
func (c *samlFlowContext) StoreRequest(entityID, originalURL string) {
	_ = entityID
	_ = originalURL

	if c == nil || c.mgr == nil {
		return
	}

	// Flow-specific request values are written via FlowController/FlowStore metadata.
	// Keep only protocol as non-flow session context for downstream auth helpers.
	c.mgr.Set(definitions.SessionKeyProtocol, definitions.ProtoSAML)
}

// OriginalURL returns the original SAML SSO URL stored in the session.
func (c *samlFlowContext) OriginalURL() string {
	if c == nil || c.mgr == nil {
		return ""
	}

	return c.mgr.GetString(definitions.SessionKeyIdPOriginalURL, "")
}

// EntityID returns the SAML entity ID stored in the session.
func (c *samlFlowContext) EntityID() string {
	if c == nil || c.mgr == nil {
		return ""
	}

	return c.mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
}

// Save persists the cookie session state.
func (c *samlFlowContext) Save(ctx *gin.Context) error {
	if c == nil || c.mgr == nil {
		return nil
	}

	return c.mgr.Save(ctx)
}
